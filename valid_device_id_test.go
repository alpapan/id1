// apps/id1/valid_device_id_test.go
//
// group: auth
// tags: validation, device, testing
// summary: Tests that a device value ending .name is refused everywhere a caller supplies one.
//
//

package id1

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// validDeviceCase is one device value and whether it must be accepted.
type validDeviceCase struct {
	name     string
	device   string
	accepted bool
}

// validDeviceCases is the whole contract in one place. It is asserted by
// TestValidDeviceIDCaseListIsPopulatedAndNamed, so deleting a row fails a test
// rather than silently dropping the coverage it carried.
var validDeviceCases = []validDeviceCase{
	{name: "the default device", device: "default", accepted: true},
	{name: "a device with a dash", device: "laptop-1", accepted: true},
	{name: "a device with a dot", device: "Device.2", accepted: true},
	{name: "a device that merely contains name", device: "myname", accepted: true},
	{name: "a device ending in names", device: "x.names", accepted: true},
	{name: "a companion file name", device: "laptop.name", accepted: false},
	{name: "a companion file name with a dash", device: "laptop-1.name", accepted: false},
	{name: "a doubled suffix", device: "a.name.name", accepted: false},
	{name: "a device that is exactly x.name", device: "x.name", accepted: false},
	{name: "a leading dot", device: ".hidden", accepted: false},
	{name: "a path", device: "a/b", accepted: false},
	{name: "the empty string", device: "", accepted: false},
}

func TestValidDeviceIDCaseListIsPopulatedAndNamed(t *testing.T) {
	if len(validDeviceCases) != 12 {
		t.Fatalf("validDeviceCases must hold 12 cases, got %d - update this guard when adding or dropping a row", len(validDeviceCases))
	}
	names := map[string]bool{}
	refused := 0
	for _, c := range validDeviceCases {
		names[c.name] = true
		if !c.accepted {
			refused++
		}
	}
	if refused != 7 {
		t.Errorf("expected 7 refused shapes, got %d", refused)
	}
	for _, want := range []string{
		"a device with a dot",
		"a companion file name",
		"a doubled suffix",
	} {
		if !names[want] {
			t.Errorf("validDeviceCases is missing the case %q", want)
		}
	}
}

func TestValidDeviceIDAcceptsAndRefusesTheListedValues(t *testing.T) {
	for _, c := range validDeviceCases {
		t.Run(c.name, func(t *testing.T) {
			if got := validDeviceID(c.device); got != c.accepted {
				t.Errorf("validDeviceID(%q) = %v, want %v", c.device, got, c.accepted)
			}
		})
	}
}

// devicePatternUsesOutsideTheHelper parses one Go source file and returns a
// description of every call to devicePattern.MatchString that is NOT inside the
// function validDeviceID.
func devicePatternUsesOutsideTheHelper(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	offenders := []string{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if fn.Name.Name == "validDeviceID" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "MatchString" {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if ok && recv.Name == "devicePattern" {
				offenders = append(offenders, filepath.Base(path)+" in "+fn.Name.Name)
			}
			return true
		})
	}
	return offenders
}

// TestDevicePatternIsOnlyUsedInsideTheHelperDerivationWorks proves the parser
// reads the file in both directions: it flags a call outside the helper and
// does not flag a call inside it. Without this, a derivation that returned an
// empty slice would satisfy the real guard below.
func TestDevicePatternIsOnlyUsedInsideTheHelperDerivationWorks(t *testing.T) {
	dir := t.TempDir()
	dirty := filepath.Join(dir, "dirty.go")
	if err := os.WriteFile(dirty, []byte(`package id1

func handler(device string) bool {
	return devicePattern.MatchString(device)
}
`), 0644); err != nil {
		t.Fatalf("writing synthetic source: %v", err)
	}
	if got := devicePatternUsesOutsideTheHelper(t, dirty); len(got) != 1 {
		t.Errorf("derivation missed a call outside the helper: got %v", got)
	}

	clean := filepath.Join(dir, "clean.go")
	if err := os.WriteFile(clean, []byte(`package id1

func validDeviceID(device string) bool {
	return devicePattern.MatchString(device)
}
`), 0644); err != nil {
		t.Fatalf("writing synthetic source: %v", err)
	}
	if got := devicePatternUsesOutsideTheHelper(t, clean); len(got) != 0 {
		t.Errorf("derivation flagged a call inside the helper: got %v", got)
	}
}

func TestDevicePatternIsOnlyUsedInsideTheHelper(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing source files: %v", err)
	}
	scanned := 0
	offenders := []string{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		scanned++
		offenders = append(offenders, devicePatternUsesOutsideTheHelper(t, path)...)
	}
	if scanned < 20 {
		t.Fatalf("derived only %d non-test source files; the derivation is broken", scanned)
	}
	sort.Strings(offenders)
	if len(offenders) != 0 {
		t.Errorf("devicePattern.MatchString must only be called inside validDeviceID; found %v", offenders)
	}
}

// TestHandleDeviceChallengeAnswersNotFoundForACompanionFileName seeds an id
// whose device "laptop" has only a companion label file, then asks for a
// challenge naming that companion as the device. The answer must be the same
// 404 an unknown device gets, not the 500 a PEM parse failure produced.
func TestHandleDeviceChallengeAnswersNotFoundForACompanionFileName(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	keysDir := filepath.Join(tmpDir, "someid", "pub", "keys")
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("failed to create the keys dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "laptop.name"), []byte("My Laptop"), 0o644); err != nil {
		t.Fatalf("failed to write the companion file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	handler := Handle(tmpDir, ctx)

	req := httptest.NewRequest(http.MethodGet, "/someid/priv/secretthing?device=laptop.name", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("a companion file name used as a device must answer 404, got %d with body %q", rec.Code, rec.Body.String())
	}
}
