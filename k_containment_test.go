package id1

import (
	"errors"
	"testing"
)

// hostileKeys is the set of key strings that must never produce a usable
// Id1Key. Each names a location outside its own first segment, or names no
// segment at all.
//
// The whitespace forms matter more than they look: K strips every space and
// newline BEFORE it splits, so ". ." and ".\n." are TURNED INTO ".." by K
// itself. No filter in front of this process can see them, which is why the
// rejection has to live here.
var hostileKeys = []struct {
	name string
	key  string
}{
	{"literal dotdot", "mallory/../victim/pub/keys/dev"},
	{"space obfuscated", "mallory/. ./victim/pub/keys/dev"},
	{"newline obfuscated", "mallory/.\n./victim/pub/keys/dev"},
	{"trailing spaces around dotdot", "mallory/ .. /victim/pub/keys/dev"},
	{"bare dotdot", ".."},
	{"bare dot", "."},
	{"single dot segment", "mallory/./victim"},
	{"leading dotdot", "../victim/priv/salt"},
	{"empty middle segment", "mallory//victim"},
	{"root slash only", "/"},
}

// TestKeyContainmentCaseListIsIntact is the tripwire over the table above.
// Deleting a row from hostileKeys also has to delete an assertion here, so a
// dropped case fails a test instead of passing quietly.
func TestKeyContainmentCaseListIsIntact(t *testing.T) {
	if len(hostileKeys) != 10 {
		t.Fatalf("hostileKeys length changed: got %d, want 10", len(hostileKeys))
	}
	seen := map[string]bool{}
	for _, c := range hostileKeys {
		seen[c.name] = true
	}
	for _, want := range []string{
		"literal dotdot",
		"space obfuscated",
		"newline obfuscated",
		"trailing spaces around dotdot",
		"bare dotdot",
		"bare dot",
		"single dot segment",
		"leading dotdot",
		"empty middle segment",
		"root slash only",
	} {
		if !seen[want] {
			t.Errorf("hostileKeys is missing the %q case", want)
		}
	}
}

// TestKeyContainmentRejectsHostileKeys is the load-bearing security test.
func TestKeyContainmentRejectsHostileKeys(t *testing.T) {
	for _, tc := range hostileKeys {
		t.Run(tc.name, func(t *testing.T) {
			k, err := K(tc.key)
			if !errors.Is(err, ErrInvalidKey) {
				t.Errorf("K(%q): got err=%v, want ErrInvalidKey (segments=%v)", tc.key, err, k.Segments)
			}
			if len(k.Segments) != 0 {
				t.Errorf("K(%q): rejected key must be the zero Id1Key, got segments=%v", tc.key, k.Segments)
			}
		})
	}
}

// TestKeyContainmentRejectsHostileKeysViaKK proves the variadic constructor
// inherits the rejection, since that is the form the JSON-body and
// query-parameter call sites use.
func TestKeyContainmentRejectsHostileKeysViaKK(t *testing.T) {
	k, err := KK("mallory", "pub", "keys", "../../../victim/pub/keys/evil")
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("KK with a traversal segment: got err=%v, want ErrInvalidKey (segments=%v)", err, k.Segments)
	}
	k2, err2 := KK("mallory", ". .", "victim")
	if !errors.Is(err2, ErrInvalidKey) {
		t.Errorf("KK with a space-obfuscated segment: got err=%v, want ErrInvalidKey (segments=%v)", err2, k2.Segments)
	}
}

// TestKeyContainmentAdmitsLegitimateKeys is the other half of the guard: the
// change must not break any key the system actually uses. Every string here
// is taken from a real call site in this package.
func TestKeyContainmentAdmitsLegitimateKeys(t *testing.T) {
	legitimate := []string{
		"0000-0002-1111-2222/pub/keys/default",
		"0000-0002-1111-2222/priv/salt",
		"_system/priv/jwt-signing-key",
		"_system/priv/jwt-signing-key-prev",
		"alice/priv/myfile",
		"alice/.online",
		"alice/.ping",
		"alice/auth",
		"alice/pub/keys/laptop-1.name",
		"alice/priv/pending/abc123.key",
		"alice/.ttl.myfile",
		"alice/.after.1744641370068551",
		"alice/pub/keys/Device.2",
		"alice/._hidden",
	}
	for _, s := range legitimate {
		k, err := K(s)
		if err != nil {
			t.Errorf("K(%q): must be admitted, got err=%v", s, err)
		}
		if k.String() != s {
			t.Errorf("K(%q): round-trip changed the key to %q", s, k.String())
		}
	}
}

// TestKeyContainmentEmptyStringUnchanged pins the one input whose behaviour
// this change deliberately leaves alone. K("") returns the zero key and no
// error, exactly as before.
//
// It is not a traversal: it names no segment, String() is "", and the HTTP
// dispatcher already refuses an empty id at id1.go before any key is built.
// The "/" case IS rejected, by the empty-segment rule, and that is the form
// actually reachable over HTTP - r.URL.Path is never the empty string.
func TestKeyContainmentEmptyStringUnchanged(t *testing.T) {
	k, err := K("")
	if err != nil {
		t.Errorf(`K(""): got err=%v, want nil`, err)
	}
	if len(k.Segments) != 0 || k.Id != "" || k.String() != "" {
		t.Errorf(`K(""): want the zero Id1Key, got %+v`, k)
	}
}
