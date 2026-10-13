// apps/id1/auth_delegation_keyfiles_test.go
//
// group: auth
// tags: authorization, delegation, keys, testing
// summary: Tests that a delegated write, append, delete or move never reaches an account's public key files.
//
//

package id1

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// keyFileDelegationOps are the operations a delegate may never run against an
// account's public key files.
var keyFileDelegationOps = []string{"set", "add", "del", "mov"}

// keyFileTargets are the paths a delegated operation must never reach: the two
// key-file shapes, the companion name file, a device path that does not exist
// yet, and the two directories whose removal, relocation or creation as a plain
// file damages the key files.
var keyFileTargets = []string{
	"victim/pub/key",
	"victim/pub/keys/laptop",
	"victim/pub/keys/laptop.name",
	"victim/pub/keys/evil",
	"victim/pub/keys",
	"victim/pub",
}

// keyFileControls are paths whose names resemble key files but are not; a
// delegated operation must still reach them.
var keyFileControls = []string{
	"victim/pub/note",
	"victim/pub/keyring",
	"victim/msg/key",
	"victim/shared/doc",
}

// keyFileSeeds are the key files the victim owns, with their exact contents.
var keyFileSeeds = map[string]string{
	"victim/pub/key":              "OWNER-KEY",
	"victim/pub/keys/laptop":      "LAPTOP-KEY",
	"victim/pub/keys/laptop.name": "Laptop",
}

func TestDelegationKeyFileCaseListsArePopulated(t *testing.T) {
	derived := deriveOpNamesFromSource(t, "cmd_op.go")
	for _, name := range keyFileDelegationOps {
		if !slices.Contains(derived, name) {
			t.Errorf("keyFileDelegationOps names %q, which is not an operation in cmd_op.go: %v", name, derived)
		}
	}
	if len(keyFileDelegationOps) != 4 {
		t.Errorf("keyFileDelegationOps must hold 4 operations, got %d - update this guard when adding or dropping one", len(keyFileDelegationOps))
	}
	if len(keyFileTargets) != 6 {
		t.Errorf("keyFileTargets must hold 6 paths, got %d - update this guard when adding or dropping one", len(keyFileTargets))
	}
	if len(keyFileControls) != 4 {
		t.Errorf("keyFileControls must hold 4 paths, got %d - update this guard when adding or dropping one", len(keyFileControls))
	}
	if len(keyFileSeeds) != 3 {
		t.Errorf("keyFileSeeds must hold 3 key files, got %d - update this guard when adding or dropping one", len(keyFileSeeds))
	}
}

// seedAccountKeyFiles writes the victim's key files and a few ordinary keys
// whose names resemble them, and returns the temp root.
func seedAccountKeyFiles(t *testing.T) string {
	t.Helper()
	root := seedVictim(t)
	for key, content := range keyFileSeeds {
		writeDelegationFile(t, key, content)
	}
	for key, content := range map[string]string{
		"victim/pub/note":    "note",
		"victim/pub/keyring": "ring",
		"victim/msg/key":     "k",
		"victim/shared/doc":  "doc",
	} {
		writeDelegationFile(t, key, content)
	}
	return root
}

// TestDelegationKeyFileNeverReachedByAnyGrant grants mallory the operation on
// the whole victim namespace ("*" in victim/.<op>) and asks whether that grant
// reaches each key-file path. It must not; the controls prove the refusal is
// confined to key files.
func TestDelegationKeyFileNeverReachedByAnyGrant(t *testing.T) {
	for _, opNameString := range keyFileDelegationOps {
		t.Run(opNameString, func(t *testing.T) {
			seedAccountKeyFiles(t)
			writeDelegationFile(t, "victim/."+opNameString, "*")
			operation := nameOp[opNameString]

			for _, target := range keyFileTargets {
				cmd := NewCommand(operation, mustK(t, target), map[string]string{"x-id": "mallory"}, nil)
				if authDotOp("mallory", cmd) {
					t.Errorf("a victim/.%s grant must not reach %s", opNameString, target)
				}
			}
			for _, control := range keyFileControls {
				cmd := NewCommand(operation, mustK(t, control), map[string]string{"x-id": "mallory"}, nil)
				if !authDotOp("mallory", cmd) {
					t.Errorf("control failed: a victim/.%s grant must still reach %s", opNameString, control)
				}
			}
		})
	}
}

// TestDelegationKeyFileLeftOnDisk runs the whole request path (ExecAs: auth,
// then the operation) and checks that every key file still holds exactly its
// seeded bytes afterwards, that no new device key appeared, and that nothing
// was created in the delegate's namespace.
func TestDelegationKeyFileLeftOnDisk(t *testing.T) {
	for _, opNameString := range keyFileDelegationOps {
		for _, target := range keyFileTargets {
			t.Run(opNameString+"_"+target, func(t *testing.T) {
				root := seedAccountKeyFiles(t)
				writeDelegationFile(t, "victim/."+opNameString, "*")
				cmd := NewCommand(nameOp[opNameString], mustK(t, target), map[string]string{"x-id": "mallory"}, []byte("mallory/stolen"))

				_, err := cmd.ExecAs("mallory", "")

				if !errors.Is(err, ErrUnauthorised) {
					t.Errorf("%s %s as mallory: got err=%v, want ErrUnauthorised", opNameString, target, err)
				}
				for rel, want := range keyFileSeeds {
					got, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
					if readErr != nil {
						t.Errorf("%s must still exist after the refused %s of %s: %v", rel, opNameString, target, readErr)
					} else if string(got) != want {
						t.Errorf("%s must be byte-identical after the refused %s of %s: got %q, want %q", rel, opNameString, target, string(got), want)
					}
				}
				if _, statErr := os.Stat(filepath.Join(root, "victim", "pub", "keys", "evil")); statErr == nil {
					t.Errorf("victim/pub/keys/evil must not exist after the refused %s of %s", opNameString, target)
				}
				if _, statErr := os.Stat(filepath.Join(root, "mallory")); statErr == nil {
					t.Errorf("the delegate's namespace must not exist after a refused %s of %s", opNameString, target)
				}
			})
		}
	}
}

// TestDelegationKeyFileControlsStillWork is the control for the two tests
// above: the same grants still write, append to, delete and move an ordinary key.
func TestDelegationKeyFileControlsStillWork(t *testing.T) {
	root := seedAccountKeyFiles(t)
	for _, opNameString := range keyFileDelegationOps {
		writeDelegationFile(t, "victim/."+opNameString, "*")
	}
	caller := map[string]string{"x-id": "mallory"}

	if _, err := NewCommand(nameOp["set"], mustK(t, "victim/pub/note"), caller, []byte("new")).ExecAs("mallory", ""); err != nil {
		t.Errorf("a delegated set of an ordinary key must still work: %v", err)
	}
	if _, err := NewCommand(nameOp["add"], mustK(t, "victim/pub/note"), caller, []byte("+more")).ExecAs("mallory", ""); err != nil {
		t.Errorf("a delegated add to an ordinary key must still work: %v", err)
	}
	got, readErr := os.ReadFile(filepath.Join(root, "victim", "pub", "note"))
	if readErr != nil || string(got) != "new+more" {
		t.Errorf("victim/pub/note after the delegated set and add: got %q (err %v), want %q", string(got), readErr, "new+more")
	}

	if _, err := NewCommand(nameOp["del"], mustK(t, "victim/pub/keyring"), caller, nil).ExecAs("mallory", ""); err != nil {
		t.Errorf("a delegated delete of an ordinary key must still work: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "victim", "pub", "keyring")); statErr == nil {
		t.Error("victim/pub/keyring must be gone after the delegated delete")
	}

	if _, err := NewCommand(nameOp["mov"], mustK(t, "victim/shared/doc"), caller, []byte("mallory/doc")).ExecAs("mallory", ""); err != nil {
		t.Errorf("a delegated move of an ordinary key must still work: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "mallory", "doc")); statErr != nil {
		t.Errorf("mallory/doc must exist after the delegated move: %v", statErr)
	}
}
