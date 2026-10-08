// apps/id1/auth_delegation_test.go
//
// group: auth
// tags: authorization, delegation, roles, testing
// summary: Tests that delegated operations never reach the private subtree or control files, and that roles stay inside the id.
//
//

package id1

import (
	"fmt"
	"slices"
	"testing"
)

// writeDelegationFile writes a delegation or role file as the store owner would.
func writeDelegationFile(t *testing.T, key string, content string) {
	t.Helper()
	if _, err := CmdSet(mustK(t, key), map[string]string{}, []byte(content)).execUnauthorised(); err != nil {
		t.Fatalf("seeding %s failed: %v", key, err)
	}
}

func TestDelegationOpCaseListIsDerivedAndPopulated(t *testing.T) {
	ops := deriveOpNamesFromSource(t, "cmd_op.go")
	if len(ops) < 6 {
		t.Fatalf("derived only %d operation names from cmd_op.go; expected at least 6: %v", len(ops), ops)
	}
	for _, want := range []string{"set", "add", "get", "del", "mov", "list"} {
		if !slices.Contains(ops, want) {
			t.Errorf("the derived operation names are missing %q: %v", want, ops)
		}
	}
}

// TestDelegationNeverReachesProtectedTargets grants mallory every operation on
// the whole victim namespace ("*" in victim/.<op>) and then asks whether that
// grant reaches each protected target. It must not, for any operation.
func TestDelegationNeverReachesProtectedTargets(t *testing.T) {
	for _, opNameString := range deriveOpNamesFromSource(t, "cmd_op.go") {
		t.Run(opNameString, func(t *testing.T) {
			seedVictim(t)
			writeDelegationFile(t, fmt.Sprintf("victim/.%s", opNameString), "*")
			operation := nameOp[opNameString]

			protected := []string{
				"victim/priv/salt",
				"victim/priv",
				fmt.Sprintf("victim/sub/.%s", opNameString),
				"victim/sub/.set",
				"victim/sub/.roles/mallory",
				"victim/sub/.roles",
			}
			for _, target := range protected {
				cmd := NewCommand(operation, mustK(t, target), map[string]string{"x-id": "mallory"}, nil)
				if authDotOp("mallory", cmd) {
					t.Errorf("a victim/.%s grant must not reach %s", opNameString, target)
				}
			}

			control := NewCommand(operation, mustK(t, "victim/shared/doc"), map[string]string{"x-id": "mallory"}, nil)
			if !authDotOp("mallory", control) {
				t.Errorf("control failed: a victim/.%s grant must still reach victim/shared/doc", opNameString)
			}
		})
	}
}

func TestGetRolesNeverReadsTheStoreRoot(t *testing.T) {
	seedVictim(t)
	writeDelegationFile(t, ".roles/mallory", "rootrole")
	writeDelegationFile(t, "victim/.roles/mallory", "ownerrole")

	roles := getRoles("mallory", mustK(t, "victim/sub/doc"))

	if slices.Contains(roles, "rootrole") {
		t.Errorf("getRoles read .roles/mallory from the store root: %v", roles)
	}
	if !slices.Contains(roles, "ownerrole") {
		t.Errorf("control failed: getRoles must still read victim/.roles/mallory: %v", roles)
	}
}

func TestNewIdBootstrapRefusesADotPrefixedId(t *testing.T) {
	seedVictim(t)
	t.Setenv("ID1_INTERNAL_SECRET", "bootstrap-secret")

	for _, refused := range []string{".roles/pub/key", ".get/pub/key", ".ttl/pub/key"} {
		cmd := CmdSet(mustK(t, refused), map[string]string{}, []byte("pem"))
		if auth("", cmd, "bootstrap-secret") {
			t.Errorf("bootstrap must refuse the dot-prefixed id in %s", refused)
		}
	}

	control := CmdSet(mustK(t, "alice/pub/key"), map[string]string{}, []byte("pem"))
	if !auth("", control, "bootstrap-secret") {
		t.Errorf("control failed: bootstrap of a new ordinary id must still be allowed")
	}
}
