// apps/backend/containers/id1/auth_dot_op_test.go
//
// group: auth
// tags: authentication, delegation, testing
// summary: Tests for auth-dot-op permission delegation logic.
//
//

package id1

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func setup(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	// Set up test data structure:
	// - test0 is a root namespace with pub/key endpoint
	// - test0/pub/tags/Robot is a resource that requires "Tagger" role to modify
	// - .get permission on test0 is "Reader" (allow all authenticated users)
	// - .set permission on test0/pub/tags is "Tagger" (allow Taggers only)
	// - Global roles: max has "Reader"
	// - test0-level roles: max has "Admin"
	// - test0/pub/tags level roles: max has "Tagger"

	_, err := CmdSet(K("test0/pub/key"), map[string]string{}, []byte("...")).Exec()
	require.NoError(t, err, "setup: failed to set test0/pub/key")

	_, err = CmdSet(K("test0/pub/tags/Robot"), map[string]string{}, []byte("...")).Exec()
	require.NoError(t, err, "setup: failed to set test0/pub/tags/Robot")

	_, err = CmdSet(K("test0/.get"), map[string]string{}, []byte("Reader")).Exec()
	require.NoError(t, err, "setup: failed to set test0/.get permission")

	_, err = CmdSet(K("test0/pub/tags/.set"), map[string]string{}, []byte("Tagger")).Exec()
	require.NoError(t, err, "setup: failed to set test0/pub/tags/.set permission")

	_, err = CmdSet(K(".roles/max"), map[string]string{}, []byte("Reader")).Exec()
	require.NoError(t, err, "setup: failed to set global role for max")

	_, err = CmdSet(K("test0/.roles/max"), map[string]string{}, []byte("Admin")).Exec()
	require.NoError(t, err, "setup: failed to set test0-level role for max")

	_, err = CmdSet(K("test0/pub/tags/.roles/max"), map[string]string{}, []byte("Tagger")).Exec()
	require.NoError(t, err, "setup: failed to set test0/pub/tags role for max")
}

func TestAuthDotOpAuthorization(t *testing.T) {
	setup(t)

	// max has "Tagger" role at test0/pub/tags, so should be able to set tags
	require.True(t, authDotOp("max", CmdSet(K("test0/pub/tags/Robot"), map[string]string{}, []byte{})),
		"max should be authorized to set test0/pub/tags/Robot with Tagger role")

	// max should not be able to delete (requires different role)
	require.False(t, authDotOp("max", CmdDel(K("test0/pub/tags/Robot"))),
		"max should not be authorized to delete test0/pub/tags/Robot")

	// max should be able to get test0/token (inherits permissions from test0)
	require.True(t, authDotOp("max", CmdGet(K("test0/token"))),
		"max should be authorized to get test0/token with inherited permissions")

	// max should not be able to delete test0/pub/key (not authorized at that level)
	require.False(t, authDotOp("max", CmdDel(K("test0/pub/key"))),
		"max should not be authorized to delete test0/pub/key")
}

func TestGetRolesReturnsAllApplicableRoles(t *testing.T) {
	setup(t)

	roles := getRoles("max", K("test0/pub/tags/Robot"))

	// Verify all inherited roles are present
	require.True(t, slices.Contains(roles, "Reader"),
		"roles should include global 'Reader' role inherited from test0/.get")

	require.True(t, slices.Contains(roles, "Admin"),
		"roles should include 'Admin' role at test0 level")

	require.True(t, slices.Contains(roles, "Tagger"),
		"roles should include 'Tagger' role at test0/pub/tags level")

	require.True(t, slices.Contains(roles, "max"),
		"roles should include user-specific role 'max'")

	require.True(t, slices.Contains(roles, "*"),
		"roles should include wildcard '*' for all-users")
}
