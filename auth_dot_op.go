// apps/id1/auth_dot_op.go
//
// group: auth
// tags: authentication, authorization, delegation
// summary: Auth-dot-op delegation pattern for inherited authorization.
// Evaluates permission inheritance through owner path hierarchy.
//
//

package id1

import (
	"fmt"
	"slices"
	"strings"
)

func authDotOp(id string, cmd Command) bool {
	if len(id) == 0 {
		return false
	}
	if delegationTargetRefused(cmd.Key) {
		return false
	}
	if delegationKeyFileRefused(cmd.Op, cmd.Key) {
		return false
	}
	roles := getRoles(id, cmd.Key)
	parentKey, err := K(cmd.Key.Parent)
	if err != nil {
		return false
	}
	for len(parentKey.String()) != 0 {
		dotOpKey, err := KK(parentKey, fmt.Sprintf(".%s", cmd.Op))
		if err == nil {
			if data, err := CmdGet(dotOpKey).execUnauthorised(); err == nil {
				lines := strings.Split(string(data), "\n")
				if ContainsAny(lines, roles) {
					return true
				}
			}
		}
		nextParentKey, err := K(parentKey.Parent)
		if err != nil {
			break
		}
		parentKey = nextParentKey
	}

	return false
}

// delegationTargetRefused reports whether a delegated operation may never
// reach key, whatever any .{op} or .roles file says. Only the owner of the id
// may touch these: the private subtree (second segment "priv", which holds the
// HMAC salt), a control file (a name of "." plus an operation name, such as
// ".set"), and anything inside a ".roles" directory. The control-file names are
// read from nameOp, so a new operation is covered the moment it exists.
func delegationTargetRefused(key Id1Key) bool {
	if len(key.Segments) > 1 && key.Segments[1] == "priv" {
		return true
	}
	for opNameString := range nameOp {
		if key.Name == "."+opNameString {
			return true
		}
	}
	return slices.Contains(key.Segments, ".roles")
}

// keyFileDelegationRefusedOps names, by operation name, the operations a
// delegate may never run against an account's public key files. Adding an
// operation name here refuses it for the same paths.
var keyFileDelegationRefusedOps = map[string]bool{"set": true, "add": true, "del": true, "mov": true}

// delegationKeyFileRefused reports whether a delegated operation may never reach
// key because it would replace, extend, remove or relocate the account's public
// key files. Only the owner of the id may do that. It is true for a refused
// operation (see keyFileDelegationRefusedOps) on {id}/pub itself, on
// {id}/pub/key, and on {id}/pub/keys and everything under it: removing or moving
// a directory takes the key files inside it, and creating either directory name
// as a plain file blocks the key files that belong inside it. Other keys under
// {id}/pub stay delegable.
func delegationKeyFileRefused(operation Op, key Id1Key) bool {
	if !keyFileDelegationRefusedOps[opName[operation]] {
		return false
	}
	if len(key.Segments) < 2 || key.Segments[1] != "pub" {
		return false
	}
	return len(key.Segments) == 2 || key.Segments[2] == "key" || key.Segments[2] == "keys"
}

func getRoles(id string, key Id1Key) []string {
	result := []string{"*", id}
	parentKey, err := K(key.Parent)
	if err != nil {
		return result
	}
	for len(parentKey.String()) != 0 {
		rolesKey, err := KK(parentKey, ".roles", id)
		if err == nil {
			if data, err := CmdGet(rolesKey).execUnauthorised(); err == nil {
				lines := strings.Split(string(data), "\n")
				result = append(result, lines...)
			}
		}
		nextParentKey, err := K(parentKey.Parent)
		if err != nil {
			break
		}
		parentKey = nextParentKey
	}
	return result
}

func ContainsAny(slice1, slice2 []string) bool {
	itemSet := make(map[string]bool)
	for _, item := range slice2 {
		itemSet[item] = true
	}
	for _, item := range slice1 {
		if itemSet[item] {
			return true
		}
	}
	return false
}
