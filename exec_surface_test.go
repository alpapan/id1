// apps/id1/exec_surface_test.go
//
// group: auth
// tags: authorization, dispatch, testing
// summary: Tests that Command exports ExecAs and no method that runs a command unauthorised.
//
//

package id1

import (
	"reflect"
	"testing"
)

func TestCommandExportsNoUnauthorisedExec(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(Command{}), reflect.TypeOf(&Command{})} {
		if _, found := typ.MethodByName("Exec"); found {
			t.Errorf("%s still exports Exec; the only exported way to run a command is ExecAs", typ)
		}
		if _, found := typ.MethodByName("ExecAs"); !found {
			t.Errorf("%s does not export ExecAs", typ)
		}
	}
}
