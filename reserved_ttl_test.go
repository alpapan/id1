// apps/id1/reserved_ttl_test.go
//
// group: server
// tags: storage, ttl, authorization, testing
// summary: Tests that TTL bookkeeping names cannot be written through set, add or mov.
//
//

package id1

import (
	"os"
	"path/filepath"
	"testing"
)

// reservedKeyCase is one key shape that must be refused by every writing
// operation, or one that must still be allowed.
type reservedKeyCase struct {
	name    string
	key     string
	refused bool
}

// reservedKeyCases is the whole reservation contract in one place. It is
// asserted by TestReservedTTLCaseListIsPopulatedAndNamed below, so deleting a
// row fails a test rather than silently dropping the coverage it carried.
var reservedKeyCases = []reservedKeyCase{
	{name: "the reserved directory itself", key: "alice/msg/.ttl", refused: true},
	{name: "a file inside the reserved directory", key: "alice/msg/.ttl/greeting", refused: true},
	{name: "the reserved directory deeper in the tree", key: "alice/msg/.ttl/sub/greeting", refused: true},
	{name: "the flat bookkeeping name", key: "alice/msg/.ttl.greeting", refused: true},
	{name: "the reserved directory directly under an identity", key: "alice/.ttl/greeting", refused: true},
	{name: "an ordinary key", key: "alice/msg/greeting", refused: false},
	{name: "an ordinary dotted key", key: "alice/msg/.online", refused: false},
	{name: "a key merely starting with the same letters", key: "alice/msg/.ttlish", refused: false},
}

func TestReservedTTLCaseListIsPopulatedAndNamed(t *testing.T) {
	if len(reservedKeyCases) != 8 {
		t.Fatalf("reservedKeyCases must hold 8 cases, got %d - update this guard when adding or dropping a row", len(reservedKeyCases))
	}
	names := map[string]bool{}
	refused := 0
	for _, c := range reservedKeyCases {
		names[c.name] = true
		if c.refused {
			refused++
		}
	}
	if refused != 5 {
		t.Errorf("expected 5 refused shapes, got %d", refused)
	}
	for _, want := range []string{
		"a file inside the reserved directory",
		"the flat bookkeeping name",
		"a key merely starting with the same letters",
	} {
		if !names[want] {
			t.Errorf("reservedKeyCases is missing the case %q", want)
		}
	}
}

func TestReservedTTLNamesAreRefusedBySet(t *testing.T) {
	for _, c := range reservedKeyCases {
		t.Run(c.name, func(t *testing.T) {
			newTTLStore(t)
			key := mustK(t, c.key)

			_, err := CmdSet(key, map[string]string{"x-id": "alice"}, []byte("payload")).Exec()

			if c.refused && err != ErrForbidden {
				t.Errorf("set %s: expected ErrForbidden, got %v", c.key, err)
			}
			if !c.refused && err != nil {
				t.Errorf("set %s: expected success, got %v", c.key, err)
			}
		})
	}
}

func TestReservedTTLNamesAreRefusedByAdd(t *testing.T) {
	for _, c := range reservedKeyCases {
		t.Run(c.name, func(t *testing.T) {
			newTTLStore(t)
			key := mustK(t, c.key)

			_, err := NewCommand(Add, key, map[string]string{"x-id": "alice"}, []byte("payload")).Exec()

			if c.refused && err != ErrForbidden {
				t.Errorf("add %s: expected ErrForbidden, got %v", c.key, err)
			}
			if !c.refused && err != nil {
				t.Errorf("add %s: expected success, got %v", c.key, err)
			}
		})
	}
}

func TestReservedTTLNamesAreRefusedAsAMoveDestination(t *testing.T) {
	for _, c := range reservedKeyCases {
		t.Run(c.name, func(t *testing.T) {
			newTTLStore(t)
			source := mustK(t, "alice/msg/source")
			if _, err := CmdSet(source, map[string]string{"x-id": "alice"}, []byte("payload")).Exec(); err != nil {
				t.Fatalf("seeding the move source failed: %v", err)
			}

			_, err := NewCommand(Mov, source, map[string]string{"x-id": "alice"}, []byte(c.key)).Exec()

			if c.refused && err != ErrForbidden {
				t.Errorf("mov to %s: expected ErrForbidden, got %v", c.key, err)
			}
			if !c.refused && err != nil {
				t.Errorf("mov to %s: expected success, got %v", c.key, err)
			}
		})
	}
}

func TestTheSchedulerStillWritesItsOwnBookkeeping(t *testing.T) {
	root := newTTLStore(t)
	key := mustK(t, "alice/msg/greeting")

	if _, err := CmdSet(key, map[string]string{"ttl": "60", "x-id": "alice"}, []byte("hello")).Exec(); err != nil {
		t.Fatalf("set with ttl failed: %v", err)
	}

	pointer := filepath.Join(root, "alice", "msg", ".ttl", "greeting")
	if _, err := os.Stat(pointer); err != nil {
		t.Fatalf("the reservation must not block the scheduler's own write at %s: %v", pointer, err)
	}
}

func TestReservedTTLNamesAreRefusedAsAMoveSource(t *testing.T) {
	newTTLStore(t)
	key := mustK(t, "alice/msg/greeting")
	if _, err := CmdSet(key, map[string]string{"ttl": "60", "x-id": "alice"}, []byte("hello")).Exec(); err != nil {
		t.Fatalf("set with ttl failed: %v", err)
	}

	pointer := mustK(t, "alice/msg/.ttl/greeting")
	_, err := NewCommand(Mov, pointer, map[string]string{"x-id": "alice"}, []byte("alice/evacuated")).Exec()

	if err != ErrForbidden {
		t.Errorf("moving bookkeeping out of the reserved directory must be refused, got %v", err)
	}
	if _, getErr := CmdGet(mustK(t, "alice/evacuated")).Exec(); getErr == nil {
		t.Errorf("the bookkeeping pointer was evacuated to an ordinary key")
	}
}
