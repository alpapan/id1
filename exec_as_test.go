// apps/id1/exec_as_test.go
//
// group: auth
// tags: authorization, dispatch, testing
// summary: Tests that ExecAs authorises before it runs a command.
//
//

package id1

import (
	"errors"
	"testing"
)

func seedExecAsNote(t *testing.T) {
	t.Helper()
	newTTLStore(t)
	if _, err := CmdSet(mustK(t, "victim/msg/note"), map[string]string{"x-id": "victim"}, []byte("secret")).execUnauthorised(); err != nil {
		t.Fatalf("seeding the note failed: %v", err)
	}
}

func TestExecAsRefusesACallerThatIsNotAuthorised(t *testing.T) {
	seedExecAsNote(t)

	data, err := CmdGet(mustK(t, "victim/msg/note")).ExecAs("mallory", "")

	if !errors.Is(err, ErrUnauthorised) {
		t.Errorf("ExecAs for a stranger: got err=%v, want ErrUnauthorised", err)
	}
	if len(data) != 0 {
		t.Errorf("ExecAs for a stranger must return no data, got %q", string(data))
	}
}

func TestExecAsRefusesAnAnonymousCaller(t *testing.T) {
	seedExecAsNote(t)

	_, err := CmdGet(mustK(t, "victim/msg/note")).ExecAs("", "")

	if !errors.Is(err, ErrUnauthorised) {
		t.Errorf("ExecAs with no identity: got err=%v, want ErrUnauthorised", err)
	}
}

func TestExecAsRunsTheCommandForItsOwner(t *testing.T) {
	seedExecAsNote(t)

	data, err := CmdGet(mustK(t, "victim/msg/note")).ExecAs("victim", "")

	if err != nil {
		t.Fatalf("ExecAs for the owner failed: %v", err)
	}
	if string(data) != "secret" {
		t.Errorf("ExecAs for the owner returned %q, want %q", string(data), "secret")
	}
}

func TestExecAsHonoursTheInternalSecretForANewIdentityBootstrap(t *testing.T) {
	newTTLStore(t)
	t.Setenv("ID1_INTERNAL_SECRET", "exec-as-secret")
	key := mustK(t, "newid/pub/key")

	for _, header := range []string{"", "wrong-secret"} {
		_, err := CmdSet(key, map[string]string{"x-id": ""}, []byte("PEM")).ExecAs("", header)
		if !errors.Is(err, ErrUnauthorised) {
			t.Errorf("bootstrap with header %q: got err=%v, want ErrUnauthorised", header, err)
		}
	}

	if _, err := CmdSet(key, map[string]string{"x-id": ""}, []byte("PEM")).ExecAs("", "exec-as-secret"); err != nil {
		t.Fatalf("bootstrap with the correct header failed: %v", err)
	}
	stored, err := CmdGet(key).execUnauthorised()
	if err != nil || string(stored) != "PEM" {
		t.Errorf("the bootstrapped key was not stored: data=%q err=%v", string(stored), err)
	}
}
