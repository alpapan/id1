package id1

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// openFDCountForAddLeakTest counts this process's open file descriptors via
// /proc/self/fd. Skips the test on a platform without /proc (non-Linux),
// since fd-leak detection here relies on it.
//
// This counts EVERY descriptor the process holds, not only the ones add()
// opened. That is sound only because apps/id1's suite runs strictly
// sequentially - the plan for this containment work locks in "no new test
// may introduce t.Parallel()" - so no other goroutine is opening or closing
// descriptors concurrently with the loop below. Introducing t.Parallel()
// anywhere in this package would make this test flaky in the failing
// direction (a concurrent open could mask a genuine leak, or a concurrent
// close could manufacture a false one).
func openFDCountForAddLeakTest(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("cannot introspect open file descriptors on this platform (no /proc/self/fd)")
	}
	return len(entries)
}

// TestAddDoesNotLeakFileDescriptorsOnWriteFailure - add() must close the file
// handle it opened even when the write itself fails. /dev/full always fails
// a write with ENOSPC, which reproduces the failure path without needing a
// real full disk or a broken pipe.
func TestAddDoesNotLeakFileDescriptorsOnWriteFailure(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("/dev/full not available on this platform")
	}

	originalDbpath := dbpath
	dbpath = "/dev"
	t.Cleanup(func() { dbpath = originalDbpath })

	key, err := K("full")
	if err != nil {
		t.Fatalf(`K("full") failed: %v`, err)
	}

	// Fifty iterations is also what makes the leak reliably visible: Go's os
	// package attaches a finaliser that closes a *os.File's descriptor when
	// it is garbage collected, so a leaked *os.File does not necessarily
	// stay leaked forever. Fifty iterations allocate too little for a GC
	// cycle to plausibly run mid-loop, so the leak stays visible for the
	// "after" count below - but that is a real, if small, dependency on GC
	// timing rather than a guarantee.
	before := openFDCountForAddLeakTest(t)
	for i := 0; i < 50; i++ {
		// Assert the specific write error (ENOSPC), not just "some error": if
		// the open itself failed instead (permissions, a sandbox denying
		// /dev/full, a future dbpath change), no descriptor would ever be
		// opened and a bare err != nil check would pass without exercising
		// the leak at all.
		if _, err := NewCommand(Add, key, map[string]string{"x-id": "full"}, []byte("x")).Exec(); !errors.Is(err, syscall.ENOSPC) {
			t.Fatalf("expected add() to fail writing to /dev/full with ENOSPC, got %v", err)
		}
	}
	after := openFDCountForAddLeakTest(t)

	if after > before {
		t.Errorf("add() leaked file descriptors on a write failure: before=%d after=%d", before, after)
	}
}
