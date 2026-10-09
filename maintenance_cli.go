// apps/id1/maintenance_cli.go
//
// group: server
// tags: maintenance, cli
// summary: Argument-driven, non-serving invocations of the id1 binary. The
// container image is distroless, so the binary itself is the only executable
// available for operations work against the key/value volume.
//
//

package id1

import (
	"fmt"
	"io"
)

const maintenanceUsage = `usage: id1 maintenance legacy-ttl [--apply]

legacy-ttl  Scan the key/value store named by DBPATH for TTL bookkeeping files
            left at the pre-relocation name {parent}/.ttl.{name}, and list them.
            With --apply, remove them as well.

            Scheduled .after. commands are never touched: one that has not fired
            yet is still a correct instruction to expire its key.
`

// RunMaintenanceCommand executes a non-serving, argument-driven invocation of
// the id1 binary. args excludes the program name, and getenv is injected so the
// store root resolves exactly as it does for the server.
//
// The return value is the process exit code: 0 on success, 1 when the store
// could not be read or a removal failed, and 2 when the arguments were not
// understood.
func RunMaintenanceCommand(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) < 2 || args[0] != "maintenance" || args[1] != "legacy-ttl" {
		fmt.Fprint(stderr, maintenanceUsage)
		return 2
	}
	apply := false
	for _, arg := range args[2:] {
		if arg == "--apply" {
			apply = true
			continue
		}
		fmt.Fprintf(stderr, "unknown argument %q\n\n", arg)
		fmt.Fprint(stderr, maintenanceUsage)
		return 2
	}

	_, storeRoot, _, _ := ResolveConfig(getenv)
	report, err := SweepLegacyTTLEntries(storeRoot, apply)
	if err != nil {
		fmt.Fprintf(stderr, "legacy-ttl sweep of %s failed: %v\n", storeRoot, err)
		return 1
	}
	report.WriteText(stdout)
	if report.Failures() > 0 {
		return 1
	}
	return 0
}
