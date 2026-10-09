// apps/id1/legacy_ttl.go
//
// group: server
// tags: storage, maintenance, ttl
// summary: Detection and removal of TTL bookkeeping files left at the
// pre-relocation name {parent}/.ttl.{name}. Scheduled .after. commands and
// bookkeeping under the reserved .ttl directory are never touched.
//
//

package id1

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// legacyTTLPrefix is the file-name prefix TTL bookkeeping carried before it moved
// into the reserved .ttl directory. A base name carrying it, with at least one
// character after it, names bookkeeping that the current writer does not read.
const legacyTTLPrefix = ".ttl."

// LegacyTTLEntry is one legacy bookkeeping file, named by its path relative to
// the store root and always slash-separated. RemoveErr is empty unless removal
// was attempted and failed.
type LegacyTTLEntry struct {
	RelPath   string
	Removed   bool
	RemoveErr string
}

// LegacyTTLReport is the outcome of one sweep of a store root.
type LegacyTTLReport struct {
	Root    string
	Applied bool
	Entries []LegacyTTLEntry
}

// Failures counts entries whose removal was attempted and failed.
func (r *LegacyTTLReport) Failures() int {
	failures := 0
	for _, entry := range r.Entries {
		if entry.RemoveErr != "" {
			failures++
		}
	}
	return failures
}

// isLegacyTTLName reports whether base names legacy TTL bookkeeping. The bare
// prefix with nothing after it never named a key, so it is not recognised.
func isLegacyTTLName(base string) bool {
	return strings.HasPrefix(base, legacyTTLPrefix) && len(base) > len(legacyTTLPrefix)
}

// ScanLegacyTTLEntries walks root and returns the sorted, slash-separated paths,
// relative to root, of every regular file whose base name is legacy TTL
// bookkeeping.
//
// Only a regular file qualifies. A directory named like bookkeeping is not
// bookkeeping, and a symlink is never followed or removed, so nothing outside
// the store can be reached through one.
func ScanLegacyTTLEntries(root string) ([]string, error) {
	var found []string
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			// The server writes and deletes keys while this runs, so an entry
			// that vanished mid-walk is ordinary, not a failure. A root that
			// does not exist still reports, because WalkDir surfaces that on
			// the first call.
			if os.IsNotExist(err) && path != root {
				return nil
			}
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		if !isLegacyTTLName(entry.Name()) {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		found = append(found, filepath.ToSlash(rel))
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Strings(found)
	return found, nil
}

// SweepLegacyTTLEntries scans root and, when apply is true, removes every legacy
// bookkeeping file it found.
//
// It never removes a .after. scheduled command. An unfired schedule is still a
// correct instruction to expire its key, and id1's own sweeper deletes it once
// it has run; cancelling one would leave a stored credential with no expiry.
func SweepLegacyTTLEntries(root string, apply bool) (*LegacyTTLReport, error) {
	paths, err := ScanLegacyTTLEntries(root)
	if err != nil {
		return nil, err
	}
	report := &LegacyTTLReport{Root: root, Applied: apply}
	for _, rel := range paths {
		entry := LegacyTTLEntry{RelPath: rel}
		if apply {
			removeErr := os.Remove(filepath.Join(root, filepath.FromSlash(rel)))
			if removeErr != nil && !os.IsNotExist(removeErr) {
				entry.RemoveErr = removeErr.Error()
			} else {
				// A file already gone is the outcome this asked for.
				entry.Removed = true
			}
		}
		report.Entries = append(report.Entries, entry)
	}
	return report, nil
}

// WriteText renders the report for an operator reading command output.
func (r *LegacyTTLReport) WriteText(w io.Writer) {
	fmt.Fprintf(w, "legacy TTL bookkeeping scan of %s\n", r.Root)
	for _, entry := range r.Entries {
		switch {
		case entry.RemoveErr != "":
			fmt.Fprintf(w, "FAILED  %s: %s\n", entry.RelPath, entry.RemoveErr)
		case entry.Removed:
			fmt.Fprintf(w, "REMOVED %s\n", entry.RelPath)
		default:
			fmt.Fprintf(w, "FOUND   %s\n", entry.RelPath)
		}
	}
	failures := r.Failures()
	if r.Applied {
		fmt.Fprintf(w, "%d found, %d removed, %d failed\n", len(r.Entries), len(r.Entries)-failures, failures)
		return
	}
	fmt.Fprintf(w, "%d found, none removed (re-run with --apply to remove them)\n", len(r.Entries))
}
