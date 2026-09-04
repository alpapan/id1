// apps/backend/containers/id1/dot_after.go
//
// group: server
// tags: authorization, delegation, permissions
// summary: Post-operation authorization enforcement via dot-after pattern.
// Validates permission changes after key operations complete.
//
//

package id1

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

/*
scans a folder for .after.<time> files, if time is after now, reads end executes command inside, deletes the file.
*
*/
func dotAfter(dir string) {
	filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if info == nil {
			return nil
		}
		isDotAfterFile := strings.HasPrefix(info.Name(), ".after.")
		if !isDotAfterFile {
			return nil
		}
		timestampMS, _ := strconv.Atoi(strings.Split(info.Name(), ".")[2])
		timestampIsPast := time.Now().UnixMilli() > int64(timestampMS)
		if !timestampIsPast {
			return nil
		}
		dotAfterContent, _ := os.ReadFile(path)
		dotAfterCommand, parseError := ParseCommand(dotAfterContent)

		// Containment. The command body - x-id included - comes from a file on
		// disk, so it says only what whoever wrote the file wanted it to say. The
		// one thing the writer does not choose is WHERE the file sits: a
		// .after. file lives inside a namespace, named by the first segment of
		// its path relative to the store root. A scheduled command may therefore
		// act only on keys inside that same namespace.
		//
		// This refuses both proved attacks: a command targeting another identity
		// from a file planted in the attacker's own namespace, and a command with
		// no target at all (a body of "del:" parses cleanly to a zero-segment
		// key, which would otherwise resolve to the store root). A file sitting
		// directly in the store root has no owning namespace and is refused too.
		//
		// Genuine schedules are unaffected: createDotTtl (cmd_set.go) writes the
		// file at the target key's own parent, so file and target share a
		// namespace by construction.
		owningId := ""
		if relPath, relErr := filepath.Rel(dir, path); relErr == nil {
			segs := strings.Split(filepath.ToSlash(relPath), "/")
			if len(segs) > 1 {
				owningId = segs[0]
			}
		}
		contained := owningId != "" &&
			parseError == nil &&
			len(dotAfterCommand.Key.Segments) > 0 &&
			dotAfterCommand.Key.Id == owningId

		// No HTTP request context in the scheduled sweep, so the internal-secret
		// new-id bootstrap exemption is never available here - a scheduled command
		// relies only on the owner/public-get/dot-op grants.
		if contained && auth(dotAfterCommand.Args["x-id"], dotAfterCommand, "") {
			dotAfterCommand.Exec()
		} else {
			log.Printf("unauthorised .after command by '%s': %s %s", dotAfterCommand.Args["x-id"], dotAfterCommand.Op, dotAfterCommand.Key)
		}
		os.Remove(path)
		time.Sleep(time.Millisecond)
		return nil
	})
}
