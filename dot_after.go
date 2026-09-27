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
	"strconv"
	"strings"
	"time"
)

/*
scans a folder for .after.<time> files, if time is after now, reads end executes command inside, deletes the file.
*
*/
func dotAfter(dir string) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		log.Printf("dotAfter: error opening root %s: %s", dir, err)
		return
	}
	defer root.Close()

	fs.WalkDir(root.FS(), ".", func(relPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			log.Printf("dotAfter: walk error at %s: %s", relPath, walkErr)
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		isDotAfterFile := strings.HasPrefix(d.Name(), ".after.")
		if !isDotAfterFile {
			return nil
		}
		timestampMS, _ := strconv.Atoi(strings.Split(d.Name(), ".")[2])
		timestampIsPast := time.Now().UnixMilli() > int64(timestampMS)
		if !timestampIsPast {
			return nil
		}
		dotAfterContent, _ := root.ReadFile(relPath)
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
		//
		// relPath is already store-root-relative and slash-separated (fs.WalkDir's
		// own contract), and it never traverses a symlinked component - the check
		// above skips any symlinked entry before descending into it, and the same
		// check refuses a symlinked LEAF entry outright - so a file reached only
		// through a symlink is never visited here at all, and owningId is always
		// the file's own real, physical first path segment.
		owningId := ""
		segs := strings.Split(relPath, "/")
		if len(segs) > 1 {
			owningId = segs[0]
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
		root.Remove(relPath)
		time.Sleep(time.Millisecond)
		return nil
	})
}
