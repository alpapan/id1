// apps/id1/req.go
//
// group: models
// tags: http, requests, parsing
// summary: HTTP request type definitions and parsing for key/value operations.
// Handles JSON unmarshaling and validation for all command types.
//
//

package id1

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

var opMap = map[string]Op{
	http.MethodGet:    Get, // also list
	http.MethodPost:   Set,
	http.MethodDelete: Del,
	http.MethodPatch:  Add, // also mov
}

type RequestProps struct {
	Id          string
	Token       string
	IsWebSocket bool
	// KeyErr carries K()'s refusal of a malformed request path. Handle turns a
	// non-nil KeyErr into HTTP 400 before any operation runs, so a key that
	// could not be constructed never reaches the filesystem.
	KeyErr error
	Cmd    Command

	// BodyTooLarge is set when the request body ran past the largest cap any
	// route sets (KVBodyLimitBytes), or past a smaller cap LimitBody applied.
	// The over-limit bytes are not kept, and Handle answers 413.
	BodyTooLarge bool
}

func (t RequestProps) String() string {
	return fmt.Sprintf("req cmd: %s %s (%s): %s", t.Cmd.Op, t.Cmd.Key, t.Cmd.Args, string(t.Cmd.Data))
}

func NewRequestProps(r *http.Request) RequestProps {
	// A trailing "*" on a GET marks a list request. Strip it BEFORE the key is
	// constructed. Leaving it in makes the final segment of "/victim/pub/..*"
	// the three characters "..*", which no containment check recognises as a
	// traversal; list() then trims the star itself and hands the real ".." to
	// the filesystem. Stripping first means the key the guards inspect is the
	// key the filesystem will be given.
	path := r.URL.Path
	isListRequest := r.Method == http.MethodGet && strings.HasSuffix(path, "*")
	if isListRequest {
		path = strings.TrimSuffix(path, "*")
	}

	key, err := K(path)
	if err != nil {
		log.Printf("new request props: rejected malformed key %q: %v", r.URL.Path, err)
	}
	req := RequestProps{
		Id:     key.Id,
		KeyErr: err,
		Cmd: Command{
			Op:   opMap[r.Method],
			Key:  key,
			Args: map[string]string{},
			Data: []byte{},
		},
	}

	paramPairs := r.URL.Query()
	for key, values := range paramPairs {
		req.Cmd.Args[key] = values[0]
	}

	if r.Header["Authorization"] != nil && len(r.Header["Authorization"]) > 0 {
		req.Token = strings.TrimPrefix(r.Header["Authorization"][0], "Bearer ")
	}

	if r.Header["Upgrade"] != nil {
		req.IsWebSocket = true
	}

	// Read through a hard stop at the largest cap any route sets, so a caller
	// that does not go through LimitBody cannot make this read buffer an
	// unbounded body. A smaller cap applied by LimitBody reports itself as
	// *http.MaxBytesError.
	data, readErr := io.ReadAll(io.LimitReader(r.Body, KVBodyLimitBytes+1))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(readErr, &tooLarge) || int64(len(data)) > KVBodyLimitBytes:
		req.BodyTooLarge = true
	case readErr != nil:
		log.Printf("error reading request body, %s", readErr)
	default:
		req.Cmd.Data = data
	}

	if isListRequest {
		req.Cmd.Op = List
	}
	if r.Method == http.MethodPatch && len(r.Header["X-Move-To"]) > 0 {
		req.Cmd.Op = Mov
		req.Cmd.Data = []byte(r.Header["X-Move-To"][0])
	}

	return req
}
