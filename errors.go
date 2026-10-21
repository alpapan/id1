// apps/id1/errors.go
//
// group: utils
// tags: errors, exceptions
// summary: Custom error definitions for authorization and storage operations.
//
//

package id1

import "errors"

var ErrNotFound = errors.New("not found")

var ErrExists = errors.New("item exists")

var ErrLimitExceeded = errors.New("limit exceeded")

var ErrForbidden = errors.New("forbidden")

// ErrPreflightFailed, ErrRecursiveAndChildren and ErrNotSupported describe a
// request the caller can correct, so the handler sends their text back.
var ErrPreflightFailed = errors.New("failed preflight checks")

var ErrRecursiveAndChildren = errors.New("recursive can't be true if children is true")

var ErrNotSupported = errors.New("not supported")

// isClientError reports whether err describes the caller's own request. The
// handler answers such an error 400 with its text; any other error is logged
// and answered 500 with a fixed text, because it can carry the store path.
func isClientError(err error) bool {
	for _, clientErr := range []error{ErrExists, ErrInvalidKey, ErrPreflightFailed, ErrRecursiveAndChildren, ErrNotSupported} {
		if errors.Is(err, clientErr) {
			return true
		}
	}
	return false
}

// ErrUnauthorised is returned by ExecAs when the caller is not authorised to
// run the command; the command is not run.
var ErrUnauthorised = errors.New("unauthorised")
