// apps/backend/containers/id1/errors.go
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
