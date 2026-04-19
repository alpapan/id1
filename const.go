// apps/backend/containers/id1/const.go
//
// group: utils
// tags: constants, sizes, units
// summary: Global constants for byte-size units and system limits.
//
//

package id1

const (
	_  = iota
	KB = 1 << (10 * iota)
	MB
	GB
	TB
	PB
)
