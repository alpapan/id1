// apps/backend/containers/id1/cmd_op.go
//
// group: models
// tags: operations, enum
// summary: Operation type enumeration for key/value store commands.
// Defines Set, Get, Add, Del, Mov, and other operation constants.
//
//

package id1

type Op int

const (
	Set Op = iota
	Add
	Get
	Del
	Mov
	List
)

var opName = map[Op]string{
	Set:  "set",
	Add:  "add",
	Get:  "get",
	Del:  "del",
	Mov:  "mov",
	List: "list",
}

var nameOp = map[string]Op{
	"set":  Set,
	"add":  Add,
	"get":  Get,
	"del":  Del,
	"mov":  Mov,
	"list": List,
}

func (t Op) String() string {
	return opName[t]
}

func op(s string) Op {
	return nameOp[s]
}
