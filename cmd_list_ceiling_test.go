// apps/id1/cmd_list_ceiling_test.go
//
// group: server
// tags: storage, list-operation, limits, testing
// summary: Tests that list clamps its three limits at their defaults and that walkDir stops at the limit.
//
//

package id1

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// listCeilingCase is one caller-supplied list argument and the field it feeds.
type listCeilingCase struct {
	name    string
	arg     string
	field   func(ListOptions) int
	ceiling int
}

// listCeilingCases is the whole ceiling contract in one place. It is asserted
// by TestListOptionsParseCaseListIsPopulatedAndNamed, so deleting a row fails a
// test rather than silently dropping the coverage it carried.
var listCeilingCases = []listCeilingCase{
	{name: "limit", arg: "limit", field: func(o ListOptions) int { return o.Limit }, ceiling: 1000},
	{name: "size-limit", arg: "size-limit", field: func(o ListOptions) int { return o.SizeLimit }, ceiling: 100 * MB},
	{name: "total-size-limit", arg: "total-size-limit", field: func(o ListOptions) int { return o.TotalSizeLimit }, ceiling: 100 * MB},
}

func TestListOptionsParseCaseListIsPopulatedAndNamed(t *testing.T) {
	if len(listCeilingCases) != 3 {
		t.Fatalf("listCeilingCases must hold 3 cases, got %d - update this guard when adding or dropping a row", len(listCeilingCases))
	}
	names := map[string]bool{}
	for _, c := range listCeilingCases {
		names[c.name] = true
	}
	for _, want := range []string{"limit", "size-limit", "total-size-limit"} {
		if !names[want] {
			t.Errorf("listCeilingCases is missing the case %q", want)
		}
	}
}

func TestListOptionsParseClampsAboveTheCeiling(t *testing.T) {
	for _, c := range listCeilingCases {
		t.Run(c.name, func(t *testing.T) {
			var opt ListOptions
			opt.Parse(map[string]string{c.arg: "999999999999"})
			if got := c.field(opt); got != c.ceiling {
				t.Errorf("%s=999999999999: got %d, want the ceiling %d", c.arg, got, c.ceiling)
			}
		})
	}
}

func TestListOptionsParseKeepsAnInRangeValue(t *testing.T) {
	for _, c := range listCeilingCases {
		t.Run(c.name, func(t *testing.T) {
			var opt ListOptions
			opt.Parse(map[string]string{c.arg: "7"})
			if got := c.field(opt); got != 7 {
				t.Errorf("%s=7: got %d, want 7", c.arg, got)
			}
		})
	}
}

func TestListOptionsParseKeepsZero(t *testing.T) {
	for _, c := range listCeilingCases {
		t.Run(c.name, func(t *testing.T) {
			var opt ListOptions
			opt.Parse(map[string]string{c.arg: "0"})
			if got := c.field(opt); got != 0 {
				t.Errorf("%s=0: got %d, want 0", c.arg, got)
			}
		})
	}
}

func TestListOptionsParseNegativeOrUnparseableBecomesTheCeiling(t *testing.T) {
	for _, c := range listCeilingCases {
		for _, raw := range []string{"-5", "abc", ""} {
			t.Run(fmt.Sprintf("%s=%q", c.name, raw), func(t *testing.T) {
				var opt ListOptions
				opt.Parse(map[string]string{c.arg: raw})
				if got := c.field(opt); got != c.ceiling {
					t.Errorf("%s=%q: got %d, want the ceiling %d", c.arg, raw, got, c.ceiling)
				}
			})
		}
	}
}

func TestWalkDirStopsAtTheLimitAndKeepsTheFirstEntries(t *testing.T) {
	root := newTTLStore(t)
	bulk := filepath.Join(root, "alice", "bulk")
	if err := os.MkdirAll(bulk, 0770); err != nil {
		t.Fatalf("seeding the tree failed: %v", err)
	}
	for i := 0; i < 300; i++ {
		name := filepath.Join(bulk, fmt.Sprintf("f%03d", i))
		if err := os.WriteFile(name, []byte("x"), 0644); err != nil {
			t.Fatalf("seeding the tree failed: %v", err)
		}
	}

	visits := 0
	walkDirVisitHook = func(string) { visits++ }
	t.Cleanup(func() { walkDirVisitHook = nil })

	opt := ListOptions{Limit: 10, SizeLimit: 100 * MB, TotalSizeLimit: 100 * MB, Keys: true, Recursive: true}
	results, err := walkDir(bulk, opt)
	if err != nil {
		t.Fatalf("walkDir returned an error: %v", err)
	}

	got := []string{}
	for key := range results {
		got = append(got, key)
	}
	sort.Strings(got)
	want := []string{}
	for i := 0; i < 10; i++ {
		want = append(want, fmt.Sprintf("alice/bulk/f%03d", i))
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("walkDir must keep the first %d entries in lexical order\n got: %v\nwant: %v", opt.Limit, got, want)
	}

	// The walk visits the directory itself, then the ten kept files, then the one
	// entry that proves the limit is reached. Anything beyond that is wasted work.
	if visits > opt.Limit+2 {
		t.Errorf("walkDir kept walking after the limit: %d entries visited for a limit of %d, want at most %d", visits, opt.Limit, opt.Limit+2)
	}
}
