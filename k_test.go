// apps/backend/containers/id1/k_test.go
//
// group: models
// tags: keys, parsing, testing
// summary: Tests for key structure parsing and validation.
//
//

package id1

import (
	"testing"
)

func TestKParsesPubPath(t *testing.T) {
	k := K("TestId/pub/key")
	if k.Id != "TestId" {
		t.Errorf("expected Id='TestId', got %q", k.Id)
	}
	if !k.Pub {
		t.Errorf("expected Pub=true, got false")
	}
	if k.Name != "key" {
		t.Errorf("expected Name='key', got %q", k.Name)
	}
	if len(k.Segments) != 3 {
		t.Errorf("expected 3 segments, got %d: %v", len(k.Segments), k.Segments)
	}
	if k.Parent != "TestId/pub" {
		t.Errorf("expected Parent='TestId/pub', got %q", k.Parent)
	}
}

func TestKStripsLeadingTrailingSlashes(t *testing.T) {
	k := K("/TestId/")
	if k.Id != "TestId" {
		t.Errorf("expected Id='TestId', got %q", k.Id)
	}
	if len(k.Segments) != 1 {
		t.Errorf("expected 1 segment, got %d: %v", len(k.Segments), k.Segments)
	}
	if k.Pub {
		t.Errorf("expected Pub=false, got true")
	}
	if k.Name != "TestId" {
		t.Errorf("expected Name='TestId', got %q", k.Name)
	}
	if k.Parent != "" {
		t.Errorf("expected empty Parent, got %q", k.Parent)
	}
}

func TestKSingleSegment(t *testing.T) {
	k := K("root")
	if k.Id != "root" {
		t.Errorf("expected Id='root', got %q", k.Id)
	}
	if k.Name != "root" {
		t.Errorf("expected Name='root', got %q", k.Name)
	}
	if len(k.Segments) != 1 {
		t.Errorf("expected 1 segment, got %d", len(k.Segments))
	}
	if k.Pub {
		t.Errorf("expected Pub=false, got true")
	}
	if k.Parent != "" {
		t.Errorf("expected empty Parent, got %q", k.Parent)
	}
}

func TestKDetectsPubInSecondSegment(t *testing.T) {
	k := K("user1/pub/token")
	if !k.Pub {
		t.Errorf("expected Pub=true for 'user1/pub/token', got false")
	}
	if k.Id != "user1" {
		t.Errorf("expected Id='user1', got %q", k.Id)
	}
}

func TestKDetectsPubFalseWhenNotSecondSegment(t *testing.T) {
	k := K("user1/data/pub")
	if k.Pub {
		t.Errorf("expected Pub=false for 'user1/data/pub', got true (pub is not second segment)")
	}
}

func TestKHandlesComplexPath(t *testing.T) {
	k := K("user123/priv/key/version/2")
	if k.Id != "user123" {
		t.Errorf("expected Id='user123', got %q", k.Id)
	}
	if k.Name != "2" {
		t.Errorf("expected Name='2', got %q", k.Name)
	}
	if k.Pub {
		t.Errorf("expected Pub=false, got true (priv is second segment)")
	}
	if len(k.Segments) != 5 {
		t.Errorf("expected 5 segments, got %d", len(k.Segments))
	}
	if k.Parent != "user123/priv/key/version" {
		t.Errorf("expected Parent='user123/priv/key/version', got %q", k.Parent)
	}
}

func TestKEmptyString(t *testing.T) {
	k := K("")
	if k.Id != "" {
		t.Errorf("expected empty Id, got %q", k.Id)
	}
	if len(k.Segments) != 0 {
		t.Errorf("expected 0 segments, got %d", len(k.Segments))
	}
}
