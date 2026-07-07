package main

import (
	"testing"

	"github.com/rvagg/depsound/internal/gopkg"
)

func TestDiffRequireSets(t *testing.T) {
	old := map[string]gopkg.Require{
		"a":    {Path: "a", Version: "v1.0.0"},
		"b":    {Path: "b", Version: "v1.0.0", Indirect: true},
		"gone": {Path: "gone", Version: "v1.0.0", Indirect: true},
	}
	niu := map[string]gopkg.Require{
		"a": {Path: "a", Version: "v2.0.0"},                 // changed, direct
		"b": {Path: "b", Version: "v3.0.0", Indirect: true}, // changed, indirect
		"c": {Path: "c", Version: "v1.0.0", Indirect: true}, // added
	}
	d := diffRequireSets(old, niu)

	if len(d.changed) != 2 || d.directChanged != 1 || d.indirectChanged != 1 {
		t.Fatalf("changed=%+v direct=%d indirect=%d", d.changed, d.directChanged, d.indirectChanged)
	}
	// sorted by path: a then b
	if d.changed[0].Path != "a" || d.changed[0].From != "v1.0.0" || d.changed[0].To != "v2.0.0" {
		t.Errorf("changed[0]=%+v", d.changed[0])
	}
	if len(d.added) != 1 || d.added[0].Path != "c" || !d.added[0].Indirect {
		t.Errorf("added=%+v", d.added)
	}
	if len(d.removed) != 1 || d.removed[0].Path != "gone" {
		t.Errorf("removed=%+v", d.removed)
	}
}
