package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rvagg/depsound/internal/depsdev"
)

func TestDiffResolved(t *testing.T) {
	old := []resolvedDep{
		{"a", "1.0.0", false},
		{"b", "1.0.0", true},
		{"gone", "1.0.0", true},
	}
	niu := []resolvedDep{
		{"a", "2.0.0", false}, // changed, direct
		{"b", "3.0.0", true},  // changed, indirect
		{"c", "1.0.0", true},  // added
	}
	d := diffResolved(old, niu)

	if len(d.changed) != 2 || d.directChanged != 1 || d.indirectChanged != 1 {
		t.Fatalf("changed=%+v direct=%d indirect=%d", d.changed, d.directChanged, d.indirectChanged)
	}
	if d.changed[0].Path != "a" || d.changed[0].From != "1.0.0" || d.changed[0].To != "2.0.0" {
		t.Errorf("changed[0]=%+v", d.changed[0])
	}
	if len(d.added) != 1 || d.added[0].Path != "c" || !d.added[0].Indirect {
		t.Errorf("added=%+v", d.added)
	}
	if len(d.removed) != 1 || d.removed[0].Path != "gone" {
		t.Errorf("removed=%+v", d.removed)
	}
}

// Multiple versions of one name (Cargo/npm dedup): a lone removed+added is a
// clean bump; extra versions are listed, not force-paired.
func TestDiffResolvedMultiVersion(t *testing.T) {
	// dedup collapse: two majors of x present, one drops out -> a removal
	old := []resolvedDep{{"x", "1.0.0", false}, {"x", "2.0.0", false}}
	niu := []resolvedDep{{"x", "2.0.0", false}}
	d := diffResolved(old, niu)
	if len(d.changed) != 0 || len(d.removed) != 1 || d.removed[0].From != "1.0.0" {
		t.Errorf("dedup collapse: changed=%+v removed=%+v", d.changed, d.removed)
	}

	// clean single bump still pairs
	d = diffResolved([]resolvedDep{{"y", "1.0.0", false}}, []resolvedDep{{"y", "1.1.0", false}})
	if len(d.changed) != 1 || d.changed[0].To != "1.1.0" {
		t.Errorf("single bump not paired: %+v", d.changed)
	}
}

// deps.dev's DIRECT is relative to the projected package, and everything else
// is deeper in its tree, so the neutral set carries it as indirect.
func TestNodesToResolved(t *testing.T) {
	got := nodesToResolved([]depsdev.Node{
		{Name: "glob", Version: "10.5.0", Relation: "DIRECT"},
		{Name: "jackspeak", Version: "3.4.3", Relation: "INDIRECT"},
	})
	if len(got) != 2 || got[0].indirect || !got[1].indirect {
		t.Errorf("nodesToResolved = %+v", got)
	}
}

// A repo that keeps a different lockfile must not read as a bare 404: the
// sibling probe names what is actually there.
func TestSiblingLockKinds(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"pnpm-lock.yaml", "go.mod"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := siblingLockKinds(filepath.Join(dir, "package-lock.json"), "npm")
	if len(got) != 2 || got[0] != "go" || got[1] != "pnpm" {
		t.Errorf("siblingLockKinds = %v, want [go pnpm]", got)
	}
	// the kind asked for is never suggested back
	if got := siblingLockKinds(filepath.Join(dir, "go.mod"), "go"); len(got) != 1 || got[0] != "pnpm" {
		t.Errorf("self-suggestion: %v", got)
	}
	// an https source has no siblings to probe
	if got := siblingLockKinds("https://example.com/package-lock.json", "npm"); got != nil {
		t.Errorf("https probe = %v", got)
	}
	// the hint leaves an unprobeable error untouched
	err := errors.New("boom")
	if wrongKindHint(err, "https://example.com/x", "npm") != err {
		t.Error("hint must pass through when nothing was found")
	}
}
