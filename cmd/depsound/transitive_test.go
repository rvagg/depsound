package main

import "testing"

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
