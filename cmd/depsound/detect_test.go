package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeGoMod writes a go.mod with the given require lines and returns its path.
// Each require is "path version" optionally suffixed " //indirect".
func writeGoMod(t *testing.T, name string, requires ...string) string {
	t.Helper()
	var b string
	b = "module example.com/m\n\ngo 1.21\n\nrequire (\n"
	for _, r := range requires {
		b += "\t" + r + "\n"
	}
	b += ")\n"
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func findChange(cs []detectChange, name, from, to string) *detectChange {
	for i := range cs {
		if cs[i].Name == name && cs[i].From == from && cs[i].To == to {
			return &cs[i]
		}
	}
	return nil
}

func TestDetectGoBump(t *testing.T) {
	old := writeGoMod(t, "go.mod", "github.com/x/y v1.3.0")
	niu := writeGoMod(t, "go.mod", "github.com/x/y v1.4.0")
	res := detectChanges([]detectPair{{path: "go.mod", old: old, new: niu}})

	if len(res.Changed) != 1 {
		t.Fatalf("want 1 change, got %d: %+v", len(res.Changed), res.Changed)
	}
	c := res.Changed[0]
	if c.Eco != "go" || c.Name != "github.com/x/y" || c.From != "v1.3.0" || c.To != "v1.4.0" {
		t.Fatalf("unexpected change %+v", c)
	}
	if len(res.Added) != 0 {
		t.Fatalf("want no additions, got %+v", res.Added)
	}
}

// TestDetectGoMultiModule is the go-car case: separate go.mods with
// intersecting deps. Same dep at the same endpoints anywhere collapses to one
// change carrying every source file; the same dep at different endpoints stays
// a distinct review.
func TestDetectGoMultiModule(t *testing.T) {
	pairs := []detectPair{
		{path: "go.mod", old: writeGoMod(t, "go.mod", "github.com/x/y v1.2.0"), new: writeGoMod(t, "go.mod", "github.com/x/y v1.4.0")},
		{path: "cmd/go.mod", old: writeGoMod(t, "go.mod", "github.com/x/y v1.3.0"), new: writeGoMod(t, "go.mod", "github.com/x/y v1.4.0")},
		{path: "v2/go.mod", old: writeGoMod(t, "go.mod", "github.com/x/y v1.3.0"), new: writeGoMod(t, "go.mod", "github.com/x/y v1.4.0")},
	}
	res := detectChanges(pairs)

	if len(res.Changed) != 2 {
		t.Fatalf("want 2 distinct changes (1.2 and 1.3 endpoints), got %d: %+v", len(res.Changed), res.Changed)
	}
	// the 1.3->1.4 change is carried by cmd/ and v2/, deduped with both files
	shared := findChange(res.Changed, "github.com/x/y", "v1.3.0", "v1.4.0")
	if shared == nil {
		t.Fatalf("missing the 1.3.0->1.4.0 change: %+v", res.Changed)
	}
	if len(shared.Files) != 2 || shared.Files[0] != "cmd/go.mod" || shared.Files[1] != "v2/go.mod" {
		t.Fatalf("want provenance [cmd/go.mod v2/go.mod] sorted, got %v", shared.Files)
	}
	// the 1.2->1.4 change stays separate (different from), from root only
	root := findChange(res.Changed, "github.com/x/y", "v1.2.0", "v1.4.0")
	if root == nil || len(root.Files) != 1 || root.Files[0] != "go.mod" {
		t.Fatalf("want a distinct 1.2.0->1.4.0 from [go.mod], got %+v", root)
	}
}

// TestDetectGoAddition: an absent old side (a newly-added go.mod, or a new
// require) surfaces as census-shaped, never as a silent nothing.
func TestDetectGoAddition(t *testing.T) {
	niu := writeGoMod(t, "go.mod", "github.com/x/y v1.0.0")
	res := detectChanges([]detectPair{{path: "go.mod", old: "-", new: niu}})

	if len(res.Changed) != 0 {
		t.Fatalf("want no bumps, got %+v", res.Changed)
	}
	if len(res.Added) != 1 || res.Added[0].Name != "github.com/x/y" || res.Added[0].To != "v1.0.0" || res.Added[0].From != "" {
		t.Fatalf("want one census-shaped addition, got %+v", res.Added)
	}
}

// TestDetectIndirect carries go.mod's // indirect through, so a transitive-only
// bump is still detected and labelled.
func TestDetectIndirect(t *testing.T) {
	old := writeGoMod(t, "go.mod", "github.com/x/y v1.0.0 // indirect")
	niu := writeGoMod(t, "go.mod", "github.com/x/y v1.1.0 // indirect")
	res := detectChanges([]detectPair{{path: "go.mod", old: old, new: niu}})
	if len(res.Changed) != 1 || !res.Changed[0].Indirect {
		t.Fatalf("want one indirect change, got %+v", res.Changed)
	}
}

// TestDetectSkipsUnknown: a changed file with no detector is noted, not
// silently dropped, and once per base name.
func TestDetectSkipsUnknown(t *testing.T) {
	res := detectChanges([]detectPair{
		{path: "package-lock.json", old: "-", new: "-"},
		{path: "sub/package-lock.json", old: "-", new: "-"},
	})
	if len(res.Changed) != 0 || len(res.Added) != 0 {
		t.Fatalf("want nothing detected, got %+v %+v", res.Changed, res.Added)
	}
	if len(res.Notes) != 1 {
		t.Fatalf("want one skip note (deduped by base name), got %v", res.Notes)
	}
}

// TestDetectReadPairsRejectsMalformed guards the stdin contract: exactly three
// tab-separated fields.
func TestDetectReadPairsRejectsMalformed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pairs")
	if err := os.WriteFile(p, []byte("go.mod only-two\tfields\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readDetectPairs(p); err == nil {
		t.Fatal("want error on a non-3-field line")
	}
}
