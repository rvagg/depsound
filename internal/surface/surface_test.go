package surface

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const patch = `diff --git a/old/ecc/bls12-381/g1.go b/new/ecc/bls12-381/g1.go
index 1111111..2222222 100644
--- a/old/ecc/bls12-381/g1.go
+++ b/new/ecc/bls12-381/g1.go
@@ -10,4 +10,5 @@ func (p *G1) Add(q *G1) {
 context
-old line
+new line
+another
 context
@@ -100,3 +101,3 @@ func (p *G1) Mul(s *Fr) {
 context
-before
+after
diff --git a/old/ecc/bn254/g1.go b/new/ecc/bn254/g1.go
index 3333333..4444444 100644
--- a/old/ecc/bn254/g1.go
+++ b/new/ecc/bn254/g1.go
@@ -5 +5 @@ func Setup() {
-x
+y
diff --git a/old/blob.bin b/new/blob.bin
index 5555555..6666666 100644
Binary files a/old/blob.bin and b/new/blob.bin differ
diff --git a/old/docs/a.md b/new/renamed/a.md
similarity index 90%
rename from old/docs/a.md
rename to new/renamed/a.md
@@ -1 +1 @@
-title
+Title
`

func writePatch(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "diff.patch")
	if err := os.WriteFile(p, []byte(patch), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParse(t *testing.T) {
	idx, err := Parse(writePatch(t), "old", "new")
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Files) != 4 {
		t.Fatalf("files = %d", len(idx.Files))
	}

	g1 := idx.Files[0]
	if g1.Path != "ecc/bls12-381/g1.go" || len(g1.Hunks) != 2 {
		t.Fatalf("g1 = %+v", g1)
	}
	if g1.Hunks[0].Symbol != "func (p *G1) Add(q *G1) {" || g1.Hunks[0].NewStart != 10 || g1.Hunks[0].NewLines != 5 {
		t.Errorf("hunk0 = %+v", g1.Hunks[0])
	}
	if g1.Hunks[1].Symbol != "func (p *G1) Mul(s *Fr) {" {
		t.Errorf("hunk1 = %+v", g1.Hunks[1])
	}

	if !idx.Files[2].Binary {
		t.Errorf("binary not detected: %+v", idx.Files[2])
	}
	if ren := idx.Files[3]; ren.Path != "renamed/a.md" || ren.OldPath != "docs/a.md" {
		t.Errorf("rename = %+v", ren)
	}

	// the two g1.go hunks and the bn254 Setup hunk carry symbols; the
	// doc rename's @@ -1 +1 @@ has no function context
	with, total := idx.Attributed()
	if total != 4 || with != 3 {
		t.Errorf("attribution = %d/%d", with, total)
	}
}

func TestMatchStatuses(t *testing.T) {
	idx, err := Parse(writePatch(t), "old", "new")
	if err != nil {
		t.Fatal(err)
	}

	r := idx.Match("ecc/bls12-381", []string{"ecc/bls12-381"}, true)
	if r.Status != StatusMatched || len(r.Files) != 1 {
		t.Errorf("bls12-381 = %+v", r)
	}
	r = idx.Match("ecc/bw6-761", []string{"ecc/bw6-761"}, true)
	if r.Status != StatusNoChangedFiles {
		t.Errorf("untouched = %+v", r)
	}
	r = idx.Match("golang.org/x/other", nil, true)
	if r.Status != StatusUnmapped {
		t.Errorf("unmapped = %+v", r)
	}
	// prefix must not match on partial segment names
	r = idx.Match("ecc/bls12", []string{"ecc/bls12"}, true)
	if r.Status != StatusNoChangedFiles {
		t.Errorf("partial segment matched: %+v", r)
	}

	// Go package semantics: importing "ecc" does NOT import ecc/bls12-381;
	// its own package is unchanged, only descendants changed
	r = idx.Match("ecc", []string{"ecc"}, true)
	if r.Status != StatusSubpackagesOnly || len(r.Files) != 0 || len(r.Descendants) == 0 {
		t.Errorf("subpackage-only = %+v", r)
	}
	// path semantics (npm): the whole subtree is the unit
	r = idx.Match("ecc", []string{"ecc"}, false)
	if r.Status != StatusMatched || len(r.Descendants) != 0 {
		t.Errorf("path-subtree = %+v", r)
	}
}

// A file renamed OUT of a unit's package must not report noChangedFiles:
// the file left the unit, a change to its surface, caught via OldPath.
func TestMatchRenameAway(t *testing.T) {
	idx := &Index{Files: []FileSurface{
		{Path: "y/moved.go", OldPath: "x/moved.go", Hunks: []Hunk{{}}},
	}}
	// unit x: the file used to live here, now gone; must be MATCHED, not
	// the false all-clear
	r := idx.Match("x", []string{"x"}, true)
	if r.Status != StatusMatched || len(r.Files) != 1 {
		t.Errorf("rename-away from x = %+v (want matched)", r)
	}
	// unit y: the file arrived here
	r = idx.Match("y", []string{"y"}, true)
	if r.Status != StatusMatched || len(r.Files) != 1 {
		t.Errorf("rename-into y = %+v (want matched)", r)
	}
	// unit z: uninvolved
	r = idx.Match("z", []string{"z"}, true)
	if r.Status != StatusNoChangedFiles {
		t.Errorf("uninvolved z = %+v", r)
	}
}

func TestSymbolHunksAndExtract(t *testing.T) {
	p := writePatch(t)
	idx, err := Parse(p, "old", "new")
	if err != nil {
		t.Fatal(err)
	}

	sel := idx.SymbolHunks(nil, "Mul")
	if len(sel) != 1 || len(sel[0].Hunks) != 1 {
		t.Fatalf("SymbolHunks = %+v", sel)
	}

	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}

	// body scan: "another" appears only in the Add hunk BODY, not any
	// symbol header
	byBody := idx.SymbolHunks(raw, "another")
	if len(byBody) != 1 || byBody[0].Hunks[0].Symbol != "func (p *G1) Add(q *G1) {" {
		t.Errorf("body-scan match = %+v", byBody)
	}
	out := string(idx.Extract(raw, sel))
	if !strings.Contains(out, "func (p *G1) Mul") || !strings.Contains(out, "+after") {
		t.Errorf("extract missing Mul hunk:\n%s", out)
	}
	if strings.Contains(out, "Add(q *G1)") || strings.Contains(out, "+another") {
		t.Errorf("extract leaked unselected hunk:\n%s", out)
	}
	if !strings.Contains(out, "diff --git a/old/ecc/bls12-381/g1.go") {
		t.Errorf("extract missing file header:\n%s", out)
	}

	// whole-file extraction includes every hunk
	whole := idx.Match("ecc/bls12-381", []string{"ecc/bls12-381"}, true)
	out = string(idx.Extract(raw, whole.Files))
	if !strings.Contains(out, "+another") || !strings.Contains(out, "+after") {
		t.Errorf("whole-file extract incomplete:\n%s", out)
	}
	if strings.Contains(out, "bn254") {
		t.Errorf("whole-file extract leaked next file:\n%s", out)
	}
}

func TestDirRollup(t *testing.T) {
	idx, err := Parse(writePatch(t), "old", "new")
	if err != nil {
		t.Fatal(err)
	}
	roll := idx.DirRollup(2)
	byDir := map[string]DirStat{}
	for _, d := range roll {
		byDir[d.Dir] = d
	}
	if byDir["ecc/bls12-381"].Files != 1 || byDir["ecc/bls12-381"].Hunks != 2 {
		t.Errorf("rollup = %+v", roll)
	}
	if byDir["ecc/bn254"].Files != 1 {
		t.Errorf("rollup = %+v", roll)
	}
}
