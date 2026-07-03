package gitdiff

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercises the parser against real git output: modify, add, delete,
// rename and binary change across two trees.
func TestDiff(t *testing.T) {
	dir := t.TempDir()
	oldT := filepath.Join(dir, "old")
	newT := filepath.Join(dir, "new")

	write := func(root, rel, content string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write(oldT, "mod.txt", "line1\nline2\n")
	write(newT, "mod.txt", "line1\nline2 changed\nline3\n")
	write(oldT, "del.txt", "going away\n")
	write(newT, "add.txt", "brand new\n")
	write(oldT, "sub/ren-old.txt", "identical content for rename detection\n")
	write(newT, "sub/ren-new.txt", "identical content for rename detection\n")
	write(oldT, "bin.dat", "a\x00b")
	write(newT, "bin.dat", "a\x00c")
	write(oldT, "same.txt", "unchanged\n")
	write(newT, "same.txt", "unchanged\n")

	patch := filepath.Join(dir, "diff.patch")
	diffs, err := Diff(dir, "old", "new", patch)
	if err != nil {
		t.Fatal(err)
	}

	byPath := map[string]FileDiff{}
	for _, d := range diffs {
		byPath[d.Path] = d
	}

	if d := byPath["mod.txt"]; d.Status != "M" || d.Added != 2 || d.Removed != 1 {
		t.Errorf("mod.txt = %+v", d)
	}
	if d := byPath["add.txt"]; d.Status != "A" || d.Added != 1 {
		t.Errorf("add.txt = %+v", d)
	}
	if d := byPath["del.txt"]; d.Status != "D" || d.Removed != 1 {
		t.Errorf("del.txt = %+v", d)
	}
	if d := byPath["sub/ren-new.txt"]; d.Status != "R" || d.OldPath != "sub/ren-old.txt" {
		t.Errorf("rename = %+v", d)
	}
	if d := byPath["bin.dat"]; !d.Binary {
		t.Errorf("bin.dat = %+v", d)
	}
	if _, ok := byPath["same.txt"]; ok {
		t.Error("unchanged file reported")
	}
	if len(diffs) != 5 {
		t.Errorf("want 5 diffs, got %d: %+v", len(diffs), diffs)
	}

	if fi, err := os.Stat(patch); err != nil || fi.Size() == 0 {
		t.Errorf("patch file missing or empty: %v", err)
	}
}

// A package shipping .gitattributes with "*.js -diff" must not be able to
// suppress its own diff, even when the workspace sits inside a git repo
// (which is when git honors in-tree attributes for --no-index).
func TestDiffGitattributesNeutralized(t *testing.T) {
	dir := t.TempDir()
	if err := exec.Command("git", "init", "-q", dir).Run(); err != nil {
		t.Skipf("git init: %v", err)
	}
	for root, content := range map[string]string{"old": "evil(\"payload-v1\")\n", "new": "evil(\"payload-v2\")\n"} {
		for name, c := range map[string]string{"payload.js": content, ".gitattributes": "*.js -diff\n"} {
			p := filepath.Join(dir, root, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	patch := filepath.Join(dir, "diff.patch")
	diffs, err := Diff(dir, "old", "new", patch)
	if err != nil {
		t.Fatal(err)
	}
	var payload *FileDiff
	for i := range diffs {
		if diffs[i].Path == "payload.js" {
			payload = &diffs[i]
		}
	}
	if payload == nil || payload.Binary || payload.Added != 1 || payload.Removed != 1 {
		t.Fatalf("payload diff suppressed or wrong: %+v", payload)
	}
	b, err := os.ReadFile(patch)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "payload-v2") {
		t.Error("patch does not contain the payload content")
	}
}

func TestDiffIdenticalTrees(t *testing.T) {
	dir := t.TempDir()
	for _, root := range []string{"old", "new"} {
		p := filepath.Join(dir, root, "a.txt")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("same\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	diffs, err := Diff(dir, "old", "new", filepath.Join(dir, "d.patch"))
	if err != nil {
		t.Fatal(err)
	}
	if len(diffs) != 0 {
		t.Errorf("identical trees: %+v", diffs)
	}
}
