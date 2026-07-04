package gopkg

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func load(t *testing.T, gomod string) *Mod {
	t.Helper()
	dir := t.TempDir()
	if gomod != "" {
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDeltas(t *testing.T) {
	old := load(t, `module github.com/x/y
go 1.23.0
toolchain go1.23.8

require (
	github.com/a/b v1.0.0
	github.com/c/d v2.0.0+incompatible
	github.com/ind/dep v1.0.0 // indirect
)

retract v1.999.0 // published in error
`)
	niu := load(t, `module github.com/x/y
go 1.25.7

tool github.com/tools/gen

require (
	github.com/a/b v1.2.0
	github.com/ind/dep v1.1.0 // indirect
)

replace github.com/a/b => ../local-fork

replace github.com/c/d v2.0.0+incompatible => github.com/fork/d v2.0.1+incompatible
`)

	cons := ConstraintsDelta(old, niu)
	byKey := map[string]string{}
	for _, c := range cons {
		byKey[c.Key] = c.Status
	}
	if byKey["go directive"] != "changed" || byKey["toolchain"] != "removed" || byKey["tool block"] != "added" {
		t.Errorf("constraints = %+v", cons)
	}

	deps := RequireDelta(old, niu)
	var sawBump, sawRemoved, sawIndirect bool
	var replaceNames []string
	for _, d := range deps {
		switch {
		case d.Name == "github.com/a/b" && d.Section == "require":
			sawBump = d.From == "v1.0.0" && d.To == "v1.2.0"
		case d.Name == "github.com/c/d" && d.Section == "require":
			sawRemoved = d.Status == "removed"
		case d.Section == "replace":
			if d.Flag == "" {
				t.Errorf("unflagged replace: %+v", d)
			}
			replaceNames = append(replaceNames, d.Name)
		case d.Name == "github.com/ind/dep":
			sawIndirect = true
		}
	}
	if !sawBump || !sawRemoved {
		t.Errorf("deps = %+v", deps)
	}
	if sawIndirect {
		t.Error("indirect requirement leaked into delta")
	}
	// version-specific replaces keep Old.Version in the key
	if len(replaceNames) != 2 || !slices.Contains(replaceNames, "github.com/c/d@v2.0.0+incompatible") {
		t.Errorf("replace names = %v", replaceNames)
	}
}

func TestModulePath(t *testing.T) {
	m := load(t, "module github.com/mattn/go-sqlite3\ngo 1.21\n")
	if m.Path() != "github.com/mattn/go-sqlite3" {
		t.Errorf("Path() = %q", m.Path())
	}
	if load(t, "").Path() != "" {
		t.Error("missing go.mod should yield empty module path")
	}
}

func TestLoadForgiving(t *testing.T) {
	m := load(t, "") // no go.mod at all
	if len(m.Warnings) != 1 {
		t.Errorf("missing go.mod: %+v", m.Warnings)
	}
	m = load(t, "this is not a go.mod ][")
	if len(m.Warnings) != 1 {
		t.Errorf("unparseable go.mod: %+v", m.Warnings)
	}
	if got := ConstraintsDelta(m, m); len(got) != 0 {
		t.Errorf("empty mods should have no deltas: %+v", got)
	}
}

func TestScanCgo(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("plain.go", "package x\n\nfunc F() {}\n")
	write("notgo.c", `#include "C"`)
	if ScanCgo(dir) {
		t.Error("false positive cgo")
	}
	// the cgo preamble comment carries the C code and can exceed any
	// head-bytes bound; whole-file scanning must still find the import
	bigPreamble := "package y\n\n/*\n" + strings.Repeat("// C code filler\n", 1000) + "*/\nimport \"C\" // cgo\n"
	write("sub/cgo.go", bigPreamble)
	if !ScanCgo(dir) {
		t.Error("import \"C\" after a large preamble (with trailing comment) not detected")
	}

	dir2 := t.TempDir()
	p := filepath.Join(dir2, "block.go")
	if err := os.WriteFile(p, []byte("package z\n\nimport (\n\t\"fmt\"\n\t\"C\"\n)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !ScanCgo(dir2) {
		t.Error("import block \"C\" not detected")
	}
}
