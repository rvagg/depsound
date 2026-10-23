package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/cache"
	"github.com/rvagg/depsound/internal/fetch"
	"github.com/rvagg/depsound/internal/spec"
)

// The false-negative bug: a root-package import must map to the whole
// module surface, and anything unmappable must fail SAFE, never silently
// as noChangedFiles.
func TestNormalizeGoUnit(t *testing.T) {
	const mod = "github.com/mattn/go-sqlite3"

	cases := []struct {
		name       string
		modulePath string
		unit       string
		wantPrefix []string // nil means "expect unmapped" (nil prefixes)
		wantScoped bool
	}{
		{"root package -> whole module", mod, mod, []string{""}, true},
		{"subpackage -> relative", "github.com/consensys/gnark-crypto",
			"github.com/consensys/gnark-crypto/ecc/bls12-381", []string{"ecc/bls12-381"}, true},
		{"already relative", mod, "ecc/bls12-381", []string{"ecc/bls12-381"}, true},
		{"foreign module -> unmapped, not empty match", mod, "github.com/other/thing", nil, true},
		{"no go.mod, absolute -> unmapped", "", "github.com/x/y", nil, true},
		{"no go.mod, relative -> used", "", "internal/foo", []string{"internal/foo"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefixes, _, scoped := normalizeUnit(spec.Go, tc.modulePath, tc.unit)
			if scoped != tc.wantScoped {
				t.Fatalf("scoped = %v", scoped)
			}
			if !equalStrings(prefixes, tc.wantPrefix) {
				t.Errorf("prefixes = %v, want %v", prefixes, tc.wantPrefix)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// helpTarget routes a `<cmd> --help` (or a bare-spec --help) to the most
// specific help topic, so an agent's reflexive --help never hits "unknown
// flag". hasHelpFlag catches the flag wherever it sits.
func TestHelpRouting(t *testing.T) {
	cases := []struct {
		args []string
		want string // "" = general usage (nil target)
	}{
		{[]string{"transitive", "--help"}, "transitive"},
		{[]string{"census", "-h"}, "census"},
		{[]string{"surface", "npm:x", "1", "2", "--help"}, "surface"},
		{[]string{"npm:foo", "--help"}, "census"},         // lone spec -> census
		{[]string{"npm:foo", "1", "2", "--help"}, "diff"}, // version pair -> diff
		{[]string{"gha:actions/checkout", "v1", "v2", "-h"}, "gha"},
		{[]string{"--help"}, ""}, // no command -> usage
	}
	for _, tc := range cases {
		if !hasHelpFlag(tc.args) {
			t.Errorf("hasHelpFlag(%v) = false", tc.args)
		}
		got := helpTarget(tc.args)
		var name string
		if len(got) > 0 {
			name = got[0]
		}
		if name != tc.want {
			t.Errorf("helpTarget(%v) = %q, want %q", tc.args, name, tc.want)
		}
	}
	if hasHelpFlag([]string{"transitive", "--old=x"}) {
		t.Error("hasHelpFlag matched a non-help flag")
	}
}

func TestMaterializeAcceptsLabelledLocalCrateEvidence(t *testing.T) {
	dir := t.TempDir()
	oldArtifact := filepath.Join(dir, "old.crate")
	newArtifact := filepath.Join(dir, "new.crate")
	writeTestCrate(t, oldArtifact, "quarantine-test-1.0.0", false)
	writeTestCrate(t, newArtifact, "quarantine-test-1.0.1", true)

	c, err := cache.Open(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	ws := c.WorkspacePath("crates", "quarantine-test", "old-local", "new-local")
	st, err := materialize(c,
		spec.Spec{Eco: spec.Crates, Name: "quarantine-test"},
		"1.0.0", "1.0.1", ws, nil,
		map[string]*fetch.LocalCrateEvidence{"1.0.0": {Path: oldArtifact}, "1.0.1": {Path: newArtifact}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Runnable.BuildRSFrom || !st.Runnable.BuildRSTo {
		t.Fatalf("local evidence lost the introduced build script: %+v", st.Runnable)
	}
}

func TestMaterializeRejectsMislabeledLocalCrateEvidence(t *testing.T) {
	dir := t.TempDir()
	oldArtifact := filepath.Join(dir, "old.crate")
	newArtifact := filepath.Join(dir, "new.crate")
	writeTestCrate(t, oldArtifact, "wrong-name-1.0.0", false)
	writeTestCrate(t, newArtifact, "quarantine-test-1.0.1", false)

	c, err := cache.Open(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = materialize(c,
		spec.Spec{Eco: spec.Crates, Name: "quarantine-test"},
		"1.0.0", "1.0.1", c.WorkspacePath("crates", "quarantine-test", "bad", "new"), nil,
		map[string]*fetch.LocalCrateEvidence{"1.0.0": {Path: oldArtifact}, "1.0.1": {Path: newArtifact}})
	if err == nil {
		t.Fatalf("mislabeled local evidence error = %v", err)
	}
}

func TestMaterializeRejectsLocalCrateManifestIdentityMismatch(t *testing.T) {
	dir := t.TempDir()
	oldArtifact := filepath.Join(dir, "old.crate")
	newArtifact := filepath.Join(dir, "new.crate")
	writeTestCrateNamed(t, oldArtifact, "quarantine-test-1.0.0", "different-crate", "pub fn value() -> u8 { 1 }\n", false)
	writeTestCrate(t, newArtifact, "quarantine-test-1.0.1", false)

	c, err := cache.Open(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = materialize(c,
		spec.Spec{Eco: spec.Crates, Name: "quarantine-test"},
		"1.0.0", "1.0.1", c.WorkspacePath("crates", "quarantine-test", "wrong-manifest", "new"), nil,
		map[string]*fetch.LocalCrateEvidence{"1.0.0": {Path: oldArtifact}, "1.0.1": {Path: newArtifact}})
	if err == nil {
		t.Fatalf("mislabeled manifest error = %v", err)
	}
}

func writeTestCrate(t *testing.T, dest, root string, build bool) {
	t.Helper()
	writeTestCrateNamed(t, dest, root, "quarantine-test", "pub fn value() -> u8 { 1 }\n", build)
}

func writeTestCrateNamed(t *testing.T, dest, root, packageName, source string, build bool) {
	t.Helper()
	f, err := os.Create(dest)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	buildLine := ""
	if build {
		buildLine = "build = \"build.rs\"\n"
	}
	files := [][2]string{
		{root + "/Cargo.toml", `[package]
name = "` + packageName + `"
version = "` + strings.TrimPrefix(root, "quarantine-test-") + `"
edition = "2021"
` + buildLine + `
[lib]
path = "src/lib.rs"
`},
		{root + "/src/lib.rs", source},
	}
	if build {
		files = append(files, [2]string{root + "/build.rs", "fn main() {}\n"})
	}
	for _, file := range files {
		name, body := file[0], file[1]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
