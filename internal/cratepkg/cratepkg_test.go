package cratepkg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, cargoToml string) *Crate {
	t.Helper()
	dir := t.TempDir()
	if cargoToml != "" {
		if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(cargoToml), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// loadWithBuildRS writes a Cargo.toml AND a root build.rs, for the cases where
// the default/disabled behavior depends on build.rs existing.
func loadWithBuildRS(t *testing.T, cargoToml string) *Crate {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(cargoToml), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "build.rs"), []byte("fn main(){}"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func hasWarning(c *Crate, sub string) bool {
	for _, w := range c.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

// TestBuildScript covers package.build's forms: a custom path is detected (a
// root-build.rs stat would miss it), build = false disables even when build.rs
// ships, the default resolves to build.rs when present, and a path escaping the
// crate is still an execution surface AND is flagged.
func TestBuildScript(t *testing.T) {
	if c := load(t, "[package]\nname = \"x\"\nbuild = \"custom.rs\"\n"); !c.HasBuildRS() || c.BuildScript != "custom.rs" {
		t.Errorf("custom build path: HasBuildRS=%v BuildScript=%q", c.HasBuildRS(), c.BuildScript)
	}
	// an array of build scripts (currently nightly multiple-build-scripts) with
	// no root build.rs must NOT fall through to "none" (a false-negative)
	if c := load(t, "cargo-features = [\"multiple-build-scripts\"]\n[package]\nname = \"x\"\nbuild = [\"a.rs\", \"b.rs\"]\n"); !c.HasBuildRS() || c.BuildScript != "a.rs" {
		t.Errorf("multiple build scripts: HasBuildRS=%v BuildScript=%q", c.HasBuildRS(), c.BuildScript)
	}
	if c := loadWithBuildRS(t, "[package]\nname = \"x\"\nbuild = false\n"); c.HasBuildRS() || c.BuildScript != "" {
		t.Errorf("build = false must disable even with build.rs present: HasBuildRS=%v BuildScript=%q", c.HasBuildRS(), c.BuildScript)
	}
	if c := loadWithBuildRS(t, "[package]\nname = \"x\"\n"); !c.HasBuildRS() || c.BuildScript != "build.rs" {
		t.Errorf("default build.rs: HasBuildRS=%v BuildScript=%q", c.HasBuildRS(), c.BuildScript)
	}
	if c := load(t, "[package]\nname = \"x\"\n"); c.HasBuildRS() {
		t.Errorf("no build key and no build.rs must be absent, got %q", c.BuildScript)
	}
	hostile := load(t, "[package]\nname = \"x\"\nbuild = \"../../evil.rs\"\n")
	if !hostile.HasBuildRS() {
		t.Error("a build script escaping the crate is still an execution surface")
	}
	if !hasWarning(hostile, "outside the crate") {
		t.Errorf("escaping build path should warn: %v", hostile.Warnings)
	}
}

func TestDeltas(t *testing.T) {
	old := load(t, `
[package]
edition = "2021"
rust-version = "1.63"

[features]
default = ["std", "os_rng"]
std = ["alloc"]

[dependencies]
rand_core = "0.9.0"
serde = { version = "1.0.103", optional = true }
`)
	niu := load(t, `
[package]
edition = "2024"
rust-version = "1.85"

[features]
default = ["std"]
std = ["alloc"]

[dependencies]
rand_core = "0.10.0"
serde_core = "1.0.228"
local = { path = "../local" }
`)

	cons := ConstraintsDelta(old, niu)
	byKey := map[string]string{}
	for _, c := range cons {
		byKey[c.Key] = c.Status
	}
	if byKey["edition"] != "changed" || byKey["rust-version (MSRV)"] != "changed" {
		t.Errorf("constraints = %+v", cons)
	}

	feats := FeaturesDelta(old, niu)
	sawDefaultChange := false
	for _, f := range feats {
		if f.Key == "feature.default" && f.Status == "changed" {
			sawDefaultChange = true
		}
	}
	if !sawDefaultChange {
		t.Errorf("default feature change not detected: %+v", feats)
	}

	deps := DepsDelta(old, niu)
	var sawBump, sawPathFlag bool
	for _, d := range deps {
		if d.Name == "rand_core" && d.From == "0.9.0" && d.To == "0.10.0" {
			sawBump = true
		}
		if d.Name == "local" && d.Flag != "" {
			sawPathFlag = true
		}
	}
	if !sawBump || !sawPathFlag {
		t.Errorf("deps = %+v", deps)
	}
}

// crates.io ships `package =` renames (dev-dep serde_lib = package "serde")
// and the value must carry the rename so the delta does not alias.
func TestPackageRename(t *testing.T) {
	c := load(t, `
[dependencies]
serde_lib = { version = "1.0", package = "serde" }
plain = "2.0"
`)
	if c.Deps["serde_lib"] != "1.0 package=serde" {
		t.Errorf("rename not rendered: %q", c.Deps["serde_lib"])
	}
	if c.Deps["plain"] != "2.0" {
		t.Errorf("plain dep = %q", c.Deps["plain"])
	}
}

// A [dependencies] alias (import name != real package) is the published
// redirect vector and must be flagged; a dev-dep alias is benign and not.
func TestPackageAliasFlagged(t *testing.T) {
	old := load(t, "[dependencies]\nfoo = \"1.0\"\n")
	niu := load(t, `
[dependencies]
foo = { version = "1.0", package = "evil-fork" }
[dev-dependencies]
serde_lib = { version = "1.0", package = "serde" }
`)
	var fooFlag, sawDev bool
	for _, d := range DepsDelta(old, niu) {
		if d.Name == "foo" && d.Section == "dependencies" && strings.Contains(d.Flag, "aliased") {
			fooFlag = true
		}
		if d.Section == "dev-dependencies" && d.Flag != "" {
			sawDev = true
		}
	}
	if !fooFlag {
		t.Error("[dependencies] alias to a different package not flagged")
	}
	if sawDev {
		t.Error("dev-dependency alias should not be flagged (benign)")
	}
}

func TestProcMacroAndBuildRS(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"),
		[]byte("[lib]\nproc-macro = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "build.rs"), []byte("fn main(){}"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !c.ProcMacro || !c.HasBuildRS() {
		t.Errorf("proc-macro=%v build.rs=%v", c.ProcMacro, c.HasBuildRS())
	}
}

func TestForgiving(t *testing.T) {
	// a crate must ship Cargo.toml, so a missing one degrades to empty
	// BUT warns (anomalous), unlike Go's optional go.mod
	c0 := load(t, "")
	if c0.Edition != "" || len(c0.Warnings) != 1 || !strings.Contains(c0.Warnings[0], "anomalous") {
		t.Errorf("missing manifest = %+v", c0)
	}
	// unparseable degrades to a warning
	c := load(t, "this is not = = toml [[[")
	if len(c.Warnings) != 1 {
		t.Errorf("unparseable warnings = %v", c.Warnings)
	}
	// workspace-inherited edition ({workspace=true}) must not crash
	c = load(t, "[package]\nedition = { workspace = true }\n")
	if c.Edition != "" {
		t.Errorf("workspace edition = %q, want empty", c.Edition)
	}
}
