package ghapkg

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, yml string) *Action {
	t.Helper()
	dir := t.TempDir()
	if yml != "" {
		if err := os.WriteFile(filepath.Join(dir, "action.yml"), []byte(yml), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestNodeActionHooks(t *testing.T) {
	a := write(t, `
name: x
runs:
  using: node20
  main: dist/index.js
  pre: dist/setup.js
  post: dist/cleanup.js
`)
	if !a.Found || a.Using != "node20" || a.Pre != "dist/setup.js" || a.Post != "dist/cleanup.js" {
		t.Fatalf("node action parse = %+v", a)
	}
}

func TestCompositeNesting(t *testing.T) {
	a := write(t, `
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
    - run: echo hi
      shell: bash
    - uses: pnpm/action-setup@0ebf47130e4866e96fce0953f49152a61190b271
`)
	if a.Using != "composite" || len(a.Uses) != 2 || a.RunSteps != 1 {
		t.Fatalf("composite parse = %+v", a)
	}
}

func TestDockerImage(t *testing.T) {
	a := write(t, "runs:\n  using: docker\n  image: docker://alpine:3.20\n")
	if a.Using != "docker" || a.Image != "docker://alpine:3.20" {
		t.Fatalf("docker parse = %+v", a)
	}
}

// A NEW post hook runs code around the action: the signal that matters, so
// the delta must surface it as "added".
func TestExecDeltaNewHook(t *testing.T) {
	old := &Action{Using: "node20", Main: "dist/index.js"}
	niu := &Action{Using: "node20", Main: "dist/index.js", Post: "dist/exfil.js"}
	d := ExecDelta(old, niu)
	var sawPost bool
	for _, c := range d {
		if c.Key == "post-hook" && c.Status == "added" && c.To == "dist/exfil.js" {
			sawPost = true
		}
		if c.Key == "using" {
			t.Error("using must be rendered by the header, not the delta")
		}
	}
	if !sawPost {
		t.Errorf("new post hook not surfaced: %+v", d)
	}
}

func TestMissingAndUnparseable(t *testing.T) {
	if a := write(t, ""); a.Found {
		t.Error("missing action.yml should not be Found")
	}
	a := write(t, "runs: [this is: not valid: yaml")
	if len(a.Warnings) == 0 {
		t.Errorf("unparseable action.yml should warn: %+v", a)
	}
}
