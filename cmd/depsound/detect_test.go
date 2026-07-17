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

// TestDetectLockfileKinds wires the three lockfiles through detect: the
// authoritative resolution file per ecosystem, parsed by resolveLock. pnpm
// resolves npm packages, so its analysis ecosystem is npm.
func TestDetectLockfileKinds(t *testing.T) {
	write := func(content string) string {
		p := filepath.Join(t.TempDir(), "lock")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	npmLock := func(ver string) string {
		return `{"lockfileVersion":3,"packages":{"":{"name":"root","version":"1.0.0"},` +
			`"node_modules/lodash":{"version":"` + ver + `","resolved":"https://registry.npmjs.org/lodash/-/lodash-` + ver + `.tgz"}}}`
	}
	cargoLock := func(ver string) string {
		return "version = 3\n\n[[package]]\nname = \"aho-corasick\"\nversion = \"" + ver +
			"\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
	}
	pnpmLock := func(ver string) string {
		return "lockfileVersion: '9.0'\npackages:\n  lodash@" + ver + ":\n    resolution: {integrity: sha512-x}\n"
	}

	cases := []struct {
		path, oldC, newC    string
		eco, name, from, to string
	}{
		{"package-lock.json", npmLock("4.17.20"), npmLock("4.17.21"), "npm", "lodash", "4.17.20", "4.17.21"},
		{"Cargo.lock", cargoLock("1.1.2"), cargoLock("1.1.3"), "crates", "aho-corasick", "1.1.2", "1.1.3"},
		{"pnpm-lock.yaml", pnpmLock("4.17.20"), pnpmLock("4.17.21"), "npm", "lodash", "4.17.20", "4.17.21"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			res := detectChanges([]detectPair{{path: c.path, old: write(c.oldC), new: write(c.newC)}})
			if len(res.Changed) != 1 {
				t.Fatalf("want 1 change, got %+v (notes %v)", res.Changed, res.Notes)
			}
			g := res.Changed[0]
			if g.Eco != c.eco || g.Name != c.name || g.From != c.from || g.To != c.to {
				t.Errorf("got %+v, want %s:%s %s->%s", g, c.eco, c.name, c.from, c.to)
			}
		})
	}
}

// TestDetectGoRedirect: a replace added in the new go.mod redirects a module
// off the registry (the trust-laundering vector). An unchanged replace present
// in both versions is not flagged; only what this PR introduces.
func TestDetectGoRedirect(t *testing.T) {
	writeText := func(content string) string {
		p := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const base = "module example.com/m\n\ngo 1.21\n\nrequire github.com/trusted/x v1.2.0\n"
	forked := base + "\nreplace github.com/trusted/x => github.com/attacker/x v1.2.0\n"

	res := detectChanges([]detectPair{{path: "go.mod", old: writeText(base), new: writeText(forked)}})
	if len(res.Redirects) != 1 {
		t.Fatalf("want 1 redirect, got %+v", res.Redirects)
	}
	r := res.Redirects[0]
	if r.Eco != "go" || r.Name != "github.com/trusted/x" || r.Target != "github.com/attacker/x@v1.2.0" {
		t.Errorf("unexpected redirect %+v", r)
	}
	if len(r.Files) != 1 || r.Files[0] != "go.mod" {
		t.Errorf("want provenance [go.mod], got %v", r.Files)
	}

	// a replace present in BOTH versions is not introduced by this PR
	res = detectChanges([]detectPair{{path: "go.mod", old: writeText(forked), new: writeText(forked)}})
	if len(res.Redirects) != 0 {
		t.Errorf("an unchanged replace must not flag: %+v", res.Redirects)
	}

	// a replace to a local path is still a redirect
	local := base + "\nreplace github.com/trusted/x => ../local\n"
	res = detectChanges([]detectPair{{path: "go.mod", old: writeText(base), new: writeText(local)}})
	if len(res.Redirects) != 1 || res.Redirects[0].Target != "../local" {
		t.Errorf("local replace should redirect to ../local, got %+v", res.Redirects)
	}
}

// TestDetectSkipsUnknown: a changed file with no detector is noted, not
// silently dropped, and once per base name.
func TestDetectSkipsUnknown(t *testing.T) {
	res := detectChanges([]detectPair{
		{path: "requirements.txt", old: "-", new: "-"}, // python: no parser
		{path: "sub/requirements.txt", old: "-", new: "-"},
	})
	if len(res.Changed) != 0 || len(res.Added) != 0 {
		t.Fatalf("want nothing detected, got %+v %+v", res.Changed, res.Added)
	}
	if len(res.Notes) != 1 {
		t.Fatalf("want one skip note (deduped by base name), got %v", res.Notes)
	}
}

// TestDetectGHAWorkflow: a workflow's pinned `uses:` refs are its resolved set,
// so a SHA (or tag) bump of an action surfaces as a gha change and an unchanged
// pin does not. Author-agnostic (reads the file, not Dependabot's word) and it
// preserves the SHA the pin-grade analysis needs. Recognised by LOCATION
// (.github/workflows/), not base name.
func TestDetectGHAWorkflow(t *testing.T) {
	write := func(content string) string {
		p := filepath.Join(t.TempDir(), "wf.yml")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// three actions, three ref kinds: a SHA bump, a tag bump, and a comment-only
	// change (same SHA, different # vX) that must NOT trip (the comment is
	// stripped by YAML, so the ref is identical).
	step := func(sha, node, cache string) string {
		return "jobs:\n  b:\n    steps:\n" +
			"      - uses: actions/checkout@" + sha + "\n" +
			"      - uses: actions/setup-node@" + node + "\n" +
			"      - uses: actions/cache@" + cache + "\n"
	}
	old := step("aaaa # v3", "v3", "cccc # v4.0.0")
	niu := step("bbbb # v4", "v4", "cccc # v4.2.0")
	res := detectChanges([]detectPair{{path: ".github/workflows/ci.yml", old: write(old), new: write(niu)}})
	if len(res.Changed) != 2 {
		t.Fatalf("want 2 gha changes (checkout sha bump, setup-node tag bump), got %+v", res.Changed)
	}
	// sorted by name: actions/checkout before actions/setup-node
	if g := res.Changed[0]; g.Eco != "gha" || g.Name != "actions/checkout" || g.From != "aaaa" || g.To != "bbbb" {
		t.Errorf("sha bump: got %+v, want gha:actions/checkout aaaa->bbbb", g)
	}
	if g := res.Changed[1]; g.Eco != "gha" || g.Name != "actions/setup-node" || g.From != "v3" || g.To != "v4" {
		t.Errorf("tag bump: got %+v, want gha:actions/setup-node v3->v4", g)
	}
	if len(res.Added) != 0 || len(res.Unresolved) != 0 {
		t.Errorf("a comment-only change (actions/cache, same SHA) must not surface; added=%+v unresolved=%+v", res.Added, res.Unresolved)
	}
}

// TestDetectUnresolvedOnParseFailure: a manifest detect was asked to parse but
// could not is recorded as Unresolved (a coverage gap the caller surfaces),
// never a benign skip Note and never silently dropped, so an all-failed run
// cannot read as "no changes".
func TestDetectUnresolvedOnParseFailure(t *testing.T) {
	write := func(content string) string {
		p := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const valid = `{"lockfileVersion":3,"packages":{"":{"dependencies":{"left-pad":"^1.3.0"}},` +
		`"node_modules/left-pad":{"version":"1.3.0"}}}`
	res := detectChanges([]detectPair{{path: "package-lock.json", old: write(valid), new: write("{ not json ")}})
	if len(res.Unresolved) != 1 || res.Unresolved[0].Path != "package-lock.json" {
		t.Fatalf("a malformed manifest must be recorded as unresolved with its path, got %+v", res.Unresolved)
	}
	if len(res.Notes) != 0 {
		t.Errorf("a parse failure is a coverage gap, not a benign skip note: %v", res.Notes)
	}
	if len(res.Changed) != 0 || len(res.Added) != 0 {
		t.Errorf("nothing should resolve from a failed parse: %+v %+v", res.Changed, res.Added)
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
