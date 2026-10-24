package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/rvagg/depsound/internal/manifest"
)

func TestLockSourceChanges(t *testing.T) {
	for _, tc := range []struct {
		name, kind, old, niu, host, integrity string
	}{
		{"npm mirror", "npm",
			`{"packages":{"node_modules/x":{"version":"1.0.0","resolved":"https://registry.npmjs.org/x.tgz","integrity":"sha512-a"}}}`,
			`{"packages":{"node_modules/x":{"version":"1.0.0","resolved":"https://mirror.invalid/x.tgz","integrity":"sha512-a"}}}`,
			"mirror.invalid", "sha512-a"},
		{"npm path", "npm",
			`{"packages":{"node_modules/x":{"version":"1.0.0","resolved":"https://registry.npmjs.org/old.tgz"}}}`,
			`{"packages":{"node_modules/x":{"version":"1.0.0","resolved":"https://registry.npmjs.org/new.tgz"}}}`,
			"registry.npmjs.org", ""},
		{"npm integrity", "npm",
			`{"packages":{"node_modules/x":{"version":"1.0.0","integrity":"sha512-a"}}}`,
			`{"packages":{"node_modules/x":{"version":"1.0.0","integrity":"sha512-b"}}}`,
			"", "sha512-b"},
		{"pnpm tarball", "pnpm",
			"lockfileVersion: '9.0'\npackages:\n  x@1.0.0:\n    resolution: {integrity: sha512-a}\n",
			"lockfileVersion: '9.0'\npackages:\n  x@1.0.0:\n    resolution: {tarball: 'https://mirror.invalid/x.tgz', integrity: sha512-b}\n",
			"mirror.invalid", "sha512-b"},
		{"Cargo checksum", "crates",
			"[[package]]\nname='x'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='a'\n",
			"[[package]]\nname='x'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='b'\n",
			"github.com", "b"},
		{"Cargo source", "crates",
			"[[package]]\nname='x'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='a'\n",
			"[[package]]\nname='x'\nversion='1.0.0'\nsource='git+https://mirror.invalid/x#abc'\n",
			"mirror.invalid", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			parse := func(name, contents string) []resolvedDep {
				p := filepath.Join(dir, name)
				if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
				d, err := resolveLock(tc.kind, p, "")
				if err != nil {
					t.Fatal(err)
				}
				return d
			}
			old, niu := parse("old", tc.old), parse("new", tc.niu)
			d := diffResolved(old, niu)
			if len(d.lockChanges) != 1 || len(d.changed)+len(d.added)+len(d.removed) != 0 {
				t.Fatalf("same-version source change misclassified: %+v", d)
			}
			c := d.lockChanges[0]
			if c.Name != "x" || c.Version != "1.0.0" || c.To[0].Host != tc.host || c.To[0].Integrity != tc.integrity {
				t.Fatalf("source evidence lost: %+v", c)
			}
			if got := diffResolved(niu, niu); len(got.lockChanges)+len(got.changed)+len(got.added)+len(got.removed) != 0 {
				t.Fatalf("unchanged metadata reported as churn: %+v", got)
			}
			reversed := diffResolved(niu, old)
			if len(reversed.lockChanges) != 1 || !reflect.DeepEqual(reversed.lockChanges[0].To, c.From) {
				t.Fatalf("reverse delta lost original evidence: %+v", reversed)
			}
		})
	}
}

func TestLockSourceDuplicateInstallations(t *testing.T) {
	a := manifest.NewLockSource("node_modules/x", "https://registry.npmjs.org/x.tgz", "sha512-a")
	b := manifest.NewLockSource("node_modules/y/node_modules/x", a.Resolved, a.Integrity)
	changed := manifest.NewLockSource(b.Location, "https://mirror.invalid/x.tgz", "sha512-b")
	old := []resolvedDep{{name: "x", version: "1.0.0", source: &a}, {name: "x", version: "1.0.0", source: &b}}
	niu := []resolvedDep{{name: "x", version: "1.0.0", source: &changed, sourceOnly: true}, {name: "x", version: "1.0.0", source: &a}}
	got := diffResolved(old, niu)
	if len(got.lockChanges) != 1 || len(got.lockChanges[0].From) != 2 || len(got.lockChanges[0].To) != 2 {
		t.Fatalf("duplicate instance collapsed: %+v", got)
	}
	if got.lockChanges[0].To[1] != changed {
		t.Fatalf("changed nested installation lost: %+v", got.lockChanges[0])
	}
	if moved := diffResolved(old, []resolvedDep{{name: "x", version: "1.0.0", source: &b}}); len(moved.lockChanges) != 0 {
		t.Fatalf("identical source deduplication is not a source change: %+v", moved)
	}
	if reordered := diffResolved([]resolvedDep{old[1], old[0]}, []resolvedDep{niu[1], niu[0]}); !reflect.DeepEqual(got.lockChanges, reordered.lockChanges) {
		t.Fatalf("input ordering changed evidence: %+v vs %+v", got, reordered)
	}
}

func TestDetectLockSourceOrigins(t *testing.T) {
	write := func(contents string) string {
		p := filepath.Join(t.TempDir(), "lock")
		if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old := write(`{"packages":{"node_modules/x":{"version":"1.0.0","integrity":"sha512-old"}}}`)
	a := write(`{"packages":{"node_modules/x":{"version":"1.0.0","integrity":"sha512-a"}}}`)
	b := write(`{"packages":{"node_modules/x":{"version":"1.0.0","integrity":"sha512-b"}}}`)
	pairs := []detectPair{
		{path: "b/package-lock.json", old: old, new: b},
		{path: "z/package-lock.json", old: old, new: a},
		{path: "a/package-lock.json", old: old, new: a},
	}
	got := detectChanges(pairs)
	if len(got.Changed)+len(got.Added)+len(got.Unresolved) != 0 || len(got.LockChanges) != 2 {
		t.Fatalf("source-only changes misclassified: %+v", got)
	}
	if !reflect.DeepEqual(got.LockChanges[0].Files, []string{"a/package-lock.json", "z/package-lock.json"}) ||
		got.LockChanges[1].To[0].Integrity != "sha512-b" {
		t.Fatalf("distinct acquisition deltas lost their manifest origins: %+v", got.LockChanges)
	}
	if reversed := detectChanges([]detectPair{pairs[2], pairs[1], pairs[0]}); !reflect.DeepEqual(got.LockChanges, reversed.LockChanges) {
		t.Fatalf("manifest input ordering changed source evidence: %+v", reversed.LockChanges)
	}
}

func TestLockSourceSwappedInstallations(t *testing.T) {
	a := manifest.NewLockSource("node_modules/x", "https://registry.npmjs.org/x.tgz", "sha512-a")
	b := manifest.NewLockSource("node_modules/y/node_modules/x", "https://mirror.invalid/x.tgz", "sha512-b")
	swappedA, swappedB := b, a
	swappedA.Location, swappedB.Location = a.Location, b.Location
	old := []resolvedDep{{name: "x", version: "1.0.0", source: &a}, {name: "x", version: "1.0.0", source: &b, sourceOnly: true}}
	niu := []resolvedDep{{name: "x", version: "1.0.0", source: &swappedA, sourceOnly: true}, {name: "x", version: "1.0.0", source: &swappedB}}
	if got := diffResolved(old, niu); len(got.lockChanges) != 1 {
		t.Fatalf("swapping sources between installed paths must remain visible: %+v", got)
	}
}

func TestLockSourceLinks(t *testing.T) {
	for _, tc := range []struct{ name, old, niu string }{
		{"exact version",
			`{"packages":{"node_modules/x":{"version":"1.0.0","resolved":"https://registry.npmjs.org/x.tgz","integrity":"sha512-old"}}}`,
			`{"packages":{"node_modules/x":{"version":"1.0.0","resolved":"packages/local x","link":true}}}`},
		{"workspace target version",
			`{"packages":{"node_modules/x":{"version":"1.0.0","resolved":"https://registry.npmjs.org/x.tgz"}}}`,
			`{"packages":{"node_modules/x":{"resolved":"packages/local x","link":true},"packages/local x":{"name":"x","version":"1.0.0"}}}`},
		{"activation flag only",
			`{"packages":{"node_modules/x":{"version":"1.0.0","resolved":"file:../local x"}}}`,
			`{"packages":{"node_modules/x":{"version":"1.0.0","resolved":"file:../local x","link":true}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parse := func(name, text string) []resolvedDep {
				p := filepath.Join(t.TempDir(), name)
				if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
				d, err := resolveLock("npm", p, "")
				if err != nil {
					t.Fatal(err)
				}
				return d
			}
			d := diffResolved(parse("old", tc.old), parse("new", tc.niu))
			if len(d.lockChanges) != 1 || len(d.added)+len(d.removed)+len(d.changed) != 0 {
				t.Fatalf("link source change misclassified: %+v", d)
			}
			to := d.lockChanges[0].To[0]
			if !to.Link || to.Host != "" || to.Integrity != "" {
				t.Fatalf("link evidence must retain unknown host/integrity: %+v", to)
			}
		})
	}
}
