package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestNonCanonicalVersionFactsRemainVisible(t *testing.T) {
	cases := []struct{ kind, path, old, niu string }{
		{"npm", "package-lock.json",
			`{"packages":{"node_modules/x":{"version":"1.0.0","resolved":"https://registry.mirror.example/x-1.tgz"}}}`,
			`{"packages":{"node_modules/x":{"version":"2.0.0","resolved":"https://registry.mirror.example/x 2.tgz#ref"},"node_modules/new":{"version":"1.0.0","resolved":"https://registry.mirror.example/new.tgz"}}}`},
		{"pnpm", "pnpm-lock.yaml",
			"lockfileVersion: '9.0'\npackages:\n  x@1.0.0:\n    resolution: {tarball: 'https://mirror.example/x1.tgz'}\n",
			"lockfileVersion: '9.0'\npackages:\n  x@2.0.0:\n    resolution: {tarball: 'https://mirror.example/x2.tgz'}\n  new@1.0.0:\n    resolution: {tarball: 'https://mirror.example/new.tgz'}\n"},
		{"crates", "Cargo.lock",
			"[[package]]\nname='x'\nversion='1.0.0'\nsource='sparse+https://mirror.example/'\n",
			"[[package]]\nname='x'\nversion='2.0.0'\nsource='sparse+https://mirror.example/'\n[[package]]\nname='new'\nversion='1.0.0'\nsource='sparse+https://mirror.example/'\n"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			write := func(label, contents string) string {
				p := filepath.Join(t.TempDir(), label)
				if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			}
			old, niu := write("old", tc.old), write("new", tc.niu)
			a, err := resolveLock(tc.kind, old, "")
			if err != nil {
				t.Fatal(err)
			}
			b, err := resolveLock(tc.kind, niu, "")
			if err != nil {
				t.Fatal(err)
			}
			d := diffResolved(a, b)
			if len(d.changed) != 1 || len(d.added) != 1 || len(d.removed) != 0 {
				t.Fatalf("noncanonical version facts lost: %+v", d)
			}
			if d.changed[0].Declared == nil || d.changed[0].Declared.FromVersion != "1.0.0" || d.changed[0].Declared.ToVersion != "2.0.0" || d.added[0].Declared == nil {
				t.Fatalf("acquisition evidence lost: %+v", d)
			}
			res := detectChanges([]detectPair{{path: tc.path, old: old, new: niu}})
			if len(res.LockChanges) != 2 || len(res.Unresolved) != 0 {
				t.Fatalf("detect silently dropped acquisitions: %+v", res)
			}
			installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
				t.Errorf("metadata-only acquisition unexpectedly requested %s", req.URL)
				return nil, http.ErrNotSupported
			})
			items := []bulkItem{itemForRef(detectEco(tc.kind).analysis, d.changed[0]), itemForRef(detectEco(tc.kind).analysis, d.added[0])}
			results := runBulk(t.TempDir(), items, false, provenanceFull, 0)
			for _, r := range results {
				if r.LockChange == nil || r.Stats != nil || r.Census != nil || r.Err != "" {
					t.Fatalf("noncanonical acquisition misclassified: %+v", r)
				}
			}
			raw, err := json.Marshal(res.LockChanges[0])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseBulkLines("lock-change " + string(raw)); err != nil {
				t.Fatalf("lossless metadata transport rejected: %v", err)
			}
		})
	}
}

func TestVersionChangeToForeignSourceIsNotRemoval(t *testing.T) {
	old := []resolvedDep{{name: "x", version: "1.0.0"}}
	niu := []resolvedDep{{name: "x", version: "1.0.1", sourceOnly: true}}
	d := diffResolved(old, niu)
	if len(d.changed) != 1 || len(d.removed) != 0 || d.changed[0].Declared == nil {
		t.Fatalf("retargeted version was described as gone: %+v", d)
	}
}

func TestAgainstIncludesNonCanonicalIdentities(t *testing.T) {
	p := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(p, []byte(`{"packages":{"node_modules/x":{"version":"1.0.0","resolved":"https://mirror.example/x.tgz"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parseAgainstTree("npm", p)
	if err != nil {
		t.Fatal(err)
	}
	if !got["x"]["1.0.0"] {
		t.Fatalf("present version treated as absent: %+v", got)
	}
}
