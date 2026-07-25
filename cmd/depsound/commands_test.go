package main

import (
	"testing"

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
