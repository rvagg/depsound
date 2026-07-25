package npmpkg

import "testing"

func TestParsePnpmLock(t *testing.T) {
	lock := `
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.0
        version: 4.17.21
packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-abc}
  '@scope/pkg@1.2.3':
    resolution: {integrity: sha512-def}
  react@18.0.0(peer@1.0.0):
    resolution: {integrity: sha512-ghi}
  gitdep@1.0.0:
    resolution: {type: git, repo: x}
`
	deps, nonReg, err := ParsePnpmLock([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range deps {
		got[d.Name] = d.Version
	}
	// scoped name preserved, peer suffix stripped, git dep excluded
	if got["lodash"] != "4.17.21" || got["@scope/pkg"] != "1.2.3" || got["react"] != "18.0.0" {
		t.Errorf("deps = %v", got)
	}
	if _, ok := got["gitdep"]; ok {
		t.Error("git dep should be excluded")
	}
	if nonReg != 1 {
		t.Errorf("nonRegistry = %d, want 1", nonReg)
	}
}

func TestParsePnpmLockOldVersionRejected(t *testing.T) {
	if _, _, err := ParsePnpmLock([]byte("lockfileVersion: '6.0'\npackages: {}\n")); err == nil {
		t.Error("lockfileVersion 6.0 should be rejected")
	}
}

// pnpm states edges outright: importers are the roots, snapshots the edges,
// with peer suffixes collapsed onto the resolved version.
func TestPnpmLockGraph(t *testing.T) {
	lock := `
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      astro:
        specifier: ^5.0.0
        version: 5.16.0(typescript@6.0.3)
    devDependencies:
      local:
        specifier: workspace:*
        version: link:../local
  packages/web:
    dependencies:
      msw:
        specifier: ^2.0.0
        version: 2.12.3
snapshots:
  astro@5.16.0(typescript@6.0.3):
    dependencies:
      svgo: 4.0.0
      cbw-sdk: '@coinbase/wallet-sdk@3.9.3'
    optionalDependencies:
      sharp: 0.34.5
  msw@2.12.3: {}
`
	roots, edges, err := PnpmLockGraph([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	// workspace links carry no version to fetch, so they are not roots
	if len(roots) != 2 || roots[0] != "astro@5.16.0" || roots[1] != "msw@2.12.3" {
		t.Errorf("roots = %v", roots)
	}
	// the peer suffix is stripped from the key, optional deps are edges too,
	// and an alias resolves to the package it really names
	if got := edges["astro@5.16.0"]; len(got) != 3 ||
		got[0] != "@coinbase/wallet-sdk@3.9.3" || got[1] != "sharp@0.34.5" || got[2] != "svgo@4.0.0" {
		t.Errorf("astro edges = %v", got)
	}
}
