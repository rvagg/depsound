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
  real-alias@npm:realpkg@2.0.0:
    resolution: {integrity: sha512-alias}
  gitdep@1.0.0:
    resolution: {type: git, repo: x}
  mirror@1.0.0:
    resolution: {tarball: https://packages.example.test/mirror-1.0.0.tgz, integrity: sha512-mirror}
  unknown@1.0.0: {}
`
	deps, nonReg, err := ParsePnpmLock([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	byLocation := map[string]LockedDep{}
	for _, d := range deps {
		byLocation[d.Source.Location] = d
	}
	for location, want := range map[string]struct {
		name, version, resolved, integrity, host string
		nonRegistry                              bool
	}{
		"lodash@4.17.21":               {"lodash", "4.17.21", "", "sha512-abc", "", false},
		"@scope/pkg@1.2.3":             {"@scope/pkg", "1.2.3", "", "sha512-def", "", false},
		"react@18.0.0(peer@1.0.0)":     {"react", "18.0.0", "", "sha512-ghi", "", false},
		"real-alias@npm:realpkg@2.0.0": {"realpkg", "2.0.0", "", "sha512-alias", "", false},
		"gitdep@1.0.0":                 {"gitdep", "1.0.0", "", "", "", true},
		"mirror@1.0.0":                 {"mirror", "1.0.0", "https://packages.example.test/mirror-1.0.0.tgz", "sha512-mirror", "packages.example.test", true},
		"unknown@1.0.0":                {"unknown", "1.0.0", "", "", "", false},
	} {
		got, ok := byLocation[location]
		if !ok || got.Name != want.name || got.Version != want.version ||
			got.Source.Resolved != want.resolved || got.Source.Integrity != want.integrity ||
			got.Source.Host != want.host || got.NonRegistry != want.nonRegistry {
			t.Errorf("%s = %+v, want %+v", location, got, want)
		}
	}
	if len(deps) != 7 {
		t.Errorf("deps = %+v, want 7", deps)
	}
	if nonReg != 2 {
		t.Errorf("nonRegistry = %d, want 2", nonReg)
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
	// Workspace links are excluded because they don't specify a registry version.
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
