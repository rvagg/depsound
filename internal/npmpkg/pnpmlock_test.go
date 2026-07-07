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
