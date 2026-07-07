package npmpkg

import "testing"

func TestParsePackageLock(t *testing.T) {
	lock := `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "root", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
	    "node_modules/a/node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"},
	    "node_modules/myalias": {"name": "realpkg", "version": "2.0.0", "resolved": "https://registry.npmjs.org/realpkg/-/realpkg-2.0.0.tgz"},
	    "node_modules/gitdep": {"version": "1.0.0", "resolved": "git+https://github.com/x/y.git#abc"},
	    "node_modules/local": {"link": true, "resolved": "packages/local"},
	    "packages/local": {"version": "0.1.0"}
	  }
	}`
	deps, nonReg, err := ParsePackageLock([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	byNameVer := map[string]bool{}
	for _, d := range deps {
		byNameVer[d.Name+"@"+d.Version] = true
	}
	// two versions of lodash kept (dedup), alias resolves to the real name,
	// git dep + workspace link/member excluded
	for _, want := range []string{"lodash@4.17.21", "lodash@4.17.20", "realpkg@2.0.0"} {
		if !byNameVer[want] {
			t.Errorf("missing %s in %v", want, byNameVer)
		}
	}
	if len(deps) != 3 {
		t.Errorf("deps = %+v, want 3 (2 lodash + realpkg)", deps)
	}
	if nonReg != 1 { // the git dep
		t.Errorf("nonRegistry = %d, want 1", nonReg)
	}
}

func TestParsePackageLockV1Rejected(t *testing.T) {
	if _, _, err := ParsePackageLock([]byte(`{"lockfileVersion":1,"dependencies":{}}`)); err == nil {
		t.Error("v1 (no packages map) should be rejected")
	}
}
