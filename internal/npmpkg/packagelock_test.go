package npmpkg

import "testing"

func TestParsePackageLock(t *testing.T) {
	lock := `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "root", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "integrity": "sha512-new"},
	    "node_modules/a/node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz", "integrity": "sha512-old"},
	    "node_modules/b/node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "integrity": "sha512-copy"},
	    "node_modules/myalias": {"name": "realpkg", "version": "2.0.0", "resolved": "https://registry.npmjs.org/realpkg/-/realpkg-2.0.0.tgz"},
	    "node_modules/gitdep": {"version": "1.0.0", "resolved": "git+https://github.com/x/y.git#abc"},
	    "node_modules/mirror": {"version": "1.0.0", "resolved": "https://packages.example.test/mirror/-/mirror-1.0.0.tgz", "integrity": "sha512-mirror"},
	    "node_modules/unknown": {"version": "1.0.0"},
	    "node_modules/local": {"link": true, "resolved": "packages/local"},
	    "packages/local": {"version": "0.1.0"}
	  }
	}`
	deps, nonReg, err := ParsePackageLock([]byte(lock))
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
		"node_modules/lodash":                {"lodash", "4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "sha512-new", "registry.npmjs.org", false},
		"node_modules/a/node_modules/lodash": {"lodash", "4.17.20", "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz", "sha512-old", "registry.npmjs.org", false},
		"node_modules/b/node_modules/lodash": {"lodash", "4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "sha512-copy", "registry.npmjs.org", false},
		"node_modules/myalias":               {"realpkg", "2.0.0", "https://registry.npmjs.org/realpkg/-/realpkg-2.0.0.tgz", "", "registry.npmjs.org", false},
		"node_modules/gitdep":                {"gitdep", "1.0.0", "git+https://github.com/x/y.git#abc", "", "github.com", true},
		"node_modules/mirror":                {"mirror", "1.0.0", "https://packages.example.test/mirror/-/mirror-1.0.0.tgz", "sha512-mirror", "packages.example.test", true},
		"node_modules/unknown":               {"unknown", "1.0.0", "", "", "", false},
		"node_modules/local":                 {"local", "0.1.0", "packages/local", "", "", true},
	} {
		got, ok := byLocation[location]
		if !ok || got.Name != want.name || got.Version != want.version ||
			got.Source.Resolved != want.resolved || got.Source.Integrity != want.integrity ||
			got.Source.Host != want.host || got.NonRegistry != want.nonRegistry {
			t.Errorf("%s = %+v, want %+v", location, got, want)
		}
	}
	if got := byLocation["node_modules/local"]; !got.Source.Link {
		t.Fatalf("link activation metadata lost: %+v", got)
	}
	if len(deps) != 8 {
		t.Errorf("deps = %+v, want 8", deps)
	}
	if nonReg != 3 {
		t.Errorf("nonRegistry = %d, want 3", nonReg)
	}
}

func TestParsePackageLockV1Rejected(t *testing.T) {
	if _, _, err := ParsePackageLock([]byte(`{"lockfileVersion":1,"dependencies":{}}`)); err == nil {
		t.Error("v1 (no packages map) should be rejected")
	}
}

// The root's devDependencies DO install (your own tooling), so they are roots
// of the graph. Missing them left a dev-dep bump, the commonest Dependabot PR
// there is, with no root at all.
func TestPackageLockGraphRootDevDeps(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{
		"": {"dependencies":{"runtime":"^1"},"devDependencies":{"typescript":"^7"}},
		"node_modules/runtime": {"version":"1.0.0"},
		"node_modules/typescript": {"version":"7.0.2","optionalDependencies":{"@ts/linux-x64":"7.0.2"}},
		"node_modules/@ts/linux-x64": {"version":"7.0.2"},
		"node_modules/typescript/node_modules/inner": {"version":"2.0.0","devDependencies":{"never":"^1"}},
		"node_modules/never": {"version":"9.9.9"}}}`
	roots, edges, err := PackageLockGraph([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 2 || roots[0] != "runtime@1.0.0" || roots[1] != "typescript@7.0.2" {
		t.Errorf("roots = %v", roots)
	}
	// optional deps of a package are edges; a transitive package's dev deps
	// never install, so they are not
	if got := edges["typescript@7.0.2"]; len(got) != 1 || got[0] != "@ts/linux-x64@7.0.2" {
		t.Errorf("typescript edges = %v", got)
	}
	if got := edges["inner@2.0.0"]; len(got) != 0 {
		t.Errorf("transitive dev dependencies added unexpected graph edges: %v", got)
	}
}
