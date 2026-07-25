package cratepkg

import "testing"

func TestParseCargoLock(t *testing.T) {
	lock := `
version = 3

[[package]]
name = "ripgrep"
version = "14.1.1"

[[package]]
name = "aho-corasick"
version = "1.1.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "localdep"
version = "0.1.0"
source = "git+https://github.com/x/y"
`
	reg, nonReg, err := ParseCargoLock([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	// only aho-corasick is registry-sourced; ripgrep (workspace, no source)
	// and localdep (git) are non-registry and not analysable
	if len(reg) != 1 || reg[0].Name != "aho-corasick" || reg[0].Version != "1.1.3" {
		t.Errorf("registry crates = %+v", reg)
	}
	if nonReg != 2 {
		t.Errorf("non-registry count = %d, want 2", nonReg)
	}
}

// Cargo.lock states edges per package; roots are the sourceless entries (the
// workspace members being built).
func TestCargoLockGraph(t *testing.T) {
	lock := `
[[package]]
name = "myapp"
version = "0.1.0"
dependencies = ["regex", "serde 1.0.0"]

[[package]]
name = "regex"
version = "1.12.4"
source = "registry+x"
dependencies = ["aho-corasick"]

[[package]]
name = "aho-corasick"
version = "1.1.3"
source = "registry+x"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+x"

[[package]]
name = "serde"
version = "2.0.0"
source = "registry+x"
`
	roots, edges, err := CargoLockGraph([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 || roots[0] != "myapp@0.1.0" {
		t.Errorf("roots = %v", roots)
	}
	// a bare name resolves to the one locked version; an explicit version wins
	// where a name is locked twice
	if got := edges["myapp@0.1.0"]; len(got) != 2 || got[0] != "regex@1.12.4" || got[1] != "serde@1.0.0" {
		t.Errorf("root edges = %v", got)
	}
	if got := edges["regex@1.12.4"]; len(got) != 1 || got[0] != "aho-corasick@1.1.3" {
		t.Errorf("regex edges = %v", got)
	}
}
