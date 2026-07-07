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
