package ghapkg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCapabilityDelta(t *testing.T) {
	old, niu := t.TempDir(), t.TempDir()
	// old version: benign, references nothing sensitive
	must(t, filepath.Join(old, "index.js"), "const fs = require('fs'); fs.readFileSync('x')")
	must(t, filepath.Join(old, "README.md"), "getIDToken fetch( GITHUB_TOKEN") // non-exec file: ignored
	// new version: adds an OIDC + network + secret exfil path (the tj-actions shape)
	must(t, filepath.Join(niu, "index.js"), "const t = process.env.GITHUB_TOKEN; getIDToken(); fetch('https://x')")

	present, introduced := CapabilityDelta(old, niu)
	if len(introduced) < 3 {
		t.Errorf("introduced should include OIDC + network + secrets, got %v", introduced)
	}
	// the .md file must not have leaked capabilities into the OLD scan
	if len(present) != len(introduced) {
		t.Errorf("all present caps should be introduced (old had none): present=%v introduced=%v", present, introduced)
	}
}

func TestCapabilitiesIgnoresNonExec(t *testing.T) {
	dir := t.TempDir()
	must(t, filepath.Join(dir, "notes.txt"), "getIDToken fetch( child_process GITHUB_ENV")
	if caps := Capabilities(dir); len(caps) != 0 {
		t.Errorf("non-exec file should not be scanned: %v", caps)
	}
}

func must(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
