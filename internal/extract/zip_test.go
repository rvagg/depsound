package extract

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func makeZip(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "test.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const modPrefix = "github.com/x/y@v1.0.0"

func TestZipPrefixEnforced(t *testing.T) {
	src := makeZip(t, map[string]string{
		modPrefix + "/go.mod":    "module github.com/x/y\n",
		modPrefix + "/a/b.go":    "package a\n",
		"github.com/evil/z@v1/x": "outside declared root",
		"stray.txt":              "no prefix at all",
	})
	dest := t.TempDir()
	rep, err := Zip(src, dest, modPrefix, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 2 {
		t.Errorf("Files = %d", rep.Files)
	}
	if len(rep.HostileEntries) != 2 {
		t.Errorf("HostileEntries = %v", rep.HostileEntries)
	}
	if _, err := os.Stat(filepath.Join(dest, "a/b.go")); err != nil {
		t.Errorf("prefixed file not extracted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "stray.txt")); !os.IsNotExist(err) {
		t.Error("out-of-prefix file was extracted")
	}
}

func TestZipHostileNames(t *testing.T) {
	src := makeZip(t, map[string]string{
		modPrefix + "/ok.go":      "package ok\n",
		modPrefix + "/../../evil": "traversal",
		modPrefix + "/esc\x1b.go": "control byte",
	})
	rep, err := Zip(src, t.TempDir(), modPrefix, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 1 || len(rep.HostileEntries) != 2 {
		t.Errorf("Files=%d Hostile=%v", rep.Files, rep.HostileEntries)
	}
}

// The go toolchain rejects duplicate and case-colliding zip entries, so
// depsound must not silently materialize a tree the ecosystem would never
// install: first occurrence wins, collision recorded hostile.
func TestZipDuplicateAndCaseCollision(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range []struct{ name, content string }{
		{modPrefix + "/a.go", "first"},
		{modPrefix + "/a.go", "duplicate"},
		{modPrefix + "/A.GO", "case collision"},
		{modPrefix + "/ok.go", "fine"},
	} {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "dup.zip")
	if err := os.WriteFile(src, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	rep, err := Zip(src, dest, modPrefix, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 2 || len(rep.HostileEntries) != 2 {
		t.Errorf("Files=%d Hostile=%v", rep.Files, rep.HostileEntries)
	}
	b, err := os.ReadFile(filepath.Join(dest, "a.go"))
	if err != nil || string(b) != "first" {
		t.Errorf("first occurrence should win: %q %v", b, err)
	}
}

func TestZipBombLimits(t *testing.T) {
	big := string(bytes.Repeat([]byte("A"), 1000))
	src := makeZip(t, map[string]string{modPrefix + "/big": big})

	lim := DefaultLimits
	lim.MaxFileBytes = 100
	if _, err := Zip(src, t.TempDir(), modPrefix, lim); err == nil {
		t.Error("MaxFileBytes not enforced")
	}
	lim = DefaultLimits
	lim.MaxTotalBytes = 100
	if _, err := Zip(src, t.TempDir(), modPrefix, lim); err == nil {
		t.Error("MaxTotalBytes not enforced")
	}
}
