package extract

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type entry struct {
	name     string
	typ      byte
	content  string
	linkname string
}

func makeTarGz(t *testing.T, entries []entry) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644, Linkname: e.linkname}
		if e.typ == tar.TypeReg {
			hdr.Size = int64(len(e.content))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "test.tgz")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPrefixStripped(t *testing.T) {
	src := makeTarGz(t, []entry{
		{name: "package/index.js", typ: tar.TypeReg, content: "x"},
		{name: "package/lib/a.js", typ: tar.TypeReg, content: "y"},
	})
	dest := t.TempDir()
	rep, err := TarGz(src, dest, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Prefix != "package" {
		t.Errorf("prefix = %q", rep.Prefix)
	}
	for _, want := range []string{"index.js", "lib/a.js"} {
		if _, err := os.Stat(filepath.Join(dest, want)); err != nil {
			t.Errorf("missing %s: %v", want, err)
		}
	}
}

func TestNoCommonPrefix(t *testing.T) {
	src := makeTarGz(t, []entry{
		{name: "a/x.js", typ: tar.TypeReg, content: "x"},
		{name: "b/y.js", typ: tar.TypeReg, content: "y"},
	})
	dest := t.TempDir()
	rep, err := TarGz(src, dest, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Prefix != "" {
		t.Errorf("prefix = %q, want none", rep.Prefix)
	}
	if _, err := os.Stat(filepath.Join(dest, "a/x.js")); err != nil {
		t.Error(err)
	}
}

func TestHostileNamesSkippedAndRecorded(t *testing.T) {
	// NUL is untestable: the tar encoder itself refuses it; the control-byte
	// check covers it defensively anyway
	hostile := []string{
		"../evil", "package/../../evil", "/abs/evil",
		"package/esc\x1b]0;pwn\x07.js",
		"..\\evil", "C:\\evil", "c:evil", "\\\\unc\\share\\evil",
	}
	for _, name := range hostile {
		src := makeTarGz(t, []entry{
			{name: "package/ok.js", typ: tar.TypeReg, content: "fine"},
			{name: name, typ: tar.TypeReg, content: "evil"},
		})
		dest := t.TempDir()
		rep, err := TarGz(src, dest, DefaultLimits)
		if err != nil {
			t.Fatalf("entry %q: extraction aborted, want skip-and-record: %v", name, err)
		}
		if len(rep.HostileEntries) != 1 {
			t.Errorf("entry %q: HostileEntries = %v", name, rep.HostileEntries)
		}
		if rep.Files != 1 {
			t.Errorf("entry %q: benign file not extracted (Files=%d)", name, rep.Files)
		}
		var found []string
		_ = filepath.WalkDir(dest, func(p string, d os.DirEntry, _ error) error {
			if d != nil && d.Type().IsRegular() {
				found = append(found, p)
			}
			return nil
		})
		if len(found) != 1 || !strings.HasSuffix(found[0], "ok.js") {
			t.Errorf("entry %q: unexpected files on disk: %v", name, found)
		}
	}
}

func TestLinksSkipped(t *testing.T) {
	src := makeTarGz(t, []entry{
		{name: "package/ok.js", typ: tar.TypeReg, content: "x"},
		{name: "package/evil", typ: tar.TypeSymlink, linkname: "/etc/passwd"},
		{name: "package/evil2", typ: tar.TypeLink, linkname: "../../x"},
	})
	dest := t.TempDir()
	rep, err := TarGz(src, dest, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.SkippedLinks) != 2 {
		t.Errorf("SkippedLinks = %v", rep.SkippedLinks)
	}
	for _, bad := range []string{"evil", "evil2"} {
		if _, err := os.Lstat(filepath.Join(dest, bad)); !os.IsNotExist(err) {
			t.Errorf("%s was created", bad)
		}
	}
}

func TestBombLimits(t *testing.T) {
	big := strings.Repeat("A", 1000)
	src := makeTarGz(t, []entry{{name: "package/big", typ: tar.TypeReg, content: big}})

	lim := DefaultLimits
	lim.MaxFileBytes = 100
	if _, err := TarGz(src, t.TempDir(), lim); err == nil {
		t.Error("MaxFileBytes not enforced")
	}

	lim = DefaultLimits
	lim.MaxTotalBytes = 100
	if _, err := TarGz(src, t.TempDir(), lim); err == nil {
		t.Error("MaxTotalBytes not enforced")
	}

	lim = DefaultLimits
	lim.MaxFiles = 0
	if _, err := TarGz(src, t.TempDir(), lim); err == nil {
		t.Error("MaxFiles not enforced")
	}
}
