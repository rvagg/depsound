package fetch

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestIndexPath(t *testing.T) {
	cases := map[string]string{
		"a":        "1/a",
		"bc":       "2/bc",
		"def":      "3/d/def",
		"serde":    "se/rd/serde",
		"bitflags": "bi/tf/bitflags",
	}
	for name, want := range cases {
		if got := indexPath(name); got != want {
			t.Errorf("indexPath(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestLocalCrateRecordsOriginDigestAndRegistryMatch(t *testing.T) {
	content := []byte("quarantined crate bytes")
	sum := sha256.Sum256(content)
	checksum := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"vers":"1.2.3","cksum":%q}`+"\n", checksum)
	}))
	defer srv.Close()
	old := cratesIndex
	cratesIndex = srv.URL
	defer func() { cratesIndex = old }()

	dir := t.TempDir()
	src := filepath.Join(dir, "source.crate")
	dest := filepath.Join(dir, "cache", "imported.crate")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := LocalCrate(t.Context(), srv.Client(), "example", "1.2.3", src, dest); err != nil {
		t.Fatal(err)
	}
	meta := ReadMeta(dest)
	if meta == nil || meta.Verification != VerifyLocalRegistry256 ||
		meta.Digest != "sha256-"+checksum || meta.URL == "" {
		t.Fatalf("local metadata = %+v", meta)
	}
	if got, err := os.ReadFile(dest); err != nil || string(got) != string(content) {
		t.Fatalf("imported bytes = %q, %v", got, err)
	}
}

func TestLocalCrateRejectsRegistryChecksumMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, `{"vers":"1.2.3","cksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	}))
	defer srv.Close()
	old := cratesIndex
	cratesIndex = srv.URL
	defer func() { cratesIndex = old }()

	dir := t.TempDir()
	src := filepath.Join(dir, "source.crate")
	if err := os.WriteFile(src, []byte("different"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := LocalCrate(t.Context(), srv.Client(), "example", "1.2.3", src, filepath.Join(dir, "dest.crate"))
	if err == nil {
		t.Fatal("checksum mismatch should fail")
	}
}

func TestLocalCrateRecordsUnanchoredDigestWhenVersionIsMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, `{"vers":"9.9.9","cksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	}))
	defer srv.Close()
	old := cratesIndex
	cratesIndex = srv.URL
	defer func() { cratesIndex = old }()

	dir := t.TempDir()
	src := filepath.Join(dir, "withdrawn.crate")
	if err := os.WriteFile(src, []byte("quarantined bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "cache", "withdrawn.crate")
	if err := LocalCrate(t.Context(), srv.Client(), "example", "1.2.3", src, dest); err != nil {
		t.Fatal(err)
	}
	if meta := ReadMeta(dest); meta == nil || meta.Verification != VerifyLocalSHA256 {
		t.Fatalf("missing-version metadata = %+v", meta)
	}
}

func TestCrateClassifiesVersionMissingFromIndex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, `{"vers":"9.9.9","cksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	}))
	defer srv.Close()
	old := cratesIndex
	cratesIndex = srv.URL
	defer func() { cratesIndex = old }()

	err := Crate(t.Context(), srv.Client(), "example", "1.2.3", filepath.Join(t.TempDir(), "example.crate"))
	unavailable, ok := err.(UnavailableError)
	if !ok {
		t.Fatalf("missing version error = %T %v", err, err)
	}
	kind, status, _, _ := unavailable.Unavailable()
	if kind != Absent || status != 0 {
		t.Fatalf("classification = %q HTTP %d", kind, status)
	}
}
