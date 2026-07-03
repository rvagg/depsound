package fetch

import (
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercises the full artifact lifecycle: fresh fetch with sidecar, cache
// hit verified without a network trip, tamper-triggered refetch, and
// missing-sidecar refetch.
func TestNPMCachePaths(t *testing.T) {
	content := []byte("tarball-bytes")
	sum := sha512.Sum512(content)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])

	tarballHits := 0
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".tgz") {
			tarballHits++
			_, _ = w.Write(content)
			return
		}
		fmt.Fprintf(w, `{"dist":{"tarball":"%s/pkg/-/pkg-1.0.0.tgz","integrity":"%s"}}`, srvURL, integrity)
	}))
	defer srv.Close()
	srvURL = srv.URL

	orig := npmRegistry
	npmRegistry = srv.URL
	defer func() { npmRegistry = orig }()

	ctx := context.Background()
	dest := filepath.Join(t.TempDir(), "pkg-1.0.0.tgz")

	if err := NPM(ctx, srv.Client(), "pkg", "1.0.0", dest); err != nil {
		t.Fatal(err)
	}
	if tarballHits != 1 {
		t.Fatalf("fresh fetch: tarball hits = %d", tarballHits)
	}
	if ReadMeta(dest) == nil {
		t.Fatal("sidecar not written")
	}

	// verified cache hit: no network
	if err := NPM(ctx, srv.Client(), "pkg", "1.0.0", dest); err != nil {
		t.Fatal(err)
	}
	if tarballHits != 1 {
		t.Errorf("cache hit refetched: tarball hits = %d", tarballHits)
	}

	// tampered artifact: refetched and restored
	if err := os.WriteFile(dest, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := NPM(ctx, srv.Client(), "pkg", "1.0.0", dest); err != nil {
		t.Fatal(err)
	}
	if tarballHits != 2 {
		t.Errorf("tampered artifact not refetched: hits = %d", tarballHits)
	}
	if b, _ := os.ReadFile(dest); string(b) != string(content) {
		t.Error("artifact not restored after tamper")
	}

	// missing sidecar: refetched, sidecar restored
	if err := os.Remove(MetaPath(dest)); err != nil {
		t.Fatal(err)
	}
	if err := NPM(ctx, srv.Client(), "pkg", "1.0.0", dest); err != nil {
		t.Fatal(err)
	}
	if tarballHits != 3 {
		t.Errorf("missing sidecar not refetched: hits = %d", tarballHits)
	}
	if ReadMeta(dest) == nil {
		t.Error("sidecar not restored")
	}
}

// A stalled download must fail after stallTimeout; a slow-but-progressing
// one must survive well past any equivalent total deadline.
func TestDownloadStallBehaviour(t *testing.T) {
	origStall := stallTimeout
	stallTimeout = 100 * time.Millisecond
	defer func() { stallTimeout = origStall }()

	content := []byte("0123456789")
	sum := sha512.Sum512(content)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])

	mode := "stall"
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, ".tgz") {
			fmt.Fprintf(w, `{"dist":{"tarball":"%s/p/-/p-1.0.0.tgz","integrity":"%s"}}`, srvURL, integrity)
			return
		}
		fl := w.(http.Flusher)
		switch mode {
		case "stall":
			_, _ = w.Write(content[:5])
			fl.Flush()
			time.Sleep(500 * time.Millisecond) // > stallTimeout, no bytes
			_, _ = w.Write(content[5:])
		case "drip":
			for _, b := range content { // steady progress, 400ms total > stallTimeout
				_, _ = w.Write([]byte{b})
				fl.Flush()
				time.Sleep(40 * time.Millisecond)
			}
		}
	}))
	defer srv.Close()
	srvURL = srv.URL
	orig := npmRegistry
	npmRegistry = srv.URL
	defer func() { npmRegistry = orig }()

	dest := filepath.Join(t.TempDir(), "p.tgz")
	if err := NPM(context.Background(), srv.Client(), "p", "1.0.0", dest); err == nil {
		t.Fatal("stalled download should fail")
	} else if !strings.Contains(err.Error(), "stalled") {
		t.Fatalf("want stall error, got: %v", err)
	}

	mode = "drip"
	if err := NPM(context.Background(), srv.Client(), "p", "1.0.0", dest); err != nil {
		t.Fatalf("progressing download killed: %v", err)
	}
}

func TestVerifyArtifact(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.tgz")
	content := []byte("artifact bytes")
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	s512 := sha512.Sum512(content)
	s1 := sha1.Sum(content)
	d512 := "sha512-" + base64.StdEncoding.EncodeToString(s512[:])
	d1 := "sha1-" + hex.EncodeToString(s1[:])

	if !verifyArtifact(p, d512) {
		t.Error("sha512 digest should verify")
	}
	if !verifyArtifact(p, d1) {
		t.Error("sha1 digest should verify")
	}
	if verifyArtifact(p, "sha512-AAAA") {
		t.Error("wrong sha512 accepted")
	}
	if verifyArtifact(p, "sha1-deadbeef") {
		t.Error("wrong sha1 accepted")
	}

	// tamper: same length, different bytes
	if err := os.WriteFile(p, []byte("artifact bytez"), 0o644); err != nil {
		t.Fatal(err)
	}
	if verifyArtifact(p, d512) {
		t.Error("tampered artifact passed sha512 verification")
	}
}
