package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rvagg/depsound/internal/cache"
	"github.com/rvagg/depsound/internal/extract"
	"github.com/rvagg/depsound/internal/fetch"
	"github.com/rvagg/depsound/internal/spec"
)

func TestLocalArtifactDiffKeepsSnapshotDuringConcurrentCensus(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "evidence.crate")
	target := filepath.Join(dir, "target.crate")
	const original = "pub fn value() -> u8 { 1 }\n"
	const replacement = "pub fn value() -> u8 { 2 }\n"
	writeTestCrateNamed(t, src, "quarantine-test-1.0.0", "quarantine-test", original, false)
	writeTestCrate(t, target, "quarantine-test-1.0.1", true)
	originalArchive := readArtifactTestFile(t, src)
	targetArchive := readArtifactTestFile(t, target)
	targetChecksum := fmt.Sprintf("%x", sha256.Sum256(targetArchive))
	downloadStarted, allowDownload := make(chan struct{}), make(chan struct{})
	var started, released sync.Once
	release := func() { released.Do(func() { close(allowDownload) }) }
	defer release()

	installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "index.crates.io":
			body := fmt.Sprintf("{\"vers\":\"1.0.1\",\"cksum\":%q}\n", targetChecksum)
			return artifactTestResponse(req, []byte(body)), nil
		case "static.crates.io":
			started.Do(func() { close(downloadStarted) })
			select {
			case <-allowDownload:
				return artifactTestResponse(req, targetArchive), nil
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		default:
			return nil, fmt.Errorf("unexpected request: %s", req.URL)
		}
	})
	cacheDir := filepath.Join(dir, "cache")
	type result struct {
		r   *resolved
		err error
	}
	results, finished := make(chan result, 1), make(chan struct{})
	go func() {
		defer close(finished)
		r, err := analyzeWithArtifacts(cacheDir, "crates:quarantine-test", "1.0.0", "1.0.1", 0, artifactInputs{from: src})
		results <- result{r, err}
	}()
	t.Cleanup(func() {
		release()
		<-finished
	})
	select {
	case <-downloadStarted:
	case got := <-results:
		t.Fatalf("analysis stopped before the interleaving point: %v", got.err)
	}

	writeTestCrateNamed(t, src, "quarantine-test-1.0.0", "quarantine-test", replacement, false)
	replacementArchive := readArtifactTestFile(t, src)
	census, err := buildCensusWithArtifact(cacheDir, "crates:quarantine-test", "1.0.0", 0, src)
	if err != nil {
		t.Fatal(err)
	}
	assertArtifactTreeSource(t, census.Tree, replacement)
	if want := fmt.Sprintf("sha256-%x", sha256.Sum256(replacementArchive)); census.Source.Digest != want {
		t.Fatalf("replacement census digest = %q, want %q", census.Source.Digest, want)
	}
	release()
	got := <-results
	if got.err != nil {
		t.Fatal(got.err)
	}
	assertArtifactTreeSource(t, filepath.Join(got.r.ws, "old"), original)
	wantDigest := fmt.Sprintf("sha256-%x", sha256.Sum256(originalArchive))
	if got.r.st.Artifact.SourceFrom.Digest != wantDigest {
		t.Fatalf("diff source digest = %q, want %q", got.r.st.Artifact.SourceFrom.Digest, wantDigest)
	}
	if err := os.WriteFile(src, originalArchive, 0o600); err != nil {
		t.Fatal(err)
	}
	cached, err := analyzeWithArtifacts(cacheDir, "crates:quarantine-test", "1.0.0", "1.0.1", 0, artifactInputs{from: src})
	if err != nil {
		t.Fatal(err)
	}
	assertArtifactTreeSource(t, filepath.Join(cached.ws, "old"), original)
	if cached.ws != got.r.ws || cached.st.Artifact.SourceFrom.Digest != wantDigest {
		t.Fatalf("cached diff did not retain the original evidence: %+v", cached.st.Artifact)
	}
}

func TestLocalArtifactsIgnoreLegacyUnboundTrees(t *testing.T) {
	dir := t.TempDir()
	fromPath, toPath := filepath.Join(dir, "old.crate"), filepath.Join(dir, "new.crate")
	const original = "pub fn value() -> u8 { 1 }\n"
	const corrupt = "pub fn value() -> u8 { 99 }\n"
	writeTestCrate(t, fromPath, "quarantine-test-1.0.0", false)
	writeTestCrate(t, toPath, "quarantine-test-1.0.1", true)
	installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "index.crates.io" {
			return nil, fmt.Errorf("unexpected request: %s", req.URL)
		}
		return artifactTestResponse(req, nil), nil
	})
	c, err := cache.Open(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	from, err := fetch.LocalCrate(t.Context(), &http.Client{}, "quarantine-test", "1.0.0", fromPath, c.LocalCrateDir())
	if err != nil {
		t.Fatal(err)
	}
	to, err := fetch.LocalCrate(t.Context(), &http.Client{}, "quarantine-test", "1.0.1", toPath, c.LocalCrateDir())
	if err != nil {
		t.Fatal(err)
	}
	legacyKey := func(version_ string, meta fetch.Meta) string {
		return version_ + "@" + meta.Digest + "@" + meta.URL + "@crate-label-v1"
	}
	fromKey, toKey := legacyKey("1.0.0", from.Meta), legacyKey("1.0.1", to.Meta)
	legacyWorkspace := c.WorkspacePath("crates", "quarantine-test", fromKey, toKey)
	_, err = materialize(c, spec.Spec{Eco: spec.Crates, Name: "quarantine-test"}, "1.0.0", "1.0.1",
		legacyWorkspace, nil, map[string]*fetch.LocalCrateEvidence{"1.0.0": from, "1.0.1": to})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyWorkspace, "old", "src", "lib.rs"), []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	legacyTree := c.CensusPath("crates", "quarantine-test", fromKey)
	if err := os.MkdirAll(filepath.Join(legacyTree, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := readArtifactTestFile(t, filepath.Join(legacyWorkspace, "old", "Cargo.toml"))
	for path, body := range map[string][]byte{"Cargo.toml": manifest, filepath.Join("src", "lib.rs"): []byte(corrupt)} {
		if err := os.WriteFile(filepath.Join(legacyTree, path), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeExtractReport(legacyTree+".extract.json", &extract.Report{Prefix: "quarantine-test-1.0.0"}); err != nil {
		t.Fatal(err)
	}

	r, err := analyzeWithArtifacts(c.Root, "crates:quarantine-test", "1.0.0", "1.0.1", 0, artifactInputs{from: fromPath, to: toPath})
	if err != nil {
		t.Fatal(err)
	}
	assertArtifactTreeSource(t, filepath.Join(r.ws, "old"), original)
	census, err := buildCensusWithArtifact(c.Root, "crates:quarantine-test", "1.0.0", 0, fromPath)
	if err != nil {
		t.Fatal(err)
	}
	assertArtifactTreeSource(t, census.Tree, original)
	assertArtifactTreeSource(t, filepath.Join(legacyWorkspace, "old"), corrupt)
	assertArtifactTreeSource(t, legacyTree, corrupt)
}

type artifactTestTransport func(*http.Request) (*http.Response, error)

func (f artifactTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func installArtifactTestTransport(t *testing.T, f artifactTestTransport) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = f
	t.Cleanup(func() { http.DefaultTransport = previous })
}

func artifactTestResponse(req *http.Request, body []byte) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

func readArtifactTestFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func assertArtifactTreeSource(t *testing.T, tree, want string) {
	t.Helper()
	if got := string(readArtifactTestFile(t, filepath.Join(tree, "src", "lib.rs"))); got != want {
		t.Fatalf("%s source = %q, want %q", tree, got, want)
	}
}
