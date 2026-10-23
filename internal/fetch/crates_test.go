package fetch

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type unavailableTransport struct{}

func (unavailableTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("offline")
}

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

func useCratesIndex(t *testing.T, body string) *http.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	old := cratesIndex
	cratesIndex = srv.URL
	t.Cleanup(func() { cratesIndex = old })
	return srv.Client()
}

func importLocalCrate(t *testing.T, client *http.Client, src, dir string) *LocalCrateEvidence {
	t.Helper()
	evidence, err := LocalCrate(t.Context(), client, "example", "1.2.3", src, dir)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func TestLocalCrateFileURLKeepsAbsolutePath(t *testing.T) {
	for _, tc := range []struct {
		path, uri string
	}{
		{"/evidence/archive #1.crate", "file:///evidence/archive%20%231.crate"},
		{"C:/evidence/archive #1.crate", "file:///C:/evidence/archive%20%231.crate"},
		{"//server/share/archive #1.crate", "file:////server/share/archive%20%231.crate"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			if got := localCrateURL(tc.path); got != tc.uri {
				t.Fatalf("file URI = %q, want %q", got, tc.uri)
			}
		})
	}
}

func TestLocalCrateRecordsOriginDigestAndRegistryMatch(t *testing.T) {
	content := []byte("quarantined crate bytes")
	sum := sha256.Sum256(content)
	checksum := hex.EncodeToString(sum[:])
	client := useCratesIndex(t, fmt.Sprintf(`{"vers":"1.2.3","cksum":%q}`+"\n", checksum))

	dir := t.TempDir()
	src := filepath.Join(dir, "source.crate")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}
	evidence := importLocalCrate(t, client, src, filepath.Join(dir, "cache"))
	origin := (&url.URL{Scheme: "file", Path: "/" + strings.TrimPrefix(filepath.ToSlash(src), "/")}).String()
	if evidence.Meta.Verification != VerifyLocalRegistry256 ||
		evidence.Meta.Digest != "sha256-"+checksum || evidence.Meta.URL != origin {
		t.Fatalf("local evidence = %+v", evidence)
	}
	if got, err := os.ReadFile(evidence.Path); err != nil || string(got) != string(content) {
		t.Fatalf("imported bytes = %q, %v", got, err)
	}
}

func TestLocalCrateRejectsRegistryChecksumMismatch(t *testing.T) {
	client := useCratesIndex(t, "{\"vers\":\"1.2.3\",\"cksum\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n")

	dir := t.TempDir()
	src := filepath.Join(dir, "source.crate")
	if err := os.WriteFile(src, []byte("different"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LocalCrate(t.Context(), client, "example", "1.2.3", src, filepath.Join(dir, "cache"))
	if err == nil {
		t.Fatal("checksum mismatch should fail")
	}
}

func TestLocalCrateRecordsUnanchoredDigestWhenVersionIsMissing(t *testing.T) {
	client := useCratesIndex(t, "{\"vers\":\"9.9.9\",\"cksum\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n")

	dir := t.TempDir()
	src := filepath.Join(dir, "withdrawn.crate")
	if err := os.WriteFile(src, []byte("quarantined bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	evidence := importLocalCrate(t, client, src, filepath.Join(dir, "cache"))
	if evidence.Meta.Verification != VerifyLocalSHA256 {
		t.Fatalf("missing-version evidence = %+v", evidence)
	}
}

func TestLocalCrateKeepsConcurrentImportsWithSameRelativeName(t *testing.T) {
	client := useCratesIndex(t, "")
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache")
	sources := []struct {
		path    string
		content []byte
	}{
		{filepath.Join(dir, "left", "input.crate"), []byte("left bytes")},
		{filepath.Join(dir, "right", "input.crate"), []byte("right bytes")},
	}
	for _, source := range sources {
		if err := os.MkdirAll(filepath.Dir(source.path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source.path, source.content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	results := make(chan *LocalCrateEvidence, len(sources))
	errs := make(chan error, len(sources))
	var wg sync.WaitGroup
	for _, source := range sources {
		wg.Add(1)
		go func(source struct {
			path    string
			content []byte
		}) {
			defer wg.Done()
			<-start
			evidence, err := LocalCrate(t.Context(), client, "example", "1.2.3", source.path, cache)
			if err != nil {
				errs <- err
				return
			}
			results <- evidence
		}(source)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	byDigest := make(map[string]*LocalCrateEvidence, len(sources))
	for evidence := range results {
		byDigest[evidence.Meta.Digest] = evidence
	}
	if len(byDigest) != len(sources) {
		t.Fatalf("imports = %d, want %d", len(byDigest), len(sources))
	}
	for _, source := range sources {
		sum := sha256.Sum256(source.content)
		digest := "sha256-" + hex.EncodeToString(sum[:])
		evidence := byDigest[digest]
		if evidence == nil {
			t.Fatalf("missing evidence for %q", source.content)
		}
		if got, err := os.ReadFile(evidence.Path); err != nil || string(got) != string(source.content) {
			t.Fatalf("%s bytes = %q, %v", evidence.Path, got, err)
		}
	}
}

func TestLocalCrateSharesBytesNotOrigin(t *testing.T) {
	client := useCratesIndex(t, "")
	dir := t.TempDir()
	content := []byte("shared archive")
	left := filepath.Join(dir, "left", "input.crate")
	right := filepath.Join(dir, "right", "input.crate")
	for _, src := range []string{left, right} {
		if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(src, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cache := filepath.Join(dir, "cache")
	first := importLocalCrate(t, client, left, cache)
	second := importLocalCrate(t, client, right, cache)
	if first.Path != second.Path {
		t.Fatalf("identical bytes stored at %q and %q", first.Path, second.Path)
	}
	leftOrigin := (&url.URL{Scheme: "file", Path: "/" + strings.TrimPrefix(filepath.ToSlash(left), "/")}).String()
	rightOrigin := (&url.URL{Scheme: "file", Path: "/" + strings.TrimPrefix(filepath.ToSlash(right), "/")}).String()
	if first.Meta.URL != leftOrigin || second.Meta.URL != rightOrigin {
		t.Fatalf("import origins = %q, %q; want %q, %q", first.Meta.URL, second.Meta.URL, leftOrigin, rightOrigin)
	}
	if first.Meta.Digest != second.Meta.Digest {
		t.Fatalf("digests differ: %q and %q", first.Meta.Digest, second.Meta.Digest)
	}
}

func TestLocalCrateRetainsEvidenceAcrossSourceReplacement(t *testing.T) {
	client := useCratesIndex(t, "")
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache")
	src := filepath.Join(dir, "input.crate")
	original := []byte("original archive")
	if err := os.WriteFile(src, original, 0o644); err != nil {
		t.Fatal(err)
	}
	first := importLocalCrate(t, client, src, cache)

	replacement := filepath.Join(dir, "replacement.crate")
	if err := os.WriteFile(replacement, []byte("replacement archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, src); err != nil {
		t.Fatal(err)
	}
	second := importLocalCrate(t, client, src, cache)
	if first.Path == second.Path || first.Meta.Digest == second.Meta.Digest {
		t.Fatalf("replacement reused original evidence: first=%+v second=%+v", first, second)
	}
	if got, err := os.ReadFile(first.Path); err != nil || string(got) != string(original) {
		t.Fatalf("first import changed to %q, %v", got, err)
	}
	wantDigest := fmt.Sprintf("sha256-%x", sha256.Sum256(original))
	wantOrigin := (&url.URL{Scheme: "file", Path: "/" + strings.TrimPrefix(filepath.ToSlash(src), "/")}).String()
	if first.Meta.Digest != wantDigest || first.Meta.URL != wantOrigin {
		t.Fatalf("first metadata changed: %+v", first.Meta)
	}
}

func TestLocalCrateRejectsCorruptDigestPath(t *testing.T) {
	client := useCratesIndex(t, "")
	dir := t.TempDir()
	src := filepath.Join(dir, "input.crate")
	if err := os.WriteFile(src, []byte("trusted archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	evidence := importLocalCrate(t, client, src, filepath.Join(dir, "cache"))
	if err := os.WriteFile(evidence.Path, []byte("corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LocalCrate(t.Context(), client, "example", "1.2.3", src, filepath.Dir(evidence.Path)); err == nil {
		t.Fatal("corrupt digest path should not be trusted")
	}
}

func TestCrateClassifiesVersionMissingFromIndex(t *testing.T) {
	client := useCratesIndex(t, "{\"vers\":\"9.9.9\",\"cksum\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n")

	err := Crate(t.Context(), client, "example", "1.2.3", filepath.Join(t.TempDir(), "example.crate"))
	var unavailable UnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("missing version error = %T %v", err, err)
	}
	failure := unavailable.Unavailable()
	if failure.Kind != Absent || failure.Stage != "registry-index" || failure.Status != http.StatusOK {
		t.Fatalf("classification = %+v", failure)
	}
	if failure.URL == failure.ArtifactURL || failure.ArtifactURL == "" {
		t.Fatalf("observed and intended URLs = %+v", failure)
	}
}

func TestLocalCrateKeepsLookupFailureSeparateFromAbsence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	old := cratesIndex
	cratesIndex = srv.URL
	t.Cleanup(func() { cratesIndex = old })

	dir := t.TempDir()
	src := filepath.Join(dir, "input.crate")
	if err := os.WriteFile(src, []byte("quarantined bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	evidence := importLocalCrate(t, srv.Client(), src, filepath.Join(dir, "cache"))
	checksum := evidence.Meta.RegistryChecksum
	if checksum == nil || checksum.State != "lookup-failed" || checksum.Status != http.StatusServiceUnavailable || checksum.URL != srv.URL+"/ex/am/example" {
		t.Fatalf("checksum observation = %+v", checksum)
	}
	if evidence.Meta.Verification != VerifyLocalSHA256 {
		t.Fatalf("verification = %q", evidence.Meta.Verification)
	}
}

func TestLocalCrateDoesNotTreatMalformedIndexAsAbsent(t *testing.T) {
	client := useCratesIndex(t, "{\"vers\":\"9.9.9\",\"cksum\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n{")

	dir := t.TempDir()
	src := filepath.Join(dir, "input.crate")
	if err := os.WriteFile(src, []byte("quarantined bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	evidence := importLocalCrate(t, client, src, filepath.Join(dir, "cache"))
	checksum := evidence.Meta.RegistryChecksum
	if checksum == nil || checksum.State != "lookup-failed" || checksum.Error == "" {
		t.Fatalf("checksum observation = %+v", checksum)
	}
}

func TestLocalCrateRecordsTransportLookupGap(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "input.crate")
	if err := os.WriteFile(src, []byte("quarantined bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	evidence := importLocalCrate(t, &http.Client{Transport: unavailableTransport{}}, src, filepath.Join(dir, "cache"))
	checksum := evidence.Meta.RegistryChecksum
	if checksum == nil || checksum.State != "lookup-failed" || checksum.Status != 0 || checksum.Error == "" {
		t.Fatalf("checksum observation = %+v", checksum)
	}
}

func TestLocalCrateDoesNotTreatIncompleteIndexAsAbsent(t *testing.T) {
	row := "{\"vers\":\"9.9.9\",\"cksum\":\"" + strings.Repeat("a", 64) + "\"}\n"
	for _, truncated := range []bool{false, true} {
		t.Run(fmt.Sprintf("truncated=%t", truncated), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if truncated {
					w.Header().Set("Content-Length", fmt.Sprint(len(row)+100))
					fmt.Fprint(w, row)
					return
				}
				fmt.Fprint(w, strings.Repeat(row, (16<<20)/len(row)+1))
			}))
			t.Cleanup(srv.Close)
			old := cratesIndex
			cratesIndex = srv.URL
			t.Cleanup(func() { cratesIndex = old })
			dir := t.TempDir()
			src := filepath.Join(dir, "input.crate")
			if err := os.WriteFile(src, []byte("quarantined bytes"), 0o644); err != nil {
				t.Fatal(err)
			}
			evidence := importLocalCrate(t, srv.Client(), src, filepath.Join(dir, "cache"))
			checksum := evidence.Meta.RegistryChecksum
			if checksum == nil || checksum.State != "lookup-failed" || checksum.Status != http.StatusOK {
				t.Fatalf("incomplete index outcome = %+v", checksum)
			}
		})
	}
}
