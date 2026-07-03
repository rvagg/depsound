package fetch

import (
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// npmRegistry is a var so tests can point it at a local server.
var npmRegistry = "https://registry.npmjs.org"

// metaTimeout is a total deadline for small metadata requests.
const metaTimeout = 30 * time.Second

// stallTimeout governs downloads: there is NO total deadline, so a slow
// link pulling a big artifact is never killed while bytes keep arriving;
// the download fails only when nothing arrives for this long. Var so
// tests can shorten it.
var stallTimeout = 30 * time.Second

const userAgent = "depvet/0.1 (+https://github.com/rvagg/depvet)"

// NPM fetches name@version into dest. The version metadata document
// supplies the canonical tarball URL and integrity, which is verified
// before the artifact enters the cache. Existing dest is a cache hit:
// registry artifacts are immutable.
func NPM(ctx context.Context, client *http.Client, name, version, dest string) error {
	// a cache hit is rehashed against its sidecar digest: immutability is
	// enforced, not assumed; mismatch or missing sidecar falls through to
	// a fresh, fully verified download that replaces the entry
	if _, err := os.Stat(dest); err == nil {
		if m := ReadMeta(dest); m != nil && verifyArtifact(dest, m.Digest) {
			return nil
		}
	}
	metaURL := npmRegistry + "/" + url.PathEscape(name) + "/" + url.PathEscape(version)
	var meta struct {
		Dist struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
			Shasum    string `json:"shasum"`
		} `json:"dist"`
	}
	if err := getJSON(ctx, client, metaURL, &meta); err != nil {
		if strings.Contains(err.Error(), "404") {
			return fmt.Errorf("npm:%s@%s metadata: %w (package name or version not found on the registry; check spelling)", name, version, err)
		}
		return fmt.Errorf("npm:%s@%s metadata: %w", name, version, err)
	}
	if meta.Dist.Tarball == "" {
		return fmt.Errorf("npm:%s@%s: metadata has no tarball URL", name, version)
	}
	if err := download(ctx, client, meta.Dist.Tarball, dest, meta.Dist.Integrity, meta.Dist.Shasum); err != nil {
		return fmt.Errorf("npm:%s@%s: %w", name, version, err)
	}
	digest := meta.Dist.Integrity
	if digest == "" {
		digest = "sha1-" + meta.Dist.Shasum
	}
	return writeMeta(dest, Meta{URL: meta.Dist.Tarball, Digest: digest})
}

// Meta is the provenance sidecar stored beside each cached artifact so
// reports remain traceable to exact inputs.
type Meta struct {
	URL    string `json:"url"`
	Digest string `json:"digest"`
}

func MetaPath(artifactPath string) string { return artifactPath + ".meta.json" }

// writeMeta is atomic (temp + rename) so concurrent fetchers of the same
// artifact can never interleave into a corrupt sidecar.
func writeMeta(artifactPath string, m Meta) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	dir := filepath.Dir(artifactPath)
	tmp, err := os.CreateTemp(dir, ".meta-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), MetaPath(artifactPath))
}

type stallReader struct {
	r        io.Reader
	watchdog *time.Timer
}

func (s *stallReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.watchdog.Reset(stallTimeout)
	}
	return n, err
}

// verifyArtifact rehashes a file against a sidecar digest of either
// "sha512-<base64>" or "sha1-<hex>" form.
func verifyArtifact(path, digest string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	h512 := sha512.New()
	h1 := sha1.New()
	if _, err := io.Copy(io.MultiWriter(h512, h1), f); err != nil {
		return false
	}
	if hexSum, ok := strings.CutPrefix(digest, "sha1-"); ok {
		return verify("", hexSum, h512, h1) == nil
	}
	return verify(digest, "", h512, h1) == nil
}

// ReadMeta returns nil for artifacts cached before sidecars existed;
// callers surface that as a degradation note, not an error.
func ReadMeta(artifactPath string) *Meta {
	b, err := os.ReadFile(MetaPath(artifactPath))
	if err != nil {
		return nil
	}
	var m Meta
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return &m
}

func getJSON(ctx context.Context, client *http.Client, u string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, metaTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func download(ctx context.Context, client *http.Client, u, dest, integrity, shasum string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	// stall watchdog: cancels the request when no bytes arrive for
	// stallTimeout; progress resets it, so slow links are never killed
	watchdog := time.AfterFunc(stallTimeout, cancel)
	defer watchdog.Stop()
	body := &stallReader{r: resp.Body, watchdog: watchdog}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".download-*")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	h512 := sha512.New()
	h1 := sha1.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h512, h1), body); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("download stalled (no data for %s): %w", stallTimeout, err)
		}
		return err
	}
	if err := verify(integrity, shasum, h512, h1); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}

func verify(integrity, shasum string, h512, h1 hash.Hash) error {
	if b64, ok := strings.CutPrefix(integrity, "sha512-"); ok {
		got := base64.StdEncoding.EncodeToString(h512.Sum(nil))
		if got != b64 {
			return fmt.Errorf("sha512 mismatch: got %s want %s", got, b64)
		}
		return nil
	}
	if shasum != "" {
		got := hex.EncodeToString(h1.Sum(nil))
		if !strings.EqualFold(got, shasum) {
			return fmt.Errorf("sha1 mismatch: got %s want %s", got, shasum)
		}
		return nil
	}
	return fmt.Errorf("no integrity data in registry metadata")
}
