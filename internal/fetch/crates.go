package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/rvagg/depsound/internal/version"
)

// Vars so tests can point them at local servers.
var (
	cratesDL    = "https://static.crates.io/crates"
	cratesIndex = "https://index.crates.io"
)

// Crate fetches name@version from crates.io into dest. The sparse index
// supplies the sha256 checksum, verified before the artifact enters the
// cache. Cache hits are rehashed against the sidecar like every artifact.
func Crate(ctx context.Context, client *http.Client, name, version_, dest string) error {
	// crate names are a strict charset; validating up front closes URL
	// injection before name interpolation (detect will feed
	// manifest-derived names here).
	if !validCrateName(name) {
		return fmt.Errorf("crates:%s: invalid crate name (allowed: letters, digits, - _)", name)
	}
	if _, err := os.Stat(dest); err == nil {
		if m := ReadMeta(dest); m != nil && verifyCrate(dest, m.Digest) {
			return nil
		}
	}

	cksum, err := indexChecksum(ctx, client, name, version_)
	if err != nil {
		return fmt.Errorf("crates:%s@%s: %w", name, version_, err)
	}
	u := fmt.Sprintf("%s/%s/%s-%s.crate", cratesDL, name, name, version_)
	tmp, err := fetchToTemp(ctx, client, u, filepath.Dir(dest))
	if err != nil {
		return fmt.Errorf("crates:%s@%s: %w", name, version_, err)
	}
	defer os.Remove(tmp)

	if !verifyCrate(tmp, "sha256-"+cksum) {
		return fmt.Errorf("crates:%s@%s: sha256 mismatch against index checksum", name, version_)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	return writeMeta(dest, Meta{URL: u, Digest: "sha256-" + cksum, Verification: VerifyRegistry256})
}

// indexChecksum reads the sparse-index file for a crate and returns the
// cksum for the requested version. The index path is a prefix scheme:
// 1-char names under 1/, 2-char under 2/, 3-char under 3/<first>/, and
// 4+ under <first-two>/<next-two>/.
func indexChecksum(ctx context.Context, client *http.Client, name, version_ string) (string, error) {
	lower := strings.ToLower(name)
	u := cratesIndex + "/" + indexPath(lower)
	body, err := getBytes(ctx, client, u)
	if err != nil {
		return "", err
	}
	// each line is a JSON object for one version
	for line := range strings.Lines(string(body)) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e struct {
			Vers  string `json:"vers"`
			Cksum string `json:"cksum"`
		}
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		if e.Vers == version_ {
			if e.Cksum == "" {
				return "", fmt.Errorf("index entry for %s has no cksum", version_)
			}
			return e.Cksum, nil
		}
	}
	return "", fmt.Errorf("version %s not found in crates.io index", version_)
}

func indexPath(name string) string {
	switch {
	case len(name) == 1:
		return "1/" + name
	case len(name) == 2:
		return "2/" + name
	case len(name) == 3:
		return "3/" + name[:1] + "/" + name
	default:
		return name[:2] + "/" + name[2:4] + "/" + name
	}
}

func validCrateName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func verifyCrate(path, digest string) bool {
	hexsum, ok := strings.CutPrefix(digest, "sha256-")
	if !ok {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == hexsum
}

func getBytes(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, metaTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", version.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}
