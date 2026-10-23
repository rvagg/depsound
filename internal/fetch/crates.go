package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	if !validCrateName(name) {
		return fmt.Errorf("crates:%s: invalid crate name (allowed: letters, digits, - _)", name)
	}
	if _, err := os.Stat(dest); err == nil {
		if m := ReadMeta(dest); m != nil && verifyCrate(dest, m.Digest) {
			return nil
		}
	}

	u := fmt.Sprintf("%s/%s/%s-%s.crate", cratesDL, name, name, version_)
	checksum, err := indexChecksum(ctx, client, name, version_, u)
	if err != nil {
		return fmt.Errorf("crates:%s@%s: %w", name, version_, err)
	}
	if checksum.State == "version-absent" {
		return &RegistryMissing{
			URL: checksum.URL, ArtifactURL: u, Status: checksum.Status,
			Hint: fmt.Sprintf("version %s is absent from the crates.io sparse index; artifact contents were not inspected", version_),
		}
	}
	tmp, err := fetchToTemp(ctx, client, u, filepath.Dir(dest))
	if err != nil {
		return fmt.Errorf("crates:%s@%s: %w", name, version_, err)
	}
	defer os.Remove(tmp)

	if !verifyCrate(tmp, checksum.Expected) {
		return fmt.Errorf("crates:%s@%s: sha256 mismatch against index checksum", name, version_)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	return writeMeta(dest, Meta{URL: u, Digest: checksum.Expected, Verification: VerifyRegistry256})
}

// LocalCrateEvidence records a local archive import. Its metadata belongs to
// this import rather than the content-addressed archive, which can be shared
// by imports from distinct origins.
type LocalCrateEvidence struct {
	Path string
	Meta Meta
}

// LocalCrate imports a caller-supplied quarantined archive as inert evidence.
// Its sha256 is always recorded. When crates.io's sparse index still carries
// the version checksum, a mismatch aborts and a match is recorded separately
// from ordinary registry acquisition. dir stores immutable archive bytes by
// their full SHA-256 digest.
func LocalCrate(ctx context.Context, client *http.Client, name, version_, src, dir string) (*LocalCrateEvidence, error) {
	if !validCrateName(name) {
		return nil, fmt.Errorf("crates:%s: invalid crate name (allowed: letters, digits, - _)", name)
	}
	resolved, err := filepath.EvalSymlinks(src)
	if err != nil {
		return nil, fmt.Errorf("local crate %q: %w", src, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, fmt.Errorf("local crate %q: %w", src, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("local crate %q: %w", src, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("local crate %q is not a regular file", src)
	}
	if info.Size() > maxArtifactBytes {
		return nil, fmt.Errorf("local crate %q exceeds the %d byte artifact ceiling", src, int64(maxArtifactBytes))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	in, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(dir, ".local-crate-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, hash), capped(in)); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("local crate %q: %w", src, err)
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	digest := "sha256-" + hex.EncodeToString(hash.Sum(nil))
	verification := VerifyLocalSHA256
	checksum, _ := indexChecksum(ctx, client, name, version_, "")
	if checksum.State == "matched" {
		if digest != checksum.Expected {
			return nil, fmt.Errorf("local crate %q: sha256 mismatch against crates.io index checksum for %s@%s", src, name, version_)
		}
		verification = VerifyLocalRegistry256
	}
	path := filepath.Join(dir, strings.TrimPrefix(digest, "sha256-"))
	if err := publishLocalCrate(tmp.Name(), path, digest); err != nil {
		return nil, err
	}
	origin := (&url.URL{Scheme: "file", Path: filepath.ToSlash(resolved)}).String()
	return &LocalCrateEvidence{
		Path: path,
		Meta: Meta{
			URL: origin, Digest: digest, Verification: verification,
			RegistryChecksum: checksum,
		},
	}, nil
}

func publishLocalCrate(tmp, path, digest string) error {
	if err := os.Link(tmp, path); err == nil {
		return nil
	} else if !os.IsExist(err) {
		return err
	}
	if !verifyCrate(path, digest) {
		return fmt.Errorf("local crate cache %q does not match digest %s", path, digest)
	}
	return nil
}

// indexChecksum reads the sparse-index file for a crate. A missing version is
// established only after every non-empty index line has parsed successfully.
func indexChecksum(ctx context.Context, client *http.Client, name, version_, artifactURL string) (*RegistryChecksum, error) {
	lower := strings.ToLower(name)
	u := cratesIndex + "/" + indexPath(lower)
	body, status, err := getBytes(ctx, client, u, "registry-index")
	observed := &RegistryChecksum{
		URL: u, ObservedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err != nil {
		observed.State = "lookup-failed"
		observed.Status = status
		observed.Error = err.Error()
		return observed, withArtifactURL(err, artifactURL)
	}
	observed.Status = status
	for line := range strings.Lines(string(body)) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry struct {
			Vers  string `json:"vers"`
			Cksum string `json:"cksum"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			err = failedAcquisition("registry-index", u, status, fmt.Errorf("parse sparse index: %w", err))
			observed.State = "lookup-failed"
			observed.Error = err.Error()
			return observed, withArtifactURL(err, artifactURL)
		}
		if entry.Vers == "" || entry.Cksum == "" {
			err := failedAcquisition("registry-index", u, status, fmt.Errorf("parse sparse index: invalid entry"))
			observed.State = "lookup-failed"
			observed.Error = err.Error()
			return observed, withArtifactURL(err, artifactURL)
		}
		if entry.Vers == version_ {
			observed.State = "matched"
			observed.Expected = "sha256-" + entry.Cksum
			return observed, nil
		}
	}
	observed.State = "version-absent"
	return observed, nil
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

func getBytes(ctx context.Context, client *http.Client, u, stage string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, metaTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", version.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, failedAcquisition(stage, u, 0, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, statusErrAt(stage, u, resp.StatusCode, "")
	}
	const maxMetadataBytes = 16 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	if err != nil {
		return nil, resp.StatusCode, failedAcquisition(stage, u, resp.StatusCode, err)
	}
	if len(body) > maxMetadataBytes {
		return nil, resp.StatusCode, failedAcquisition(stage, u, resp.StatusCode, fmt.Errorf("metadata exceeds %d byte ceiling", maxMetadataBytes))
	}
	return body, resp.StatusCode, nil
}
