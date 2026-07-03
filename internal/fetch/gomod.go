package fetch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
)

// Vars so tests can point them at local servers.
var (
	goProxy = "https://proxy.golang.org"
	goSumDB = "https://sum.golang.org"
)

// GoModule fetches module@version from the Go proxy into dest. The
// downloaded zip's H1 dirhash is compared against the checksum
// database's lookup record (TLS-trust comparison today; full
// transparency-log note verification is a target). Cache hits are
// rehashed against the sidecar like every other artifact.
func GoModule(ctx context.Context, client *http.Client, mod, version, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		if m := ReadMeta(dest); m != nil && verifyGoArtifact(dest, m.Digest) {
			return nil
		}
	}

	escPath, err := module.EscapePath(mod)
	if err != nil {
		return fmt.Errorf("go:%s: %w", mod, err)
	}
	escVer, err := module.EscapeVersion(version)
	if err != nil {
		return fmt.Errorf("go:%s@%s: %w", mod, version, err)
	}
	u := fmt.Sprintf("%s/%s/@v/%s.zip", goProxy, escPath, escVer)

	tmp, err := fetchToTemp(ctx, client, u, filepath.Dir(dest))
	if err != nil {
		return fmt.Errorf("go:%s@%s: %w", mod, version, err)
	}
	defer os.Remove(tmp)

	h1, err := dirhash.HashZip(tmp, dirhash.Hash1)
	if err != nil {
		return fmt.Errorf("go:%s@%s: hashing zip: %w", mod, version, err)
	}
	verification, err := checkSumDB(ctx, client, mod, version, h1)
	if err != nil {
		return fmt.Errorf("go:%s@%s: %w", mod, version, err)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	return writeMeta(dest, Meta{URL: u, Digest: h1, Verification: verification})
}

// checkSumDB compares h1 against the checksum database's record for the
// module zip and reports how the artifact was verified. A module absent
// from the database (private, or GONOSUMDB territory) is not an error,
// but the degradation to TLS trust is RECORDED, never silent.
func checkSumDB(ctx context.Context, client *http.Client, mod, version, h1 string) (string, error) {
	escPath, err := module.EscapePath(mod)
	if err != nil {
		return "", err
	}
	escVer, err := module.EscapeVersion(version)
	if err != nil {
		return "", err
	}
	u := fmt.Sprintf("%s/lookup/%s@%s", goSumDB, escPath, escVer)
	ctx, cancel := context.WithTimeout(ctx, metaTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return VerifyTLSOnly, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("sumdb lookup %s: %s", u, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	want := fmt.Sprintf("%s %s %s", mod, version, h1)
	for line := range strings.Lines(string(body)) {
		if strings.TrimSpace(line) == want {
			return VerifySumDB, nil
		}
	}
	return "", fmt.Errorf("zip hash %s does not match the checksum database record", h1)
}

func verifyGoArtifact(path, digest string) bool {
	if !strings.HasPrefix(digest, "h1:") {
		return false
	}
	h1, err := dirhash.HashZip(path, dirhash.Hash1)
	return err == nil && h1 == digest
}

// fetchToTemp downloads u into a temp file in dir under the stall
// watchdog, returning the temp path.
func fetchToTemp(ctx context.Context, client *http.Client, u, dir string) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return "", fmt.Errorf("GET %s: %s (module path or version not found on the proxy; check spelling)", u, resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return "", err
	}
	watchdog := time.AfterFunc(stallTimeout, cancel)
	defer watchdog.Stop()
	_, err = io.Copy(tmp, &stallReader{r: resp.Body, watchdog: watchdog})
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp.Name())
		if ctx.Err() != nil {
			return "", fmt.Errorf("download stalled (no data for %s): %w", stallTimeout, err)
		}
		return "", err
	}
	return tmp.Name(), nil
}
