package fetch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ResolveGHACommit resolves a GitHub Actions ref (tag, branch, or SHA) to
// its commit SHA: the immutable anchor behind a mutable tag pin, and the
// single most important fact about a GHA dependency. name is owner/repo.
func ResolveGHACommit(ctx context.Context, client *http.Client, name, ref string) (string, error) {
	var out struct {
		SHA string `json:"sha"`
	}
	u := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", name, ref)
	if err := getGitHubJSON(ctx, client, u, &out); err != nil {
		return "", fmt.Errorf("gha:%s resolve %q: %w", name, ref, err)
	}
	if out.SHA == "" {
		return "", fmt.Errorf("gha:%s: ref %q did not resolve to a commit", name, ref)
	}
	return out.SHA, nil
}

// ResolveGHARef resolves a ref to its commit AND classifies the pin: sha
// (immutable) / tag (mutable, re-pointable) / branch (unpinned, moves on
// every push). The kind drives the strength of the pinning warning.
func ResolveGHARef(ctx context.Context, client *http.Client, name, ref string) (sha, kind string, err error) {
	sha, err = ResolveGHACommit(ctx, client, name, ref)
	if err != nil {
		return "", "", err
	}
	if isHexSHA(ref) {
		return sha, "sha", nil
	}
	if githubRefExists(ctx, client, name, "tags", ref) {
		return sha, "tag", nil
	}
	return sha, "branch", nil
}

// ResolveGHAPin resolves a ref to its immutable identity for fetching. A
// full-sha ref needs no network (it is already the identity; a bogus one
// fails at download). Mutable refs (tag/branch) hit the API fresh on every
// call, by design: a moved tag must never hide behind a cache, so resolution
// is never reused between runs.
func ResolveGHAPin(ctx context.Context, client *http.Client, name, ref string) (sha, kind string, err error) {
	if isHexSHA(ref) {
		return strings.ToLower(ref), "sha", nil
	}
	return ResolveGHARef(ctx, client, name, ref)
}

func githubRefExists(ctx context.Context, client *http.Client, name, kind, ref string) bool {
	ctx, cancel := context.WithTimeout(ctx, metaTimeout)
	defer cancel()
	u := fmt.Sprintf("https://api.github.com/repos/%s/git/ref/%s/%s", name, kind, ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func isHexSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// GHA fetches the repo tree tarball for owner/repo at an already-resolved
// commit. It downloads by sha, never by the caller's ref: a mutable ref can
// re-point between resolution and download, and the sidecar Digest must name
// the bytes actually fetched. dest must be keyed by sha too, so the cached
// artifact is genuinely immutable and a cache hit needs no rehash (no
// registry checksum exists; the sha is the identity, bytes rest on TLS
// trust, recorded as tls-only). ref is the caller's spelling, kept for
// error messages; kind (sha|tag|branch) rides into the sidecar.
func GHA(ctx context.Context, client *http.Client, name, ref, sha, kind, dest string) error {
	if _, err := os.Stat(dest); err == nil && ReadMeta(dest) != nil {
		return nil
	}
	u := GHATarballURL(name, sha)
	if err := downloadPlain(ctx, client, u, dest); err != nil {
		return fmt.Errorf("gha:%s@%s (commit %s): %w", name, ref, sha, err)
	}
	return writeMeta(dest, Meta{URL: u, Digest: "git-" + sha, Verification: VerifyTLSOnly, RefKind: kind})
}

// GHATarballURL is the immutable download address for a resolved commit.
func GHATarballURL(name, sha string) string {
	return fmt.Sprintf("https://codeload.github.com/%s/tar.gz/%s", name, sha)
}

func getGitHubJSON(ctx context.Context, client *http.Client, u string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, metaTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return json.NewDecoder(resp.Body).Decode(v)
	case http.StatusNotFound:
		return statusErr(u, resp.StatusCode, "repo or ref not found; check owner/repo and the tag")
	case http.StatusForbidden:
		return statusErr(u, resp.StatusCode, "rate-limited or forbidden; set GITHUB_TOKEN to raise the limit")
	default:
		return statusErr(u, resp.StatusCode, "")
	}
}

// downloadPlain fetches url to dest with NO integrity check, for artifacts
// that carry no registry checksum (GHA tarballs). It keeps the stall
// watchdog so a slow codeload transfer is never killed while progressing.
func downloadPlain(ctx context.Context, client *http.Client, u, dest string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusErr(u, resp.StatusCode, "")
	}
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
	if _, err := io.Copy(tmp, capped(body)); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("download stalled (no data for %s): %w", stallTimeout, err)
		}
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}
