package fetch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// maxManifestBytes caps a caller-pointed text file (a go.mod, not an
// artifact); the largest real go.mod files are well under a MiB.
const maxManifestBytes = 16 << 20

// GetURL fetches a small text file the CALLER named (a manifest URL for
// transitive analysis), TLS-only, size-capped. A github.com/blob URL is
// rewritten to raw; github hosts get GITHUB_TOKEN. The URL is caller-
// supplied, not extracted from untrusted package content, so there is no
// SSRF-from-a-package concern; the bytes are still untrusted DATA.
func GetURL(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	if strings.HasPrefix(u, "http://") {
		return nil, fmt.Errorf("refusing non-TLS URL %q (use https)", u)
	}
	if !strings.HasPrefix(u, "https://") {
		return nil, fmt.Errorf("not a URL: %q", u)
	}
	u = rewriteGitHubBlob(u)
	ctx, cancel := context.WithTimeout(ctx, metaTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if isGitHubHost(u) {
		if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr(u, resp.StatusCode, "")
	}
	return readCapped(resp.Body, u)
}

// GitHubContents fetches a file at a ref via the API contents endpoint,
// which (unlike raw.githubusercontent.com) works for PRIVATE repos with a
// token. name is owner/repo; path defaults to go.mod when empty.
func GitHubContents(ctx context.Context, client *http.Client, name, ref, path string) ([]byte, error) {
	if path == "" {
		path = "go.mod"
	}
	u := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s?ref=%s", name, path, url.QueryEscape(ref))
	ctx, cancel := context.WithTimeout(ctx, metaTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/vnd.github.raw+json")
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return readCapped(resp.Body, u)
	case http.StatusNotFound:
		return nil, statusErr(u, resp.StatusCode, fmt.Sprintf("github:%s@%s:%s not found (repo, ref or path wrong; private repos need GITHUB_TOKEN)", name, ref, path))
	default:
		return nil, statusErr(u, resp.StatusCode, "")
	}
}

func readCapped(r io.Reader, u string) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxManifestBytes {
		return nil, fmt.Errorf("%s exceeds %d byte manifest limit", u, maxManifestBytes)
	}
	return b, nil
}

func isGitHubHost(u string) bool {
	return strings.HasPrefix(u, "https://raw.githubusercontent.com/") ||
		strings.HasPrefix(u, "https://api.github.com/") ||
		strings.HasPrefix(u, "https://github.com/")
}

// rewriteGitHubBlob turns a human github.com/<o>/<r>/blob/<ref>/<path> URL
// into the raw content URL, since agents often have the blob form.
func rewriteGitHubBlob(u string) string {
	const p = "https://github.com/"
	rest, ok := strings.CutPrefix(u, p)
	if !ok {
		return u
	}
	owner, after, ok := strings.Cut(rest, "/")
	if !ok {
		return u
	}
	repo, after, ok := strings.Cut(after, "/blob/")
	if !ok {
		return u
	}
	return "https://raw.githubusercontent.com/" + owner + "/" + repo + "/" + after
}
