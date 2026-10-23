package fetch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// A full-sha ref is already the immutable identity: no network, normalized
// to lower case so cache keys and recorded digests never case-split.
func TestResolveGHAPinSHAShortcut(t *testing.T) {
	sha, kind, err := ResolveGHAPin(context.Background(), &http.Client{}, "owner/repo",
		"2C5A7429AA5BAF8A79E12724A296282CD73E5EE1")
	if err != nil {
		t.Fatal(err)
	}
	if kind != "sha" {
		t.Errorf("kind = %q, want sha", kind)
	}
	if sha != "2c5a7429aa5baf8a79e12724a296282cd73e5ee1" {
		t.Errorf("sha not lowercased: %q", sha)
	}
}

func TestResolveGHAPinTagLookupOutcomes(t *testing.T) {
	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, tc := range []struct {
		name, body, kind, reason string
		status                   int
		header                   http.Header
		transportFailure         bool
	}{
		{name: "tag", status: http.StatusOK, kind: "tag"},
		{name: "branch", status: http.StatusNotFound, kind: "branch"},
		{name: "policy", status: http.StatusForbidden, body: `{"message":"Repository access blocked","block":{"reason":"tos"}}`, header: http.Header{"Retry-After": []string{"60"}}, kind: Denied, reason: "policy-blocked"},
		{name: "rate limit", status: http.StatusForbidden, body: `{"message":"forbidden"}`, header: http.Header{"X-RateLimit-Remaining": []string{"0"}}, kind: Transient, reason: "rate-limited"},
		{name: "authentication", status: http.StatusUnauthorized, header: http.Header{"X-RateLimit-Remaining": []string{"0"}}, kind: Denied},
		{name: "unknown denial", status: http.StatusForbidden, kind: Denied},
		{name: "server failure", status: http.StatusServiceUnavailable, kind: Transient},
		{name: "transport failure", transportFailure: true, kind: Transient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch req.URL.Path {
				case "/repos/owner/repo/commits/v1":
					return testResponse(http.StatusOK, nil, `{"sha":"`+sha+`"}`), nil
				case "/repos/owner/repo/git/ref/tags/v1":
					if tc.transportFailure {
						return nil, errors.New("tag lookup connection failed")
					}
					return testResponse(tc.status, tc.header, tc.body), nil
				default:
					t.Fatalf("unexpected request: %s", req.URL)
					return nil, nil
				}
			})}
			resolved, kind, err := ResolveGHAPin(t.Context(), client, "owner/repo", "v1")
			if tc.status == http.StatusOK || tc.status == http.StatusNotFound {
				if err != nil || resolved != sha || kind != tc.kind {
					t.Fatalf("resolved pin = %q %q, %v", resolved, kind, err)
				}
				return
			}
			if err == nil || kind != "" {
				t.Fatalf("failed tag lookup invented a pin kind: %q %q, %v", resolved, kind, err)
			}
			var unavailable UnavailableError
			if !errors.As(err, &unavailable) {
				t.Fatalf("tag lookup lost its acquisition outcome: %v", err)
			}
			failure := unavailable.Unavailable()
			if failure.Kind != tc.kind || failure.Reason != tc.reason || failure.Status != tc.status || failure.Stage != "ref-resolution" || failure.URL != "https://api.github.com/repos/owner/repo/git/ref/tags/v1" {
				t.Fatalf("tag lookup outcome = %+v", failure)
			}
			if tc.reason == "policy-blocked" && failure.PolicyReason != "tos" {
				t.Fatalf("tag lookup lost its policy reason: %+v", failure)
			}
		})
	}
}

// The download address must be the resolved commit, never the caller's ref:
// a mutable ref can re-point between resolution and download.
func TestGHATarballURLBySHA(t *testing.T) {
	got := GHATarballURL("actions/checkout", "11bd71901bbe5b1630ceea73d27597364c9af683")
	want := "https://codeload.github.com/actions/checkout/tar.gz/11bd71901bbe5b1630ceea73d27597364c9af683"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The download cap aborts an oversized stream with the ceiling named,
// instead of filling the runner's disk.
func TestCappedReader(t *testing.T) {
	r := &cappedReader{r: neverEnding{}, remaining: 1000}
	n, err := io.Copy(io.Discard, r)
	if err == nil || n > 1000 {
		t.Errorf("cap not enforced: n=%d err=%v", n, err)
	}
	if err != nil && !strings.Contains(err.Error(), "artifact ceiling") {
		t.Errorf("error does not name the ceiling: %v", err)
	}
}

type neverEnding struct{}

func (neverEnding) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'A'
	}
	return len(p), nil
}

func TestResolveGHACommitPolicyBlock(t *testing.T) {
	client := githubTestClient(http.StatusForbidden, http.Header{"Retry-After": []string{"60"}}, `{"message":"Repository access blocked","block":{"reason":"tos\u001b[31m"}}`)

	_, err := ResolveGHACommit(context.Background(), client, "owner/repo", "v1")
	failure := unavailableHTTPError(t, err)
	if failure.Kind() != Denied || failure.Stage != "ref-resolution" || failure.Reason != "policy-blocked" {
		t.Fatalf("classification = %#v", failure)
	}
	if failure.PolicyReason != "tos\x1b[31m" {
		t.Fatalf("policy reason = %q", failure.PolicyReason)
	}
}

func TestGHADownloadRateLimited(t *testing.T) {
	client := githubTestClient(http.StatusForbidden, http.Header{"X-RateLimit-Remaining": []string{"0"}}, `{"message":"forbidden"}`)
	err := GHA(context.Background(), client, "owner/repo", "v1", strings.Repeat("a", 40), t.TempDir()+"/action.tar.gz")
	failure := unavailableHTTPError(t, err)
	if failure.Kind() != Transient || failure.Stage != "artifact" || failure.Reason != "rate-limited" {
		t.Fatalf("classification = %#v", failure)
	}
	if failure.ArtifactURL == "" || failure.ArtifactURL != failure.URL {
		t.Fatalf("artifact URL = %q, URL = %q", failure.ArtifactURL, failure.URL)
	}
}

func TestGitHubStatusErrEvidenceBoundaries(t *testing.T) {
	t.Run("unknown forbidden", func(t *testing.T) {
		failure := githubStatusErr(testResponse(http.StatusForbidden, nil, `{"message":"forbidden"}`), "https://api.github.com/x", "input", "")
		if failure.Kind() != Denied || failure.Reason != "" || failure.PolicyReason != "" {
			t.Fatalf("classification = %#v", failure)
		}
	})
	t.Run("unauthorized", func(t *testing.T) {
		failure := githubStatusErr(testResponse(http.StatusUnauthorized, http.Header{"X-RateLimit-Remaining": []string{"0"}}, `{"message":"API rate limit exceeded"}`), "https://api.github.com/x", "input", "")
		if failure.Kind() != Denied || failure.Reason != "" {
			t.Fatalf("classification = %#v", failure)
		}
	})
	t.Run("legal restriction", func(t *testing.T) {
		failure := githubStatusErr(testResponse(http.StatusUnavailableForLegalReasons, nil, `{"message":"Repository access blocked","block":{"reason":"legal"}}`), "https://api.github.com/x", "input", "")
		if failure.Kind() != Denied || failure.Reason != "policy-blocked" || failure.PolicyReason != "legal" {
			t.Fatalf("classification = %#v", failure)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		failure := githubStatusErr(testResponse(http.StatusForbidden, nil, `{"message":`), "https://api.github.com/x", "input", "")
		if failure.Kind() != Denied || failure.Reason != "" {
			t.Fatalf("classification = %#v", failure)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		body := `{"message":"Repository access blocked","block":{"reason":"tos"}}` + strings.Repeat(" ", maxGitHubErrorBytes)
		failure := githubStatusErr(testResponse(http.StatusForbidden, nil, body), "https://api.github.com/x", "input", "")
		if failure.Kind() != Denied || failure.Reason != "" || failure.PolicyReason != "" {
			t.Fatalf("classification = %#v", failure)
		}
	})
	t.Run("too many requests", func(t *testing.T) {
		failure := githubStatusErr(testResponse(http.StatusTooManyRequests, nil, `not json`), "https://api.github.com/x", "input", "")
		if failure.Kind() != Transient || failure.Reason != "rate-limited" {
			t.Fatalf("classification = %#v", failure)
		}
	})
}

func githubTestClient(status int, header http.Header, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testResponse(status, header, body), nil
	})}
}

func testResponse(status int, header http.Header, body string) *http.Response {
	canonical := make(http.Header, len(header))
	for key, values := range header {
		for _, value := range values {
			canonical.Add(key, value)
		}
	}
	return &http.Response{
		StatusCode: status,
		Header:     canonical,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}

func unavailableHTTPError(t *testing.T, err error) *HTTPError {
	t.Helper()
	var failure *HTTPError
	if !errors.As(err, &failure) {
		t.Fatalf("error %v does not carry HTTP failure", err)
	}
	return failure
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
