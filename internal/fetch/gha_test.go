package fetch

import (
	"context"
	"net/http"
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

// The download address must be the resolved commit, never the caller's ref:
// a mutable ref can re-point between resolution and download.
func TestGHATarballURLBySHA(t *testing.T) {
	got := GHATarballURL("actions/checkout", "11bd71901bbe5b1630ceea73d27597364c9af683")
	want := "https://codeload.github.com/actions/checkout/tar.gz/11bd71901bbe5b1630ceea73d27597364c9af683"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
