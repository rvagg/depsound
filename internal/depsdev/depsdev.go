// Package depsdev is a thin client for deps.dev's public v3 API, used to
// resolve a package version's FULL transitive dependency set when there is
// no lockfile to diff (the adopt-a-dep / census-transitive case). It is a
// theoretical resolve (deps.dev's, not the user's actual install), so
// callers frame it as an estimate. Public, no auth, stdlib only.
package depsdev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/rvagg/depsound/internal/version"
)

// base is a var so tests can point it at a local server.
var base = "https://api.deps.dev/v3"

const timeout = 30 * time.Second

// Node is one resolved dependency in the subtree: an exact name+version and
// how it relates to the root (DIRECT or INDIRECT).
type Node struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Relation string `json:"relation"` // DIRECT | INDIRECT
}

// System maps a depsound ecosystem to deps.dev's system name. ok=false where
// deps.dev has no resolved graph: Go returns 404 on :dependencies (and does
// not need it, go.mod IS the resolved set).
func System(eco string) (system string, ok bool) {
	switch eco {
	case "npm":
		return "npm", true
	case "crates":
		return "cargo", true
	}
	return "", false
}

// VersionInfo is deps.dev GetVersion: when it was published, whether the
// ecosystem deprecated it, its licenses, and deps.dev's view of the source
// repo (the "actual repo", to cross-check against the package's claim).
type VersionInfo struct {
	PublishedAt time.Time
	Deprecated  bool
	Licenses    []string
	SourceRepo  string // github.com/owner/repo, from the SOURCE_REPO link
}

// Version fetches GetVersion for system/name@ver. Returns nil,nil when
// deps.dev has no record (never blocks a review).
func Version(ctx context.Context, client *http.Client, system, name, ver string) (*VersionInfo, error) {
	u := fmt.Sprintf("%s/systems/%s/packages/%s/versions/%s", base, system, url.PathEscape(name), url.PathEscape(ver))
	var out struct {
		PublishedAt  string   `json:"publishedAt"`
		IsDeprecated bool     `json:"isDeprecated"`
		Licenses     []string `json:"licenses"`
		Links        []struct {
			Label string `json:"label"`
			URL   string `json:"url"`
		} `json:"links"`
	}
	if err := getJSON(ctx, client, u, &out); err != nil {
		return nil, err
	}
	vi := &VersionInfo{Deprecated: out.IsDeprecated, Licenses: out.Licenses}
	vi.PublishedAt, _ = time.Parse(time.RFC3339, out.PublishedAt)
	for _, l := range out.Links {
		if l.Label == "SOURCE_REPO" {
			vi.SourceRepo = l.URL // raw; caller normalizes
		}
	}
	return vi, nil
}

// ProjectInfo is deps.dev GetProject: repo popularity + the OpenSSF
// Scorecard (a supply-chain health snapshot).
type ProjectInfo struct {
	Stars, Forks     int
	ScorecardOverall float64
	ScorecardChecks  map[string]int // check name -> score (-1 = not applicable)
}

// Project fetches GetProject for a github.com/owner/repo key (derive it from
// a VersionInfo.SourceRepo). Returns nil,nil when deps.dev has no project.
func Project(ctx context.Context, client *http.Client, repo string) (*ProjectInfo, error) {
	if repo == "" {
		return nil, nil
	}
	u := fmt.Sprintf("%s/projects/%s", base, url.PathEscape(repo))
	var out struct {
		StarsCount int `json:"starsCount"`
		ForksCount int `json:"forksCount"`
		Scorecard  struct {
			OverallScore float64 `json:"overallScore"`
			Checks       []struct {
				Name  string `json:"name"`
				Score int    `json:"score"`
			} `json:"checks"`
		} `json:"scorecard"`
	}
	if err := getJSON(ctx, client, u, &out); err != nil {
		return nil, err
	}
	pi := &ProjectInfo{Stars: out.StarsCount, Forks: out.ForksCount,
		ScorecardOverall: out.Scorecard.OverallScore, ScorecardChecks: map[string]int{}}
	for _, c := range out.Scorecard.Checks {
		pi.ScorecardChecks[c.Name] = c.Score
	}
	return pi, nil
}

func getJSON(ctx context.Context, client *http.Client, u string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", version.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("deps.dev %s: %s", u, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// Dependencies resolves the flat transitive dependency set (excluding the
// package itself) of system/name@version.
func Dependencies(ctx context.Context, client *http.Client, system, name, ver string) ([]Node, error) {
	u := fmt.Sprintf("%s/systems/%s/packages/%s/versions/%s:dependencies",
		base, system, url.PathEscape(name), url.PathEscape(ver))
	ctx, cancel := context.WithTimeout(ctx, timeout)
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
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("deps.dev has no resolved graph for %s:%s@%s (unpublished, or a binary-only crate)", system, name, ver)
	default:
		return nil, fmt.Errorf("deps.dev %s: %s", u, resp.Status)
	}

	var out struct {
		Nodes []struct {
			VersionKey struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"versionKey"`
			Relation string `json:"relation"`
		} `json:"nodes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("deps.dev %s: %w", u, err)
	}
	var deps []Node
	for _, n := range out.Nodes {
		if n.Relation == "SELF" {
			continue
		}
		deps = append(deps, Node{n.VersionKey.Name, n.VersionKey.Version, n.Relation})
	}
	return deps, nil
}
