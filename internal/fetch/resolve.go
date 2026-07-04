package fetch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// Resolved is a concrete version resolution with its publish time (zero if
// the registry did not give one) and a note if a cooldown skipped newer
// versions.
type Resolved struct {
	Version   string
	Published time.Time
	Note      string
}

// ResolveVersion turns "latest" or "" into a concrete version. With
// cooldown == 0 it uses the registry's own latest tag; with cooldown > 0
// it picks the newest NON-prerelease version published at least that long
// ago (the pnpm minimumReleaseAge / npmrc cooldown posture: do not adopt a
// version fresh enough to be an uncaught compromise). Concrete inputs pass
// through unchanged so caching keys on a real version, never "latest".
func ResolveVersion(ctx context.Context, client *http.Client, eco, name, req string, cooldown time.Duration) (Resolved, error) {
	if req != "" && req != "latest" {
		return Resolved{Version: req}, nil
	}
	switch eco {
	case "npm":
		return resolveNPM(ctx, client, name, cooldown)
	case "go":
		return resolveGo(ctx, client, name, cooldown)
	case "crates":
		return resolveCrate(ctx, client, name, cooldown)
	}
	return Resolved{}, fmt.Errorf("latest resolution unsupported for ecosystem %q", eco)
}

func resolveNPM(ctx context.Context, client *http.Client, name string, cooldown time.Duration) (Resolved, error) {
	var doc struct {
		DistTags map[string]string          `json:"dist-tags"`
		Time     map[string]string          `json:"time"`
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := getJSON(ctx, client, npmRegistry+"/"+url.PathEscape(name), &doc); err != nil {
		return Resolved{}, fmt.Errorf("npm:%s resolve: %w", name, err)
	}
	if cooldown == 0 {
		v := doc.DistTags["latest"]
		if v == "" {
			return Resolved{}, fmt.Errorf("npm:%s has no latest dist-tag", name)
		}
		return Resolved{Version: v, Published: parseTime(doc.Time[v])}, nil
	}
	cand := make([]candidate, 0, len(doc.Versions))
	for v := range doc.Versions {
		cand = append(cand, candidate{v, parseTime(doc.Time[v])})
	}
	return pickCooldown(cand, cooldown)
}

func resolveGo(ctx context.Context, client *http.Client, mod string, cooldown time.Duration) (Resolved, error) {
	esc, err := module.EscapePath(mod)
	if err != nil {
		return Resolved{}, err
	}
	if cooldown == 0 {
		var info struct {
			Version string
			Time    time.Time
		}
		if err := getJSON(ctx, client, fmt.Sprintf("%s/%s/@latest", goProxy, esc), &info); err != nil {
			return Resolved{}, fmt.Errorf("go:%s resolve: %w", mod, err)
		}
		return Resolved{Version: info.Version, Published: info.Time}, nil
	}
	// cooldown: list versions, then time each (newest-first, stop early)
	list, err := getBytes(ctx, client, fmt.Sprintf("%s/%s/@v/list", goProxy, esc))
	if err != nil {
		return Resolved{}, fmt.Errorf("go:%s list: %w", mod, err)
	}
	var cand []candidate
	for line := range strings.Lines(string(list)) {
		v := strings.TrimSpace(line)
		if v == "" || semver.Prerelease(v) != "" {
			continue
		}
		var info struct {
			Version string
			Time    time.Time
		}
		if getJSON(ctx, client, fmt.Sprintf("%s/%s/@v/%s.info", goProxy, esc, v), &info) == nil {
			cand = append(cand, candidate{v, info.Time})
		}
	}
	return pickCooldown(cand, cooldown)
}

func resolveCrate(ctx context.Context, client *http.Client, name string, cooldown time.Duration) (Resolved, error) {
	var doc struct {
		Crate struct {
			MaxStable string `json:"max_stable_version"`
		} `json:"crate"`
		Versions []struct {
			Num       string    `json:"num"`
			CreatedAt time.Time `json:"created_at"`
			Yanked    bool      `json:"yanked"`
		} `json:"versions"`
	}
	if err := getJSON(ctx, client, "https://crates.io/api/v1/crates/"+url.PathEscape(name), &doc); err != nil {
		return Resolved{}, fmt.Errorf("crates:%s resolve: %w", name, err)
	}
	if cooldown == 0 {
		if doc.Crate.MaxStable == "" {
			return Resolved{}, fmt.Errorf("crates:%s has no stable version", name)
		}
		var pub time.Time
		for _, v := range doc.Versions {
			if v.Num == doc.Crate.MaxStable {
				pub = v.CreatedAt
			}
		}
		return Resolved{Version: doc.Crate.MaxStable, Published: pub}, nil
	}
	var cand []candidate
	for _, v := range doc.Versions {
		if v.Yanked || semver.Prerelease("v"+v.Num) != "" {
			continue
		}
		cand = append(cand, candidate{v.Num, v.CreatedAt})
	}
	return pickCooldown(cand, cooldown)
}

type candidate struct {
	version   string
	published time.Time
}

// pickCooldown selects the newest (by semver) candidate published at least
// cooldown ago, and notes how many newer ones the cooldown withheld.
func pickCooldown(cand []candidate, cooldown time.Duration) (Resolved, error) {
	cutoff := time.Now().Add(-cooldown)
	// pass 1: newest old-enough version
	var best candidate
	for _, c := range cand {
		if c.published.IsZero() || c.published.After(cutoff) {
			continue
		}
		if best.version == "" || semverGreater(c.version, best.version) {
			best = c
		}
	}
	if best.version == "" {
		return Resolved{}, fmt.Errorf("no non-prerelease version older than the %s cooldown", cooldown)
	}
	// pass 2: how many real versions the cooldown withheld (newer than the
	// pick but too fresh) -- deterministic, independent of iteration order
	skipped := 0
	for _, c := range cand {
		if !c.published.IsZero() && c.published.After(cutoff) && semverGreater(c.version, best.version) {
			skipped++
		}
	}
	note := ""
	if skipped > 0 {
		note = fmt.Sprintf("cooldown (%s) withheld %d newer version(s)", cooldown, skipped)
	}
	return Resolved{Version: best.version, Published: best.published, Note: note}, nil
}

func semverGreater(a, b string) bool {
	if b == "" {
		return true
	}
	return semver.Compare(canonicalV(a), canonicalV(b)) > 0
}

func canonicalV(v string) string {
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}
