package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rvagg/depvet/internal/cache"
	"github.com/rvagg/depvet/internal/version"
)

var apiURL = "https://api.osv.dev/v1/query"

const userAgent = version.UserAgent

// cacheTTL bounds staleness: OSV is time-varying (advisories land after a
// release), so unlike immutable artifacts it is re-fetched when stale.
const cacheTTL = 6 * time.Hour

type Vuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Fixed    []string `json:"fixed,omitempty"` // versions that fix it, from affected ranges
}

// Assessment is the upgrade's vulnerability delta. FixedByUpgrade is the
// argument FOR the bump; StillPresent means the bump does not help;
// Introduced is the rare case where the new version is newly vulnerable.
type Assessment struct {
	Queried        bool   `json:"queried"`
	FetchedAt      string `json:"fetchedAt,omitempty"`
	Ecosystem      string `json:"ecosystem,omitempty"`
	FixedByUpgrade []Vuln `json:"fixedByUpgrade,omitempty"`
	StillPresent   []Vuln `json:"stillPresent,omitempty"`
	Introduced     []Vuln `json:"introduced,omitempty"`
	Note           string `json:"note,omitempty"`
}

// Ecosystem maps a depvet ecosystem id to OSV's. Returns false when OSV
// has no matching ecosystem.
func Ecosystem(eco string) (string, bool) {
	switch eco {
	case "npm":
		return "npm", true
	case "go":
		return "Go", true
	case "crates":
		return "crates.io", true
	}
	return "", false
}

// osvVersion adapts depvet's version string to what OSV expects: Go
// advisory ranges are semver without the leading v that Go modules carry.
func osvVersion(osvEco, version string) string {
	if osvEco == "Go" {
		return strings.TrimPrefix(version, "v")
	}
	return version
}

// Assess queries both versions and diffs the vulnerability sets. Failures
// degrade to a noted, un-queried Assessment rather than erroring: a
// security lookup being unavailable must not block a review.
func Assess(ctx context.Context, client *http.Client, cacheRoot, eco, name, from, to string) Assessment {
	osvEco, ok := Ecosystem(eco)
	if !ok {
		return Assessment{Note: "OSV has no ecosystem mapping for " + eco}
	}
	fromV, fromT, err1 := query(ctx, client, cacheRoot, osvEco, name, osvVersion(osvEco, from))
	toV, toT, err2 := query(ctx, client, cacheRoot, osvEco, name, osvVersion(osvEco, to))
	if err1 != nil || err2 != nil {
		return Assessment{Note: "OSV lookup failed (network or API); no vulnerability data"}
	}

	// Stamp with the OLDER of the two fetches: cache hits carry their
	// original fetch time, so a 6h-old cached query must not present as
	// just-fetched.
	fetchedAt := fromT
	if toT.Before(fetchedAt) {
		fetchedAt = toT
	}
	a := Assessment{Queried: true, Ecosystem: osvEco, FetchedAt: fetchedAt.UTC().Format(time.RFC3339)}
	fromSet := index(fromV)
	toSet := index(toV)
	for key, v := range fromSet {
		if _, still := toSet[key]; still {
			a.StillPresent = append(a.StillPresent, v)
		} else {
			a.FixedByUpgrade = append(a.FixedByUpgrade, v)
		}
	}
	for key, v := range toSet {
		if _, was := fromSet[key]; !was {
			a.Introduced = append(a.Introduced, v)
		}
	}
	sortVulns(a.FixedByUpgrade)
	sortVulns(a.StillPresent)
	sortVulns(a.Introduced)
	return a
}

// Present looks up the vulnerabilities affecting a SINGLE version (the
// absolute/census framing, vs Assess's delta). Degrades to nil on
// failure or unmapped ecosystem; a security lookup must not block a
// review. queried reports whether the lookup actually ran.
func Present(ctx context.Context, client *http.Client, cacheRoot, eco, name, version string) (vulns []Vuln, fetchedAt string, queried bool) {
	osvEco, ok := Ecosystem(eco)
	if !ok {
		return nil, "", false
	}
	v, ts, err := query(ctx, client, cacheRoot, osvEco, name, osvVersion(osvEco, version))
	if err != nil {
		return nil, "", false
	}
	// dedupe by alias so GHSA+CVE+RUSTSEC of one advisory count once
	seen := map[string]bool{}
	for _, vu := range v {
		key := canonical(vu)
		if !seen[key] {
			seen[key] = true
			vulns = append(vulns, vu)
		}
	}
	sortVulns(vulns)
	return vulns, ts.UTC().Format(time.RFC3339), true
}

// index keys vulns by a canonical id that collapses aliases (an advisory
// returned as both GHSA-x and CVE-y, or GHSA and RUSTSEC, is one vuln).
func index(vulns []Vuln) map[string]Vuln {
	out := map[string]Vuln{}
	for _, v := range vulns {
		out[canonical(v)] = v
	}
	return out
}

// canonical picks the lexicographically smallest of the id and its
// aliases, so the same advisory maps to one key regardless of which
// identifier OSV returned first.
func canonical(v Vuln) string {
	best := v.ID
	for _, a := range v.Aliases {
		if a < best {
			best = a
		}
	}
	return best
}

func sortVulns(vs []Vuln) {
	sort.Slice(vs, func(i, j int) bool { return vs[i].ID < vs[j].ID })
}

func query(ctx context.Context, client *http.Client, cacheRoot, osvEco, name, version string) ([]Vuln, time.Time, error) {
	if v, ts, ok := readCache(cacheRoot, osvEco, name, version); ok {
		return v, ts, nil
	}
	body, _ := json.Marshal(map[string]any{
		"version": version,
		"package": map[string]string{"name": name, "ecosystem": osvEco},
	})
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("OSV query: %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, time.Time{}, err
	}
	vulns := parse(raw)
	now := time.Now().UTC()
	writeCache(cacheRoot, osvEco, name, version, vulns, now)
	return vulns, now, nil
}

// parse handles OSV's response shape, including the empty-result form
// which is `{}` (no vulns key), not `{"vulns": []}`.
func parse(raw []byte) []Vuln {
	var resp struct {
		Vulns []struct {
			ID       string   `json:"id"`
			Aliases  []string `json:"aliases"`
			Summary  string   `json:"summary"`
			Affected []struct {
				Ranges []struct {
					Events []struct {
						Fixed string `json:"fixed"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
			Severity []struct {
				Score string `json:"score"`
			} `json:"severity"`
		} `json:"vulns"`
	}
	if json.Unmarshal(raw, &resp) != nil {
		return nil
	}
	var out []Vuln
	for _, v := range resp.Vulns {
		vuln := Vuln{ID: v.ID, Aliases: v.Aliases, Summary: v.Summary}
		if len(v.Severity) > 0 {
			vuln.Severity = v.Severity[0].Score
		}
		seen := map[string]bool{}
		for _, af := range v.Affected {
			for _, rg := range af.Ranges {
				for _, e := range rg.Events {
					if e.Fixed != "" && !seen[e.Fixed] {
						seen[e.Fixed] = true
						vuln.Fixed = append(vuln.Fixed, e.Fixed)
					}
				}
			}
		}
		out = append(out, vuln)
	}
	return out
}

type cacheEnvelope struct {
	FetchedAt time.Time `json:"fetchedAt"`
	Vulns     []Vuln    `json:"vulns"`
}

// cachePath reuses cache.Component (sanitized + hash-suffixed) per the
// key-to-path invariant, so scoped/underscore/case-variant names cannot
// alias to one another's advisory data.
func cachePath(cacheRoot, osvEco, name, version string) string {
	return filepath.Join(cacheRoot, "osv",
		cache.Component(osvEco), cache.Component(name), cache.Component(version)+".json")
}

func readCache(cacheRoot, osvEco, name, version string) ([]Vuln, time.Time, bool) {
	if cacheRoot == "" {
		return nil, time.Time{}, false
	}
	b, err := os.ReadFile(cachePath(cacheRoot, osvEco, name, version))
	if err != nil {
		return nil, time.Time{}, false
	}
	var env cacheEnvelope
	if json.Unmarshal(b, &env) != nil {
		return nil, time.Time{}, false
	}
	if time.Since(env.FetchedAt) > cacheTTL {
		return nil, time.Time{}, false
	}
	return env.Vulns, env.FetchedAt, true
}

func writeCache(cacheRoot, osvEco, name, version string, vulns []Vuln, fetchedAt time.Time) {
	if cacheRoot == "" {
		return
	}
	p := cachePath(cacheRoot, osvEco, name, version)
	if os.MkdirAll(filepath.Dir(p), 0o755) != nil {
		return
	}
	b, err := json.Marshal(cacheEnvelope{FetchedAt: fetchedAt, Vulns: vulns})
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".osv-*")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return
	}
	tmp.Close()
	os.Rename(tmp.Name(), p)
}
