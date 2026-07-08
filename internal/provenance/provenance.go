// Package provenance assembles publish/anomaly facts about a package version
// for the security lens: the account-takeover-republish threat (xz, event-
// stream, tj-actions). The high-signal parts are DELTAS vs the package's own
// history (maintainer changed, size jumped, provenance dropped), which a
// compromise disturbs; the rest is context. Facts and anomaly flags only,
// never a verdict, a clean provenance panel is NOT proof of safety.
package provenance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/rvagg/depsound/internal/depsdev"
	"github.com/rvagg/depsound/internal/version"
)

// ddSystem maps to deps.dev's system name. Unlike the :dependencies endpoint
// (Go 404s), GetVersion/GetProject cover Go too.
var ddSystem = map[string]string{"npm": "npm", "crates": "cargo", "go": "go"}

// Result is the provenance panel: facts plus the anomaly flags (the signal).
type Result struct {
	Queried bool `json:"queried"`

	PublishedAt   string `json:"publishedAt,omitempty"`
	AgeDays       int    `json:"ageDays,omitempty"`
	Freshness     string `json:"freshness,omitempty"` // under-day | fresh | "" (the takeover risk window)
	PrevVersion   string `json:"prevVersion,omitempty"`
	GapDays       int    `json:"gapDays,omitempty"`
	DormancyBreak bool   `json:"dormancyBreak,omitempty"` // released after a long silence

	Publisher         string `json:"publisher,omitempty"`
	MaintainerChanged bool   `json:"maintainerChanged,omitempty"` // publisher differs from the prior version's

	Attestation        bool `json:"attestation,omitempty"`        // npm provenance present
	AttestationDropped bool `json:"attestationDropped,omitempty"` // prior version had one, this does not

	// install-script DELTA vs the prior version: a script that runs on `npm
	// install` APPEARING (or changing) is the event-stream/xz mechanism, the
	// highest-value shape signal.
	InstallScriptsAdded   []string `json:"installScriptsAdded,omitempty"`
	InstallScriptsChanged []string `json:"installScriptsChanged,omitempty"`

	ClaimedRepo  string `json:"claimedRepo,omitempty"`  // the package's own repository field
	SourceRepo   string `json:"sourceRepo,omitempty"`   // deps.dev's view
	RepoMismatch bool   `json:"repoMismatch,omitempty"` // claimed != source

	Size     int64 `json:"size,omitempty"`
	PrevSize int64 `json:"prevSize,omitempty"`
	SizeJump bool  `json:"sizeJump,omitempty"`

	Deprecated bool `json:"deprecated,omitempty"`
	Yanked     bool `json:"yanked,omitempty"`

	Stars        int      `json:"stars,omitempty"`
	Scorecard    float64  `json:"scorecard,omitempty"`
	ScorecardLow []string `json:"scorecardLow,omitempty"` // checks scoring low
	Note         string   `json:"note,omitempty"`
}

// Assess assembles the provenance for eco:name@ver. prevVer is the baseline
// the deltas are measured against: pass "" (census) to auto-detect the
// immediately-prior published version, or the diff's `from` so a bump's
// deltas read across exactly the versions under review. Never errors, a
// security lookup that fails must not block a review; Queried reports whether
// anything came back.
func Assess(ctx context.Context, eco, name, ver, prevVer string) *Result {
	r := &Result{}
	client := &http.Client{}

	if sys, ok := ddSystem[eco]; ok {
		if vi, err := depsdev.Version(ctx, client, sys, name, ver); err == nil && vi != nil {
			r.Queried = true
			if !vi.PublishedAt.IsZero() {
				r.PublishedAt = vi.PublishedAt.UTC().Format("2006-01-02")
				r.AgeDays = int(time.Since(vi.PublishedAt).Hours() / 24)
			}
			r.Deprecated = vi.Deprecated
			r.SourceRepo = trimRepo(vi.SourceRepo)
			if pi, err := depsdev.Project(ctx, client, r.SourceRepo); err == nil && pi != nil {
				r.Stars = pi.Stars
				r.Scorecard = pi.ScorecardOverall
				r.ScorecardLow = lowChecks(pi.ScorecardChecks)
			}
		}
	}

	switch eco {
	case "npm":
		assessNPM(ctx, client, name, ver, prevVer, r)
	case "crates":
		assessCrates(ctx, client, name, ver, prevVer, r)
	case "go":
		r.Note = "Go has no publisher/provenance (module path IS the repo; sumdb/zip-vs-tag is the anchor), so only cadence + scorecard apply"
	}

	r.RepoMismatch = repoMismatch(r.ClaimedRepo, r.SourceRepo)
	r.Freshness = freshnessTier(r.AgeDays, r.PublishedAt != "")
	if r.GapDays > 365 {
		r.DormancyBreak = true
	}
	if r.PrevSize > 0 && r.Size >= r.PrevSize*2 && r.Size-r.PrevSize > 20<<10 {
		r.SizeJump = true
	}
	return r
}

// --- npm -------------------------------------------------------------------

func assessNPM(ctx context.Context, client *http.Client, name, ver, prevVer string, r *Result) {
	var doc struct {
		Repository json.RawMessage            `json:"repository"`
		Time       map[string]string          `json:"time"`
		Versions   map[string]json.RawMessage `json:"versions"`
	}
	if err := getJSON(ctx, client, "https://registry.npmjs.org/"+url.PathEscape(name), &doc); err != nil {
		return
	}
	r.Queried = true
	r.ClaimedRepo = repoURL(doc.Repository)

	type npmVer struct {
		Publisher struct {
			Name string `json:"name"`
		} `json:"_npmUser"`
		Deprecated json.RawMessage   `json:"deprecated"`
		Scripts    map[string]string `json:"scripts"`
		Dist       struct {
			UnpackedSize int64           `json:"unpackedSize"`
			Attestations json.RawMessage `json:"attestations"`
		} `json:"dist"`
	}
	cur := parseNpmVer[npmVer](doc.Versions[ver])
	if cur != nil {
		r.Publisher = cur.Publisher.Name
		r.Size = cur.Dist.UnpackedSize
		r.Attestation = len(cur.Dist.Attestations) > 0
		r.Deprecated = r.Deprecated || len(cur.Deprecated) > 0
	}
	// dormancy is a property of THIS release vs its immediate predecessor, not
	// of the diff baseline (which may skip intermediate releases), so measure
	// the cadence gap against the immediate predecessor always
	imm := prevPublished(doc.Time, ver)
	if imm != "" {
		r.GapDays = gapDays(doc.Time[imm], doc.Time[ver])
	}
	// deltas (size, publisher, attestation, install scripts) are measured
	// against the requested baseline: the diff's `from`, else the predecessor
	prev := prevVer
	if prev == "" {
		prev = imm
	}
	if prev != "" && prev != ver {
		r.PrevVersion = prev
		if pv := parseNpmVer[npmVer](doc.Versions[prev]); pv != nil {
			r.PrevSize = pv.Dist.UnpackedSize
			if cur != nil && cur.Publisher.Name != "" && pv.Publisher.Name != "" {
				r.MaintainerChanged = cur.Publisher.Name != pv.Publisher.Name
			}
			// the high-value delta: a version that stopped carrying the
			// provenance its predecessor had (published off the trusted pipeline)
			if cur != nil && !r.Attestation && len(pv.Dist.Attestations) > 0 {
				r.AttestationDropped = true
			}
			if cur != nil {
				r.InstallScriptsAdded, r.InstallScriptsChanged = installScriptDelta(pv.Scripts, cur.Scripts)
			}
		}
	}
}

// --- crates ----------------------------------------------------------------

func assessCrates(ctx context.Context, client *http.Client, name, ver, prevVer string, r *Result) {
	var doc struct {
		Crate struct {
			Repository string `json:"repository"`
		} `json:"crate"`
		Versions []struct {
			Num         string `json:"num"`
			CreatedAt   string `json:"created_at"`
			Yanked      bool   `json:"yanked"`
			CrateSize   int64  `json:"crate_size"`
			PublishedBy struct {
				Login string `json:"login"`
			} `json:"published_by"`
		} `json:"versions"`
	}
	if err := getJSON(ctx, client, "https://crates.io/api/v1/crates/"+url.PathEscape(name), &doc); err != nil {
		return
	}
	r.Queried = true
	r.ClaimedRepo = trimRepo(doc.Crate.Repository)

	// versions are newest-first; find this one and the one published before it
	idx := -1
	for i, v := range doc.Versions {
		if v.Num == ver {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	cur := doc.Versions[idx]
	r.Publisher = cur.PublishedBy.Login
	r.Size = cur.CrateSize
	r.Yanked = cur.Yanked

	// dormancy: gap to the immediate predecessor (newest-first, so idx+1),
	// a property of this release regardless of the diff baseline
	if idx+1 < len(doc.Versions) {
		r.GapDays = gapDays(doc.Versions[idx+1].CreatedAt, cur.CreatedAt)
	}
	// deltas: vs the explicit prevVer (diff's `from`) else the predecessor
	prevIdx := idx + 1
	if prevVer != "" {
		prevIdx = -1
		for i, v := range doc.Versions {
			if v.Num == prevVer {
				prevIdx = i
				break
			}
		}
	}
	if prevIdx >= 0 && prevIdx < len(doc.Versions) && prevIdx != idx {
		prev := doc.Versions[prevIdx]
		r.PrevVersion = prev.Num
		r.PrevSize = prev.CrateSize
		if cur.PublishedBy.Login != "" && prev.PublishedBy.Login != "" {
			r.MaintainerChanged = cur.PublishedBy.Login != prev.PublishedBy.Login
		}
	}
}

// --- helpers ---------------------------------------------------------------

// freshnessTier flags a very recent publish, the window in which a malicious
// republish is live before the ecosystem catches and yanks it. Graduated:
// under-day (<24h) is hotter than fresh (1-2 days). Empty when older or when
// the publish date is unknown.
func freshnessTier(ageDays int, hasDate bool) string {
	switch {
	case !hasDate:
		return ""
	case ageDays == 0:
		return "under-day"
	case ageDays <= 2:
		return "fresh"
	}
	return ""
}

// installHooks are the npm lifecycle scripts that run on `npm install <pkg>`,
// so a new one is code newly executing on every consumer's machine.
var installHooks = []string{"preinstall", "install", "postinstall"}

// installScriptDelta reports install hooks that APPEARED (present now, absent
// before) or CHANGED command, comparing the prior version to this one.
func installScriptDelta(prev, cur map[string]string) (added, changed []string) {
	for _, h := range installHooks {
		c, hasC := cur[h]
		p, hasP := prev[h]
		switch {
		case hasC && !hasP:
			added = append(added, h)
		case hasC && hasP && c != p:
			changed = append(changed, h)
		}
	}
	return added, changed
}

func parseNpmVer[T any](raw json.RawMessage) *T {
	if len(raw) == 0 {
		return nil
	}
	var v T
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return &v
}

// prevPublished returns the version published immediately before ver, by
// timestamp (npm's time map is not version-ordered).
func prevPublished(times map[string]string, ver string) string {
	target, ok := times[ver]
	if !ok {
		return ""
	}
	tt, err := time.Parse(time.RFC3339, target)
	if err != nil {
		return ""
	}
	best, bestT := "", time.Time{}
	for v, ts := range times {
		if v == ver || v == "created" || v == "modified" {
			continue
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil || !t.Before(tt) {
			continue
		}
		if t.After(bestT) {
			best, bestT = v, t
		}
	}
	return best
}

func gapDays(from, to string) int {
	f, err1 := time.Parse(time.RFC3339, from)
	t, err2 := time.Parse(time.RFC3339, to)
	if err1 != nil || err2 != nil {
		return 0
	}
	return int(t.Sub(f).Hours() / 24)
}

// scorecardSignal is the subset of OpenSSF checks that bear on the supply-
// chain-takeover question. The rest (Fuzzing, CII-Best-Practices, SAST,
// Security-Policy, Packaging, License) are hygiene, not signal, and popular
// healthy packages routinely score them low, so surfacing them is noise.
var scorecardSignal = map[string]bool{
	"Dangerous-Workflow": true, // an exploitable CI workflow
	"Binary-Artifacts":   true, // committed, unreviewable binaries
	"Maintained":         true, // abandonment risk
	"Code-Review":        true, // changes land unreviewed (takeover surface)
}

func lowChecks(checks map[string]int) []string {
	var low []string
	for name, score := range checks {
		if scorecardSignal[name] && score >= 0 && score < 5 { // -1 = not applicable
			low = append(low, fmt.Sprintf("%s=%d", name, score))
		}
	}
	sort.Strings(low)
	return low
}

func repoMismatch(claimed, source string) bool {
	if claimed == "" || source == "" {
		return false
	}
	return trimRepo(claimed) != trimRepo(source)
}

func trimRepo(u string) string {
	u = strings.TrimSuffix(u, ".git")
	u = strings.TrimPrefix(u, "git+")
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "ssh://git@")
	u = strings.TrimPrefix(u, "git@")
	u = strings.ReplaceAll(u, "github.com:", "github.com/")
	return strings.TrimSuffix(u, "/")
}

// repoURL extracts the url from an npm repository field, which is either a
// string or an object {type,url}.
func repoURL(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return trimRepo(s)
	}
	var o struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(raw, &o) == nil {
		return trimRepo(o.URL)
	}
	return ""
}

func getJSON(ctx context.Context, client *http.Client, u string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
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
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(v)
}
