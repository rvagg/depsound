// Package provenance assembles publish/anomaly facts about a package version
// for the security lens: the account-takeover-republish threat (xz, event-
// stream, tj-actions). The high-signal parts are DELTAS vs the package's own
// history (maintainer changed, size jumped, provenance dropped), which a
// compromise disturbs; the rest is context. Facts and anomaly flags only,
// never a verdict, a clean provenance panel is NOT proof of safety.
package provenance

import (
	"context"
	"encoding/base64"
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
	// Sources records each source's outcome (complete | failed | unsupported)
	// so a partial answer can never read as full coverage: "depsdev" carries
	// cadence, source repo and scorecard; "registry" carries publisher,
	// attestation and the delta history. Queried stays true when ANY source
	// answered; consumers needing full coverage check Complete().
	Sources map[string]string `json:"sources,omitempty"`

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
	// AttestedSource is the repo the (npm-validated) provenance attestation
	// says the build ran from; AttestedMismatch flags it differing from the
	// package's own claimed repository, valid provenance from the wrong repo.
	AttestedSource   string `json:"attestedSource,omitempty"`
	AttestedMismatch bool   `json:"attestedMismatch,omitempty"`

	// install-script DELTA vs the prior version: a script that runs on `npm
	// install` APPEARING (or changing) is the event-stream/xz mechanism, the
	// highest-value shape signal.
	InstallScriptsAdded   []string `json:"installScriptsAdded,omitempty"`
	InstallScriptsChanged []string `json:"installScriptsChanged,omitempty"`
	// BinAdded lists CLI commands the package now installs on PATH that a
	// prior version did not (a bin runs only when invoked, not on install).
	BinAdded []string `json:"binAdded,omitempty"`

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
	r := &Result{Sources: map[string]string{}}
	client := &http.Client{}

	if sys, ok := ddSystem[eco]; ok {
		if vi, err := depsdev.Version(ctx, client, sys, name, ver); err == nil && vi != nil {
			r.Queried = true
			r.Sources["depsdev"] = "complete"
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
		} else {
			r.Sources["depsdev"] = "failed"
		}
	} else {
		r.Sources["depsdev"] = "unsupported"
	}

	switch eco {
	case "npm":
		r.Sources["registry"] = sourceState(assessNPM(ctx, client, name, ver, prevVer, r))
	case "crates":
		r.Sources["registry"] = sourceState(assessCrates(ctx, client, name, ver, prevVer, r))
	case "go":
		r.Sources["registry"] = "unsupported"
		r.Note = "Go has no publisher/provenance (module path IS the repo; sumdb/zip-vs-tag is the anchor), so only cadence + scorecard apply"
	default:
		r.Sources["registry"] = "unsupported"
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

func sourceState(ok bool) string {
	if ok {
		return "complete"
	}
	return "failed"
}

// sourceScope names what a source carries, so a failure states exactly which
// coverage was lost.
var sourceScope = map[string]string{
	"depsdev":  "cadence, source repo, scorecard",
	"registry": "publisher, attestation, install-script/bin deltas",
}

// FailedSources lists the sources that errored, with what each carries.
// Unsupported sources are excluded: a source that does not exist for the
// ecosystem is not lost coverage.
func (r *Result) FailedSources() []string {
	var out []string
	for _, src := range []string{"depsdev", "registry"} {
		if r.Sources[src] == "failed" {
			out = append(out, src+" ("+sourceScope[src]+")")
		}
	}
	return out
}

// Complete reports whether every applicable source answered: the bar for a
// coverage claim ("provenance checked"). Queried alone means only that
// SOMETHING answered.
func (r *Result) Complete() bool {
	if !r.Queried {
		return false
	}
	for _, state := range r.Sources {
		if state == "failed" {
			return false
		}
	}
	return true
}

// --- npm -------------------------------------------------------------------

func assessNPM(ctx context.Context, client *http.Client, name, ver, prevVer string, r *Result) bool {
	var doc struct {
		Repository json.RawMessage            `json:"repository"`
		Time       map[string]string          `json:"time"`
		Versions   map[string]json.RawMessage `json:"versions"`
	}
	if err := getJSON(ctx, client, "https://registry.npmjs.org/"+url.PathEscape(name), &doc); err != nil {
		return false
	}
	r.Queried = true
	r.ClaimedRepo = repoURL(doc.Repository)

	type npmVer struct {
		Publisher struct {
			Name string `json:"name"`
		} `json:"_npmUser"`
		Deprecated json.RawMessage   `json:"deprecated"`
		Scripts    map[string]string `json:"scripts"`
		Bin        json.RawMessage   `json:"bin"`
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
		if r.Attestation {
			// read the npm-VALIDATED predicate (no crypto: npm already checked
			// the signature at publish) for its attested source, and flag it
			// differing from the package's own claim
			r.AttestedSource = attestedSource(ctx, client, cur.Dist.Attestations)
			r.AttestedMismatch = r.AttestedSource != "" && r.ClaimedRepo != "" && r.AttestedSource != r.ClaimedRepo
		}
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
				r.BinAdded = addedBins(binNames(pv.Bin, name), binNames(cur.Bin, name))
			}
		}
	}
	return true
}

// --- crates ----------------------------------------------------------------

func assessCrates(ctx context.Context, client *http.Client, name, ver, prevVer string, r *Result) bool {
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
		return false
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
		return true // the registry answered; this version is just not listed
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
	return true
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

// attestedSource reads the source repo from a version's npm provenance
// attestation. The signature is already verified by npm at publish, so this
// only DECODES the validated predicate (base64 DSSE payload -> in-toto
// statement -> SLSA buildDefinition) to surface where it was built from. Empty
// on any failure, so a parse hiccup degrades to "attestation present".
func attestedSource(ctx context.Context, client *http.Client, distAtt json.RawMessage) string {
	var info struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(distAtt, &info) != nil || info.URL == "" {
		return ""
	}
	var resp struct {
		Attestations []struct {
			PredicateType string `json:"predicateType"`
			Bundle        struct {
				DsseEnvelope struct {
					Payload string `json:"payload"`
				} `json:"dsseEnvelope"`
			} `json:"bundle"`
		} `json:"attestations"`
	}
	if err := getJSON(ctx, client, info.URL, &resp); err != nil {
		return ""
	}
	for _, a := range resp.Attestations {
		if !strings.Contains(a.PredicateType, "slsa.dev/provenance") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(a.Bundle.DsseEnvelope.Payload)
		if err != nil {
			continue
		}
		var st struct {
			Predicate struct {
				BuildDefinition struct {
					ExternalParameters struct {
						Workflow struct {
							Repository string `json:"repository"`
						} `json:"workflow"`
					} `json:"externalParameters"`
					ResolvedDependencies []struct {
						URI string `json:"uri"`
					} `json:"resolvedDependencies"`
				} `json:"buildDefinition"`
			} `json:"predicate"`
		}
		if json.Unmarshal(raw, &st) != nil {
			continue
		}
		repo := st.Predicate.BuildDefinition.ExternalParameters.Workflow.Repository
		if repo == "" && len(st.Predicate.BuildDefinition.ResolvedDependencies) > 0 {
			repo = st.Predicate.BuildDefinition.ResolvedDependencies[0].URI
		}
		if repo == "" {
			continue
		}
		repo = trimRepo(repo)
		if i := strings.Index(repo, "@"); i >= 0 {
			repo = repo[:i] // drop a trailing @ref
		}
		return repo
	}
	return ""
}

// binNames reads the package's bin field (a string installs one command named
// after the package; an object maps command names to paths) into the set of
// command names it puts on PATH.
func binNames(raw json.RawMessage, pkgName string) []string {
	if len(raw) == 0 {
		return nil
	}
	var obj map[string]string
	if json.Unmarshal(raw, &obj) == nil {
		names := make([]string, 0, len(obj))
		for k := range obj {
			names = append(names, k)
		}
		sort.Strings(names)
		return names
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		n := pkgName
		if i := strings.LastIndex(n, "/"); i >= 0 {
			n = n[i+1:] // a string bin is named after the package, sans scope
		}
		return []string{n}
	}
	return nil
}

// addedBins returns the command names present now that were absent before.
func addedBins(prev, cur []string) []string {
	was := make(map[string]bool, len(prev))
	for _, b := range prev {
		was[b] = true
	}
	var out []string
	for _, b := range cur {
		if !was[b] {
			out = append(out, b)
		}
	}
	return out
}

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
