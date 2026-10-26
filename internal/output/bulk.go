package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/stats"
)

// BulkResult pairs a dependency-change reference with its analysis, or an
// error if analysis failed. Ref is a display label, not a shell argument. A
// bump has Stats (a diff). A newly added dependency has a Census of its whole
// footprint because there is no earlier version to diff; it adds unreviewed
// surface and must not disappear from the report.
type BulkResult struct {
	Ref        string               `json:"ref"`
	Stats      *stats.Stats         `json:"stats,omitempty"`
	Census     *Census              `json:"census,omitempty"`
	LockChange *manifest.LockChange `json:"lockChange,omitempty"`
	// Redirect names the non-registry source a dependency (Ref) is pointed at
	// by a replace/patch/override: a fork, git URL, or local path. It is a
	// FACT-grade signal from the declaration itself. No artifact is fetched, so
	// this result has neither Stats nor Census.
	Redirect string `json:"redirect,omitempty"`
	// Unavailable is a classified acquisition failure (the artifact could not be
	// fetched): absent/denied/transient, preserving URL and status.
	Unavailable *Unavailable `json:"unavailable,omitempty"`
	// Note is a benign no-action finding (e.g. two ranges resolving to the
	// same version): information, never a failure and never a flag.
	Note string `json:"note,omitempty"`
	Err  string `json:"error,omitempty"`
}

// digest is the low-level Stats->signals extractor Derive wraps into the typed
// ledger (exec surface, generated-delta, compat). It is no longer a renderer
// engine; OSV lives in the ledger derivation directly.
type digest struct {
	exec     bool
	execWhat []string
	// registryExec marks a surface that runs on an ordinary registry install;
	// nonRegistryOnly marks one that needs a git/link/file source. A change
	// with only the latter must not read as "code runs when you install this".
	registryExec    bool
	nonRegistryOnly bool
	compat          bool
	genFile         string // biggest unreviewed generated/binary file, if a large delta
	genDelta        int
}

// addExec records a build-execution surface as a pointer, distinguishing
// INTRODUCED (louder) from present-in-both (the code it executes may still
// have changed). Absent in both versions records nothing.
func (d *digest) addExec(name string, from, to bool) {
	switch {
	case !from && to:
		d.exec = true
		d.registryExec = true
		d.execWhat = append(d.execWhat, name+" INTRODUCED")
	case from && to:
		d.exec = true
		d.registryExec = true
		d.execWhat = append(d.execWhat, name+" present (build code may have changed)")
	}
}

// Bulk renders the aggregate: a rollup of which deps trip which signals
// (execution surface / compat / security) first, then a per-dep table.
// Signals are facts, not verdicts; the single-pair command gives detail.
func Bulk(results []BulkResult) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("depsound bulk: %d dependency changes considered.", len(results))
	w("this is a router: a fired signal is a pointer to inspect, not a summary.")
	w("for version changes: depsound <eco>:<name> <from> <to>  (now instant, cached)")
	writeRouter(w, results, false, nil, nil)
	return b.String()
}

// bulkSection is one router section: the ledger codes it collects and its
// title. Every diff-signal code has a home here; census/redirect/failure render
// as their own blocks. A new signal code without a section fails renderer parity.
type bulkSection struct {
	codes []Code
	title string
}

var bulkSections = []bulkSection{
	{[]Code{CodeMalwareAdvisory}, "malicious-package advisory matches a reviewed version (not a flaw to upgrade past)"},
	{[]Code{CodeArtifactAbsent}, "artifact unavailable (registry metadata or URL absent; contents not inspected)"},
	{[]Code{CodeHostileEntry}, "hostile archive member(s) skipped (traversal/absolute/control-byte name: an attack-shaped artifact)"},
	{[]Code{CodeProvenanceAnomaly}, "provenance anomaly: account-takeover shape (publisher shift, attestation dropped or attesting elsewhere, yank)"},
	{[]Code{CodeRepoMismatch}, "claimed repo differs from the registry source repo (often a rename or redirect; confirm which is current)"},
	{[]Code{CodeProvenanceGap}, "coverage gap: provenance or maintenance metadata incomplete (a source lookup failed)"},
	{[]Code{CodeRetracted}, "reviewed Go module version is retracted (current latest go.mod metadata)"},
	{[]Code{CodeDeprecated}, "dependency deprecated (current maintenance metadata, not compromise)"},
	{[]Code{CodeUnreviewable}, "structurally unreviewable mass (generated/binary dominates the artifact bytes)"},
	{[]Code{CodeRangeResolved}, "endpoints resolved from a range at review time (one satisfying version reviewed)"},
	{[]Code{CodeArtifactDenied}, "coverage gap: artifact access denied (auth/policy)"},
	{[]Code{CodeArtifactFetch}, "coverage gap: artifact fetch failed (transient)"},
	{[]Code{CodeRegistryChecksum}, "registry checksum index observations"},
	{[]Code{CodeExecIntroduced, CodeCensusExec}, "build/install execution surface"},
	{[]Code{CodeLockSource}, "declared lockfile source, integrity, or version changes"},
	{[]Code{CodeCensusCVE}, "known vulnerabilities at an exact registry target"},
	{[]Code{CodeAnalysisFailed}, "analysis failed (coverage gap)"},
	{[]Code{CodeExecPresent}, "build/install execution surface present, its build code may have changed"},
	{[]Code{CodeNonRegistryDep}, "declares dependencies served from outside the registry (a trusted name pulling code from elsewhere)"},
	{[]Code{CodeExecGitOnly}, "hooks that run only for a git/link/file dependency (a registry install does not run them)"},
	{[]Code{CodeBinaryAdded}, "binary/opaque file(s) added (zero line delta, an ideal payload channel; ranked by bytes)"},
	{[]Code{CodeBinaryChanged}, "binary/opaque file(s) changed (zero line delta; ranked by byte delta)"},
	{[]Code{CodeGeneratedDelta}, "large unreviewed generated/binary change (payload can hide here)"},
	{[]Code{CodeGHARefMoved}, "GitHub Actions ref re-pointed to a different commit since last fetch"},
	{[]Code{CodeGHAPinWeakened}, "GitHub Actions pin weakened (the re-point enabling move)"},
	{[]Code{CodeGHAPinGrade}, "GitHub Actions pin grade (mutable/unpinned standing context)"},
	{[]Code{CodeGHAPinRaised}, "GitHub Actions pin strengthened"},
	{[]Code{CodeGHACaps}, "GitHub Actions runner capability introduced by the bump"},
	{[]Code{CodeOSVIntroduced}, "vulnerabilities introduced by the upgrade"},
	{[]Code{CodeOSVStill}, "vulnerabilities still present after the upgrade (bump did not fix them)"},
	{[]Code{CodeGHAUsing}, "GitHub Actions runtime changed (may raise the minimum runner version)"},
	{[]Code{CodeBinDelta}, "installed executable (bin) entries changed (a new or re-pointed command on PATH)"},
	{[]Code{CodeCompatChange}, "compatibility changes"},
	{[]Code{CodeExportsUnresolved}, "coverage gap: exports/resolution compatibility could not be computed"},
	{[]Code{CodeSkippedLink}, "coverage gap: symlink/hardlink(s) not materialized (contents not inspected)"},
	{[]Code{CodeIntegrityWeak}, "coverage gap: artifact verified by TLS trust only (no registry integrity or checksum-DB record)"},
	{[]Code{CodeOSVDisabled, CodeOSVFailed}, "coverage gap: known-advisory scan did not complete for these deps"},
	{[]Code{CodeOSVFixed}, "advisories fixed by the upgrade (the merge argument)"},
	{[]Code{CodeProvenanceHardened}, "trusted publishing adopted (a mechanism, not release approval)"},
	{[]Code{CodeNoContentChange}, "no content change: the version moved, what installs did not"},
	{[]Code{CodeOSVUnsupported}, "note: known-advisory scan not applicable (OSV has no index for this ecosystem)"},
}

// provenanceGap phrases the coverage footer's provenance/maintenance-metadata
// entry: empty when every diffed dep had full coverage, the whole gap when none
// did, and an N-of-M count when partial. One dep answering must never clear the
// gap for the rest.
func provenanceGap(results []BulkResult) string {
	total, complete := 0, 0
	for _, r := range results {
		var answered bool
		switch {
		case r.Stats != nil:
			answered = r.Stats.Provenance != nil && r.Stats.Provenance.Complete()
		case r.Census != nil:
			answered = r.Census.Provenance != nil && r.Census.Provenance.Complete()
		default:
			continue
		}
		total++
		if answered {
			complete++
		}
	}
	return provenanceGapCounts(total, complete)
}

func provenanceGapCounts(total, complete int) string {
	switch {
	case total == 0 || complete == 0:
		return "provenance and maintenance metadata"
	case complete == total:
		return ""
	default:
		return fmt.Sprintf("provenance and maintenance metadata (%d of %d changes)", total-complete, total)
	}
}

type routerCoverage struct {
	reports, artifacts, unavailable, lockChanges, sourceOnlyBaselines, censusReports int
	osvRan, osvMissing, osvNA                                                        int
	provenanceComplete                                                               int
}

func (c *routerCoverage) include(r *BulkResult) {
	if r.LockChange != nil {
		c.lockChanges++
		if r.LockChange.ToRegistry {
			c.sourceOnlyBaselines++
		}
	}
	switch {
	case r.Stats != nil:
		s := r.Stats
		c.report(s.Package.Ecosystem, s.Security.Queried, len(s.Artifact.Unavailable),
			s.Provenance != nil && s.Provenance.Complete())
	case r.Census != nil:
		s := r.Census
		failures := 0
		if s.Unavailable != nil {
			failures = 1
		}
		c.censusReports++
		c.report(s.Ecosystem, s.OSVQueried, failures, s.Provenance != nil && s.Provenance.Complete())
	case r.Unavailable != nil:
		c.unavailable++
	}
}

func (c *routerCoverage) report(eco string, queried bool, unavailable int, provenanceComplete bool) {
	c.reports++
	if unavailable > 0 {
		c.unavailable += unavailable
	} else {
		c.artifacts++
	}
	switch {
	case queried:
		c.osvRan++
	case !osvSupported(eco):
		c.osvNA++
	default:
		c.osvMissing++
	}
	if provenanceComplete {
		c.provenanceComplete++
	}
}

// writeRouter renders the prioritised signal sections + coverage boundary over
// a set of analysed deps, entirely from the shared ledger (so it surfaces every
// fact markdown does; digestOf is now an internal input to Derive, not a second
// engine). Shared by bulk and transitive (the transitive changed-module set IS
// a bulk list); transitive adjusts the coverage line that would otherwise
// wrongly claim the transitive graph is unchecked.
func writeRouter(w func(string, ...any), results []BulkResult, transitive bool, added, removed []ModuleRef) {
	var failed, redirects, newDeps, targetCensuses, clean []BulkResult
	type sigEntry struct {
		ref string
		sig Signal
	}
	buckets := map[Code][]sigEntry{}
	var coverage routerCoverage
	for _, modules := range [][]ModuleRef{added, removed} {
		for _, module := range modules {
			if module.Analysis != nil {
				coverage.include(module.Analysis)
			}
		}
	}
	for _, r := range results {
		coverage.include(&r)
		switch {
		case r.Redirect != "":
			redirects = append(redirects, r)
			continue
		case r.Note != "":
			for _, sig := range DeriveBenign(r.Ref, r.Note).Signals {
				buckets[sig.Code] = append(buckets[sig.Code], sigEntry{r.Ref, sig})
			}
			continue
		}
		if r.Census != nil {
			if r.LockChange != nil {
				targetCensuses = append(targetCensuses, r)
			} else {
				newDeps = append(newDeps, r)
			}
		}
		l := DeriveBulkResult(r)
		if len(l.Signals) == 0 {
			if r.Stats != nil {
				clean = append(clean, r)
			} else {
				failed = append(failed, r)
			}
			continue
		}
		for _, sig := range l.Signals {
			buckets[sig.Code] = append(buckets[sig.Code], sigEntry{r.Ref, sig})
		}
	}

	// a redirect (a trusted name served from elsewhere) is the loudest
	if len(redirects) > 0 {
		w("")
		w("dependency redirected off the registry (fork/git/local: trust-laundering shape):")
		for _, r := range redirects {
			w("  %s  -> %s", EscapeText(r.Ref), EscapeText(r.Redirect))
		}
	}
	// diff signals in priority order, from the ledger
	for _, sec := range bulkSections {
		var ents []sigEntry
		for _, code := range sec.codes {
			ents = append(ents, buckets[code]...)
		}
		if len(ents) == 0 {
			continue
		}
		w("")
		w("%s:", sec.title)
		for _, e := range ents {
			line := EscapeText(e.sig.Title)
			if detail := signalDetail(e.sig, EscapeText); detail != "" {
				line += ": " + detail
			}
			w("  %s  %s", EscapeText(e.ref), line)
		}
	}
	if len(newDeps) > 0 {
		w("")
		w("new dependencies (whole footprint unreviewed; adopt-review, not a diff):")
		for _, r := range newDeps {
			w("  %s  %s", EscapeText(r.Ref), censusFootprint(r.Census))
		}
	}
	if len(targetCensuses) > 0 {
		w("")
		w("canonical registry targets (source-only baseline not inspected; target footprint, not a diff):")
		for _, r := range targetCensuses {
			w("  %s  %s", EscapeText(r.Ref), censusFootprint(r.Census))
		}
	}
	if len(clean) > 0 {
		w("")
		w("no flags raised (%d): NOT the same as safe. These were not assessed", len(clean))
		w("for reachability, semantics, intent, or test coverage, a starting point:")
		for _, r := range clean {
			w("  %s", EscapeText(r.Ref))
		}
	}
	if len(failed) > 0 {
		w("")
		w("failed (not analysed):")
		for _, r := range failed {
			w("  %s: %s", EscapeText(r.Ref), EscapeText(r.Err))
		}
	}

	// coverage boundary once, at the aggregate (same for every dep); the
	// anti-false-security spine, proportionate to a router (one block, not
	// repeated per dep). CVE scan is named backward-looking, not "security"
	w("")
	w("=== coverage: heuristic triage, NOT a verdict ===")
	switch {
	case coverage.reports == 0 && coverage.unavailable == 0:
		if coverage.lockChanges > 0 {
			w("checked: %d lockfile metadata declaration(s); no artifacts inspected or advisory scans run.", coverage.lockChanges)
		} else if transitive {
			w("checked: dependency graph and name/version changes; no artifacts inspected.")
		} else {
			w("checked: routing outcomes only; no artifacts inspected.")
		}
	case coverage.artifacts > 0 && coverage.unavailable > 0:
		w("checked: %d artifact report(s): diff/footprint, file classes, manifest compat, execution surface; %d acquisition failure(s): status only.", coverage.artifacts, coverage.unavailable)
	case coverage.artifacts > 0:
		w("checked: artifact diff/footprint, file classes, manifest compat, execution surface.")
	default:
		w("checked: artifact acquisition status only; contents were not inspected.")
	}
	if coverage.sourceOnlyBaselines > 0 {
		w("  source-only baseline declarations: %d; their baseline contents were not fetched or advisory-scanned.", coverage.sourceOnlyBaselines)
	}
	// OSV status is derived from what actually ran, not asserted flat: a
	// disabled/failed scan is a gap, an unsupported ecosystem is not.
	if coverage.reports > 0 {
		var st []string
		if coverage.osvRan > 0 {
			st = append(st, fmt.Sprintf("run for %d", coverage.osvRan))
		}
		if coverage.osvMissing > 0 {
			st = append(st, fmt.Sprintf("not run or incomplete for %d", coverage.osvMissing))
		}
		if coverage.osvNA > 0 {
			st = append(st, fmt.Sprintf("not applicable for %d (ecosystem unsupported)", coverage.osvNA))
		}
		w("  known-advisory scan (OSV, backward-looking; blind to novel/unreported code): %s.", strings.Join(st, "; "))
	}
	if transitive {
		w("NOT checked: does your code reach each change; what changed inside added modules;")
		w(" runtime semantics; test coverage; whatever the lockfile itself omits (pruned,")
		w(" test-only or platform-conditional). Added modules were censused at the")
		w(" resolved version, not diffed. Silence != safe.")
		if g := provenanceGapCounts(coverage.reports, coverage.provenanceComplete); g != "" {
			w("  NOT checked: %s.", g)
		}
	} else {
		prov := ""
		if g := provenanceGapCounts(coverage.reports, coverage.provenanceComplete); g != "" {
			prov = "; " + g
		}
		w("NOT checked: does your code reach each change; what it does; test coverage;")
		if coverage.unavailable > 0 {
			w(" unavailable artifact contents;")
		}
		w(" transitive deps these bumps pull in%s. Silence != safe.", prov)
	}
	if coverage.artifacts > 0 && coverage.censusReports == 0 {
		w("next: for each dep you rely on, intersect the diff with your usage ->")
		w(" depsound surface <eco>:<name> <from> <to> --uses=<your imports>")
	} else if coverage.artifacts > 0 {
		w("next: inspect each registry target footprint and its declared acquisition metadata.")
	} else if coverage.unavailable > 0 {
		w("next: obtain the exact artifact from a source you trust, such as a registry operator;")
		w(" for crates, re-run with --from-artifact/--to-artifact or --artifact.")
	} else if coverage.lockChanges > 0 {
		w("next: inspect both declared lockfile entries and confirm the intended registry, mirror or local link.")
	} else {
		w("next: inspect the dependency declarations and graph changes -> depsound guide")
	}
}

func digestOf(s *stats.Stats) digest {
	d := digest{
		compat: s.Compat.TypeFrom != s.Compat.TypeTo || len(s.Compat.Constraints) > 0 || len(s.Compat.Exports) > 0,
	}
	r := s.Runnable
	// the two hook sets are separated upstream by activation path, because only
	// one of them runs when a consumer installs this from the registry
	for _, c := range r.Lifecycle {
		d.exec, d.registryExec = true, true
		d.execWhat = append(d.execWhat, "lifecycle "+c.Key+" "+c.Status)
	}
	for _, c := range r.LifecycleGitOnly {
		d.exec, d.nonRegistryOnly = true, true
		d.execWhat = append(d.execWhat, "lifecycle "+c.Key+" "+c.Status+" (git/non-registry installs only)")
	}
	// execution surface fires on PRESENCE, not only introduction: a build
	// surface present in both versions (cgo true->true) still executes the
	// code that changed, so it must not read as "no flags" in bulk the way
	// it did before. INTRODUCED is the louder tier.
	d.addExec("binding.gyp", r.GypFrom, r.GypTo)
	d.addExec("cgo", r.CgoFrom, r.CgoTo)
	d.addExec("build.rs", r.BuildRSFrom, r.BuildRSTo)
	d.addExec("proc-macro", r.ProcMacroFrom, r.ProcMacroTo)
	// a big generated/binary delta is unreviewed surface where a payload can
	// hide (npm dist/, vendored C); flag it even without a build surface
	if big := largestGenerated(s.Files.Entries); big.Added+big.Removed >= 100 {
		d.genFile = big.Path
		d.genDelta = big.Added + big.Removed
	}
	sort.Strings(d.execWhat)
	return d
}

// malicious and vulnsOnly separate malicious-package records from vulnerability
// records, which require different incident-response or patch advice.
func malicious(sets ...[]osv.Vuln) []osv.Vuln {
	var out []osv.Vuln
	seen := map[string]bool{}
	for _, set := range sets {
		for _, v := range set {
			if v.Malicious() && !seen[v.ID] {
				seen[v.ID] = true
				out = append(out, v)
			}
		}
	}
	return out
}

func vulnsOnly(set []osv.Vuln) []osv.Vuln {
	var out []osv.Vuln
	for _, v := range set {
		if !v.Malicious() {
			out = append(out, v)
		}
	}
	return out
}

func joinVulnIDs(vulns []osv.Vuln, max int) string {
	var ids []string
	for i, v := range vulns {
		if i >= max {
			ids = append(ids, fmt.Sprintf("+%d more", len(vulns)-max))
			break
		}
		id := v.ID
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				id = a
				break
			}
		}
		ids = append(ids, id)
	}
	return strings.Join(ids, ", ")
}
