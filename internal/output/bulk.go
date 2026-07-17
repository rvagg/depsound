package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/stats"
)

// BulkResult pairs a dependency-change reference with its analysis, or an
// error if it failed. Ref is tool-formed (spec + versions), safe to print. A
// bump carries Stats (a diff); a newly-added dependency carries Census (its
// whole footprint, since there is no prior version to diff): a new dep is
// unreviewed surface, not a delta, and must never be silently absent.
type BulkResult struct {
	Ref    string       `json:"ref"`
	Stats  *stats.Stats `json:"stats,omitempty"`
	Census *Census      `json:"census,omitempty"`
	// Redirect names the non-registry source a dependency (Ref) is pointed at
	// by a replace/patch/override: a fork, git URL, or local path. FACT-grade
	// and needs no fetch, so it carries no Stats/Census; the trust-laundering
	// signal is the redirect itself.
	Redirect string `json:"redirect,omitempty"`
	// Unavailable is a classified acquisition failure (the artifact could not be
	// fetched): absent/denied/transient, preserving URL and status.
	Unavailable *Unavailable `json:"unavailable,omitempty"`
	Err         string       `json:"error,omitempty"`
}

// digest is the low-level Stats->signals extractor Derive wraps into the typed
// ledger (exec surface, generated-delta, compat). It is no longer a renderer
// engine; OSV lives in the ledger derivation directly.
type digest struct {
	exec     bool
	execWhat []string
	compat   bool
	genFile  string // biggest unreviewed generated/binary file, if a large delta
	genDelta int
}

// addExec records a build-execution surface as a pointer, distinguishing
// INTRODUCED (louder) from present-in-both (the code it executes may still
// have changed). Absent in both versions records nothing.
func (d *digest) addExec(name string, from, to bool) {
	switch {
	case !from && to:
		d.exec = true
		d.execWhat = append(d.execWhat, name+" INTRODUCED")
	case from && to:
		d.exec = true
		d.execWhat = append(d.execWhat, name+" present (build code may have changed)")
	}
}

// Bulk renders the aggregate: a rollup of which deps trip which signals
// (execution surface / compat / security) first, then a per-dep table.
// Signals are facts, not verdicts; the single-pair command gives detail.
func Bulk(results []BulkResult) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("depsound bulk: %d dependencies analysed (cached).", len(results))
	w("this is a router: a fired signal is a pointer to inspect, not a summary.")
	w("drill any dep with: depsound <eco>:<name> <from> <to>  (now instant, cached)")
	writeRouter(w, results, false)
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
	{[]Code{CodeArtifactAbsent}, "artifact unavailable (URL not retrievable now; contents not inspected; prior publication not established)"},
	{[]Code{CodeHostileEntry}, "hostile archive member(s) skipped (traversal/absolute/control-byte name: an attack-shaped artifact)"},
	{[]Code{CodeArtifactDenied}, "coverage gap: artifact access denied (auth/policy)"},
	{[]Code{CodeArtifactFetch}, "coverage gap: artifact fetch failed (transient)"},
	{[]Code{CodeExecIntroduced}, "new build/install execution surface introduced"},
	{[]Code{CodeExecPresent}, "build/install execution surface present, its build code may have changed"},
	{[]Code{CodeBinaryAdded}, "binary/opaque file(s) added (zero line delta, an ideal payload channel; ranked by bytes)"},
	{[]Code{CodeBinaryChanged}, "binary/opaque file(s) changed (zero line delta; ranked by byte delta)"},
	{[]Code{CodeGeneratedDelta}, "large unreviewed generated/binary change (payload can hide here)"},
	{[]Code{CodeGHACaps}, "GitHub Actions runner capability introduced by the bump"},
	{[]Code{CodeOSVIntroduced}, "CVEs introduced by the upgrade"},
	{[]Code{CodeOSVStill}, "CVEs still present after the upgrade (bump did not fix them)"},
	{[]Code{CodeGHAUsing}, "GitHub Actions runtime changed (may raise the minimum runner version)"},
	{[]Code{CodeBinDelta}, "installed executable (bin) entries changed (a new or re-pointed command on PATH)"},
	{[]Code{CodeCompatChange}, "compatibility changes"},
	{[]Code{CodeExportsUnresolved}, "coverage gap: exports/resolution compatibility could not be computed"},
	{[]Code{CodeSkippedLink}, "coverage gap: symlink/hardlink(s) not materialized (contents not inspected)"},
	{[]Code{CodeIntegrityWeak}, "coverage gap: artifact verified by TLS trust only (no registry integrity or checksum-DB record)"},
	{[]Code{CodeOSVDisabled, CodeOSVFailed}, "coverage gap: known-CVE scan did not complete for these deps"},
	{[]Code{CodeOSVFixed}, "advisories fixed by the upgrade (the merge argument)"},
	{[]Code{CodeOSVUnsupported}, "note: known-CVE scan not applicable (OSV has no index for this ecosystem)"},
}

// writeRouter renders the prioritised signal sections + coverage boundary over
// a set of analysed deps, entirely from the shared ledger (so it surfaces every
// fact markdown does; digestOf is now an internal input to Derive, not a second
// engine). Shared by bulk and transitive (the transitive changed-module set IS
// a bulk list); transitive adjusts the coverage line that would otherwise
// wrongly claim the transitive graph is unchecked.
func writeRouter(w func(string, ...any), results []BulkResult, transitive bool) {
	var failed, redirects, newDeps, clean []BulkResult
	type sigEntry struct {
		ref string
		sig Signal
	}
	buckets := map[Code][]sigEntry{}
	diffCount := 0 // deps carrying a version diff (the OSV-via-diff denominator)
	for _, r := range results {
		switch {
		case r.Unavailable != nil:
			for _, sig := range DeriveUnavailable(r.Ref, r.Unavailable).Signals {
				buckets[sig.Code] = append(buckets[sig.Code], sigEntry{r.Ref, sig})
			}
		case r.Redirect != "":
			redirects = append(redirects, r)
		case r.Census != nil:
			newDeps = append(newDeps, r)
		case r.Stats == nil:
			failed = append(failed, r)
		default:
			diffCount++
			l := Derive(r.Ref, r.Stats)
			if len(l.Signals) == 0 {
				clean = append(clean, r)
				continue
			}
			for _, sig := range l.Signals {
				buckets[sig.Code] = append(buckets[sig.Code], sigEntry{r.Ref, sig})
			}
		}
	}

	// a redirect (a trusted name served from elsewhere) is the loudest
	if len(redirects) > 0 {
		w("")
		w("dependency redirected off the registry (fork/git/local: trust-laundering shape):")
		for _, r := range redirects {
			w("  %s  -> %s", taint(r.Ref), taint(r.Redirect))
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
			line := e.sig.Title
			if e.sig.Detail != "" {
				line += ": " + e.sig.Detail
			}
			w("  %s  %s", taint(e.ref), taint(line))
		}
	}
	if len(newDeps) > 0 {
		w("")
		w("new dependencies (whole footprint unreviewed; adopt-review, not a diff):")
		for _, r := range newDeps {
			w("  %s  %s", taint(r.Ref), taint(censusFootprint(r.Census)))
		}
	}
	if len(clean) > 0 {
		w("")
		w("no flags raised (%d): NOT the same as safe. These were not assessed", len(clean))
		w("for reachability, semantics, intent, or test coverage, a starting point:")
		for _, r := range clean {
			w("  %s", taint(r.Ref))
		}
	}
	if len(failed) > 0 {
		w("")
		w("failed (not analysed):")
		for _, r := range failed {
			w("  %s: %s", taint(r.Ref), taint(r.Err))
		}
	}

	// coverage boundary once, at the aggregate (same for every dep); the
	// anti-false-security spine, proportionate to a router (one block, not
	// repeated per dep). CVE scan is named backward-looking, not "security"
	w("")
	w("=== coverage: heuristic triage, NOT a verdict ===")
	w("checked: artifact diff, file classes, manifest compat, execution surface.")
	// OSV status is derived from what actually ran, not asserted flat: a
	// disabled/failed scan is a gap, an unsupported ecosystem is not.
	osvGap := len(buckets[CodeOSVDisabled]) + len(buckets[CodeOSVFailed])
	osvNA := len(buckets[CodeOSVUnsupported])
	if diffCount > 0 {
		var st []string
		if ran := diffCount - osvGap - osvNA; ran > 0 {
			st = append(st, fmt.Sprintf("run for %d", ran))
		}
		if osvGap > 0 {
			st = append(st, fmt.Sprintf("did not complete for %d (see the coverage-gap section above)", osvGap))
		}
		if osvNA > 0 {
			st = append(st, fmt.Sprintf("not applicable for %d (ecosystem unsupported)", osvNA))
		}
		w("  known-CVE scan (OSV, backward-looking; blind to novel/injected code): %s.", strings.Join(st, "; "))
	}
	if transitive {
		w("NOT checked: does your code reach each change; what it does; test coverage;")
		w("  added modules are listed but not diffed; test-only/deeper modules beyond")
		w("  go.mod's pruned set (go.sum has more); publish provenance. Silence != safe.")
	} else {
		w("NOT checked: does your code reach each change; what it does; test coverage;")
		w("  transitive deps these bumps pull in; publish provenance. Silence != safe.")
	}
	w("next: for each dep you rely on, intersect the diff with your usage ->")
	w("  depsound surface <eco>:<name> <from> <to> --uses=<your imports>")
}

func digestOf(s *stats.Stats) digest {
	d := digest{
		compat: s.Compat.TypeFrom != s.Compat.TypeTo || len(s.Compat.Constraints) > 0 || len(s.Compat.Exports) > 0,
	}
	r := s.Runnable
	for _, c := range r.Lifecycle {
		d.exec = true
		d.execWhat = append(d.execWhat, "lifecycle "+c.Key+" "+c.Status)
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

// joinVulnIDs renders advisory IDs (preferring the CVE alias, more
// recognizable than a GHSA id) so the router points at what to act on,
// not just how many. Capped so a heavy dep does not become a wall.
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
