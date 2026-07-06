package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/stats"
)

// BulkResult pairs a dependency-change reference with its analysis, or an
// error if it failed. Ref is tool-formed (spec + versions), safe to print.
type BulkResult struct {
	Ref   string       `json:"ref"`
	Stats *stats.Stats `json:"stats,omitempty"`
	Err   string       `json:"error,omitempty"`
}

// digest is the per-dep signal summary the aggregate rolls up.
type digest struct {
	exec     bool
	execWhat []string
	compat   bool
	osvFixed int
	osvStill int
	osvIntro int
	stillIDs string // pre-joined advisory IDs: a pointer to act on, not a count
	introIDs string
}

// Bulk renders the aggregate: a rollup of which deps trip which signals
// (execution surface / compat / security) first, then a per-dep table.
// Signals are facts, not verdicts; the single-pair command gives detail.
func Bulk(results []BulkResult) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("depsound bulk: %d dependencies analysed (cached).", len(results))
	w("this is a ROUTER: a fired signal is a POINTER to inspect, not a summary.")
	w("drill any dep with: depsound <eco>:<name> <from> <to>  (now instant, cached)")

	var failed, execHits, compatHits, introHits, stillHits, fixHits, clean []BulkResult
	digests := map[string]digest{}
	for _, r := range results {
		if r.Stats == nil {
			failed = append(failed, r)
			continue
		}
		d := digestOf(r.Stats)
		digests[r.Ref] = d
		if d.osvIntro > 0 {
			introHits = append(introHits, r)
		}
		if d.exec {
			execHits = append(execHits, r)
		}
		if d.osvStill > 0 {
			stillHits = append(stillHits, r)
		}
		if d.compat {
			compatHits = append(compatHits, r)
		}
		if d.osvFixed > 0 {
			fixHits = append(fixHits, r)
		}
		// clean = nothing notable at all, including no fixed advisories
		// (which are called out above as their own positive signal)
		if !d.exec && !d.compat && d.osvIntro == 0 && d.osvStill == 0 && d.osvFixed == 0 {
			clean = append(clean, r)
		}
	}

	// order by weight: new risk first, then residual, then breaking, then
	// the positive (fixes), then the unremarkable
	section(w, "WARNING new build/install execution surface", execHits, func(r BulkResult) string {
		return strings.Join(digests[r.Ref].execWhat, ", ")
	})
	section(w, "WARNING CVEs INTRODUCED by the upgrade", introHits, func(r BulkResult) string {
		d := digests[r.Ref]
		return fmt.Sprintf("%d introduced: %s", d.osvIntro, d.introIDs)
	})
	section(w, "CVEs STILL PRESENT after the upgrade (bump did not fix them)", stillHits, func(r BulkResult) string {
		d := digests[r.Ref]
		return fmt.Sprintf("%d still present: %s", d.osvStill, d.stillIDs)
	})
	section(w, "compatibility changes", compatHits, func(r BulkResult) string {
		return "constraints/exports changed"
	})
	section(w, "advisories FIXED by the upgrade (the merge argument)", fixHits, func(r BulkResult) string {
		return fmt.Sprintf("%d fixed", digests[r.Ref].osvFixed)
	})
	if len(clean) > 0 {
		w("")
		w("NO FLAGS RAISED (%d): NOT the same as safe. These were not assessed", len(clean))
		w("for reachability, semantics, intent, or test coverage, a starting point:")
		for _, r := range clean {
			w("  %s", taint(r.Ref))
		}
	}
	if len(failed) > 0 {
		w("")
		w("FAILED (not analysed):")
		for _, r := range failed {
			w("  %s: %s", taint(r.Ref), taint(r.Err))
		}
	}

	// coverage boundary once, at the aggregate (same for every dep); the
	// anti-false-security spine, proportionate to a router (one block, not
	// repeated per dep). CVE scan is named backward-looking, not "security"
	w("")
	w("=== COVERAGE: heuristic triage, NOT a verdict ===")
	w("checked: artifact diff, file classes, manifest compat, execution surface,")
	w("  KNOWN-CVE scan (OSV, backward-looking; blind to novel/injected code).")
	w("NOT checked: does your code REACH each change; what it DOES; test coverage;")
	w("  TRANSITIVE deps these bumps pull in; publish provenance. Silence != safe.")
	w("next: for each dep you rely on, intersect the diff with your usage ->")
	w("  depsound surface <eco>:<name> <from> <to> --uses=<your imports>")
	return b.String()
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
	if !r.GypFrom && r.GypTo {
		d.exec = true
		d.execWhat = append(d.execWhat, "binding.gyp added")
	}
	if !r.CgoFrom && r.CgoTo {
		d.exec = true
		d.execWhat = append(d.execWhat, "cgo introduced")
	}
	if !r.BuildRSFrom && r.BuildRSTo {
		d.exec = true
		d.execWhat = append(d.execWhat, "build.rs introduced")
	}
	if !r.ProcMacroFrom && r.ProcMacroTo {
		d.exec = true
		d.execWhat = append(d.execWhat, "proc-macro introduced")
	}
	d.osvFixed = len(s.Security.FixedByUpgrade)
	d.osvStill = len(s.Security.StillPresent)
	d.osvIntro = len(s.Security.Introduced)
	d.stillIDs = joinVulnIDs(s.Security.StillPresent, 5)
	d.introIDs = joinVulnIDs(s.Security.Introduced, 5)
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

func section(w func(string, ...any), title string, hits []BulkResult, detail func(BulkResult) string) {
	if len(hits) == 0 {
		return
	}
	w("")
	w("%s:", title)
	for _, r := range hits {
		w("  %s  %s", taint(r.Ref), taint(detail(r)))
	}
}
