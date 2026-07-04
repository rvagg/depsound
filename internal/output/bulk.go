package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rvagg/depvet/internal/stats"
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
	deps     int
	osvFixed int
	osvStill int
	osvIntro int
	files    int
	added    int
	removed  int
}

// Bulk renders the aggregate: a rollup of which deps trip which signals
// (execution surface / compat / security) first, then a per-dep table.
// Signals are facts, not verdicts; the single-pair command gives detail.
func Bulk(results []BulkResult) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("depvet bulk: %d dependencies", len(results))

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
	section(w, "WARNING vulnerabilities INTRODUCED by the upgrade", introHits, func(r BulkResult) string {
		return fmt.Sprintf("%d introduced", digests[r.Ref].osvIntro)
	})
	section(w, "vulnerabilities STILL PRESENT after the upgrade", stillHits, func(r BulkResult) string {
		return fmt.Sprintf("%d still present", digests[r.Ref].osvStill)
	})
	section(w, "compatibility changes", compatHits, func(r BulkResult) string {
		return "constraints/exports changed"
	})
	section(w, "advisories FIXED by the upgrade (the merge argument)", fixHits, func(r BulkResult) string {
		return fmt.Sprintf("%d fixed", digests[r.Ref].osvFixed)
	})
	if len(clean) > 0 {
		w("")
		w("no notable signals:")
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

	w("")
	w("per-dependency:")
	for _, r := range results {
		if r.Stats == nil {
			w("  %-40s  ERROR", taint(r.Ref))
			continue
		}
		d := digests[r.Ref]
		w("  %-40s  %d files +%d/-%d  %s", taint(r.Ref), d.files, d.added, d.removed, digestLine(d))
	}

	w("")
	w("detail on any dep: depvet <eco>:<name> <from> <to>  (advisory leads, not a gate)")
	return b.String()
}

func digestOf(s *stats.Stats) digest {
	d := digest{
		compat:  s.Compat.TypeFrom != s.Compat.TypeTo || len(s.Compat.Constraints) > 0 || len(s.Compat.Exports) > 0,
		deps:    len(s.Dependencies),
		files:   s.Files.Changed,
		added:   s.Files.Added,
		removed: s.Files.Removed,
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
	sort.Strings(d.execWhat)
	return d
}

// digestLine is the compact per-dep signal string.
func digestLine(d digest) string {
	var parts []string
	if d.exec {
		parts = append(parts, "EXEC")
	}
	if d.compat {
		parts = append(parts, "compat")
	}
	if d.deps > 0 {
		parts = append(parts, fmt.Sprintf("%d deps", d.deps))
	}
	sec := ""
	switch {
	case d.osvIntro > 0:
		sec = fmt.Sprintf("OSV +%d introduced!", d.osvIntro)
	case d.osvStill > 0:
		sec = fmt.Sprintf("OSV %d still-present", d.osvStill)
	case d.osvFixed > 0:
		sec = fmt.Sprintf("OSV %d fixed", d.osvFixed)
	}
	if sec != "" {
		parts = append(parts, sec)
	}
	if len(parts) == 0 {
		return "clean"
	}
	return strings.Join(parts, "  ")
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
