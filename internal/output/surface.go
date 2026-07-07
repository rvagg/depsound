package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rvagg/depsound/internal/stats"
	"github.com/rvagg/depsound/internal/surface"
)

// Surface renders the consumer-intersection report: matched units first
// with their changed files and top symbols, then the honest non-matches
// (unmapped and out-of-scope are NOT all-clears), and always the
// unindexable and attribution disclosures so a clean result cannot be
// mistaken for complete coverage.
func Surface(s *stats.Stats, results []surface.UnitResult, idx *surface.Index, ws string) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("depsound surface %s:%s %s -> %s", s.Package.Ecosystem, taint(s.Package.Name), taint(s.Package.From), taint(s.Package.To))
	w("")

	var matched, subpkg, clear, unmapped, oos []surface.UnitResult
	for _, r := range results {
		switch r.Status {
		case surface.StatusMatched:
			matched = append(matched, r)
		case surface.StatusSubpackagesOnly:
			subpkg = append(subpkg, r)
		case surface.StatusNoChangedFiles:
			clear = append(clear, r)
		case surface.StatusUnmapped:
			unmapped = append(unmapped, r)
		default:
			oos = append(oos, r)
		}
	}

	if len(matched) == 0 && len(subpkg) == 0 {
		w("no consumer unit intersects the changed files")
	}
	for _, r := range matched {
		hunks := 0
		for _, f := range r.Files {
			hunks += len(f.Hunks)
		}
		w("MATCHED %s  (%d files, %d hunks; %s)", taint(r.Unit), len(r.Files), hunks, classBreakdown(r.Files))
		for _, f := range topFiles(r.Files, 8) {
			w("  %s%s", taint(f.Path), fileHint(f))
		}
		if len(r.Files) > 8 {
			w("  ... and %d more files", len(r.Files)-8)
		}
		if len(r.Descendants) > 0 {
			w("  + %d file(s) in descendant packages (verify you import them): %s",
				len(r.Descendants), descendantDirs(r.Descendants))
		}
	}

	// the merkledag case: the unit's own package is unchanged; only nested
	// packages changed. NOT a match, reported honestly, with the exact
	// commands to drill deeper if the agent judges them reachable.
	for _, r := range subpkg {
		w("SUBPACKAGES ONLY %s  (own package unchanged; verify you import these)", taint(r.Unit))
		for _, f := range topFiles(r.Descendants, 8) {
			w("  %s%s", taint(f.Path), fileHint(f))
		}
		if len(r.Descendants) > 8 {
			w("  ... and %d more files", len(r.Descendants)-8)
		}
		w("  drill in: re-run --uses=%s/<subpkg>, or show --dir=<subpkg>; --subtree counts the whole area",
			taint(r.Unit))
	}

	if len(clear) > 0 {
		w("")
		w("no changes touch (mapped, all-clear):")
		for _, r := range clear {
			w("  %s", taint(r.Unit))
		}
	}
	if len(unmapped) > 0 {
		w("")
		w("UNMAPPED (could not resolve to changed paths; NOT a no-change result):")
		for _, r := range unmapped {
			w("  %s  %s", taint(r.Unit), taint(r.Detail))
		}
	}
	if len(oos) > 0 {
		w("")
		w("OUT OF SCOPE (mechanism unsupported):")
		for _, r := range oos {
			w("  %s  %s", taint(r.Unit), taint(r.Detail))
		}
	}

	// disclosures: unindexable changes and attribution rate exist so a
	// clean intersection is never mistaken for full coverage
	var unindexable []string
	for _, f := range idx.Files {
		if f.Binary {
			unindexable = append(unindexable, f.Path)
		}
	}
	with, total := idx.Attributed()
	w("")
	w("coverage: %d of %d hunks are symbol-attributed", with, total)
	if len(unindexable) > 0 {
		w("unindexable changes NOT covered by symbol matching (review directly):")
		for _, p := range unindexable {
			w("  %s", taint(p))
		}
	}

	// Honest blind spot: matching is by path, not import reachability. A
	// unit can be impacted by changes in other packages it depends on,
	// which never appear under it. Quantify what falls outside the units
	// so a small or empty match is not mistaken for low impact.
	outside := unmatchedCount(results, idx)
	w("")
	w("=== COVERAGE: matches by PATH, not reachability; NOT a verdict ===")
	w("NOT checked (a match is where to LOOK, not proof of impact):")
	for _, l := range SurfaceLimitations(s.Package.Ecosystem) {
		w("  - %s", l)
	}
	if outside > 0 {
		w("  - %d of %d changed files fall outside your units; a small match is", outside, len(idx.Files))
		w("    not low impact. review the full diff: depsound %s:%s %s %s",
			s.Package.Ecosystem, taint(s.Package.Name), s.Package.From, s.Package.To)
	}
	w("")
	w("workspace: %s", ws)
	return b.String()
}

// SurfaceLimitations returns the blind-spot disclaimers for an ecosystem.
// The reachability caveat is universal; matching mechanics and what the
// static match cannot model are ecosystem-specific. Shared by the text
// and JSON renderers so the two never drift.
func SurfaceLimitations(eco string) []string {
	common := []string{
		"matching is by path, not import reachability: changes in code your units depend on are not attributed here",
		"a small or empty match is not proof of low impact; review the full diff for module-wide changes",
	}
	switch eco {
	case "go":
		return append(common,
			"Go matching is per-package; nested packages report as subpackagesOnly, drill in with a deeper --uses=, show --dir=, or --subtree",
			"build tags and GOOS/GOARCH are not modeled: a changed file may not compile into your build",
		)
	case "npm":
		return append(common,
			"npm matching is by subtree (a subpath and everything beneath it)",
			"module resolution (exports conditions such as import/require, browser/node) is not modeled: a changed file may not be in the entry your import resolves to",
		)
	default:
		return common
	}
}

// unmatchedCount reports how many changed files were not covered by any
// unit's own-package or descendant match: the transitive blind spot,
// stated as a number.
func unmatchedCount(results []surface.UnitResult, idx *surface.Index) int {
	covered := map[string]bool{}
	for _, r := range results {
		for _, f := range r.Files {
			covered[f.Path] = true
		}
		for _, f := range r.Descendants {
			covered[f.Path] = true
		}
	}
	n := 0
	for _, f := range idx.Files {
		if !covered[f.Path] {
			n++
		}
	}
	return n
}

// classBreakdown summarizes matched files by class so test/docs/generated
// noise is visible at a glance rather than inflating the file count.
func classBreakdown(files []surface.FileSurface) string {
	counts := map[string]int{}
	for _, f := range files {
		c := f.Class
		if c == "" {
			c = "source"
		}
		counts[c]++
	}
	order := []string{"source", "generated", "test", "docs", "meta", "binary"}
	var parts []string
	for _, c := range order {
		if counts[c] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[c], c))
		}
	}
	if len(parts) == 0 {
		return "no files"
	}
	return strings.Join(parts, ", ")
}

func topFiles(files []surface.FileSurface, n int) []surface.FileSurface {
	sorted := make([]surface.FileSurface, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i].Hunks) > len(sorted[j].Hunks) })
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	return sorted
}

// fileHint prefixes the class tag (for non-source) before the symbols.
func fileHint(f surface.FileSurface) string {
	cls := ""
	if f.Class != "" && f.Class != "source" {
		cls = " [" + f.Class + "]"
	}
	return cls + symbolHint(f)
}

// descendantDirs lists the distinct nested package directories, the unit
// of "did I import this", not individual files.
func descendantDirs(files []surface.FileSurface) string {
	seen := map[string]bool{}
	var dirs []string
	for _, f := range files {
		d := f.Path
		if i := strings.LastIndex(d, "/"); i >= 0 {
			d = d[:i]
		}
		if !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	sort.Strings(dirs)
	for i, d := range dirs {
		dirs[i] = taint(d)
	}
	return strings.Join(dirs, ", ")
}

func symbolHint(f surface.FileSurface) string {
	if f.Binary {
		return "  (binary)"
	}
	seen := map[string]bool{}
	var syms []string
	for _, h := range f.Hunks {
		if h.Symbol != "" && !seen[h.Symbol] {
			seen[h.Symbol] = true
			syms = append(syms, taint(cleanSymbol(h.Symbol)))
		}
		if len(syms) == 3 {
			break
		}
	}
	if len(syms) == 0 {
		return fmt.Sprintf("  (%d hunks)", len(f.Hunks))
	}
	return "  " + strings.Join(syms, ", ")
}

// cleanSymbol trims a hunk-context line to a readable symbol name.
func cleanSymbol(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "{("); i > 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}
