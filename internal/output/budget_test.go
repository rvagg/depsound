package output

import (
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/stats"
)

// A clean report (nothing flagged) is almost entirely invariant boilerplate:
// the coverage boundary + the notice. That is the anti-false-security SPINE
// and is meant to be here, but it must not INFLATE, so cap the loud/caveat
// lines. If this trips, a new always-on caveat was added: put the "why" in
// `depsound guide`, not in every report. The two load-bearing warnings
// (attacker-writable data; no-flags != safe) plus the coverage bullets are
// the budget; explanation of heuristics/threat-model belongs in the guide.
func TestReportBoilerplateBudget(t *testing.T) {
	s := &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm", Name: "x", From: "1", To: "2"}}
	s.Coverage, s.NextActions = Guide(s)
	out := Text(s)

	loud := 0
	for line := range strings.Lines(out) {
		if strings.Contains(line, "NOT ") || strings.Contains(line, "NOTICE") ||
			strings.Contains(line, "WARNING") || strings.Contains(line, "NEVER") ||
			strings.Contains(line, "GUESS") {
			loud++
		}
	}
	const budget = 12
	if loud > budget {
		t.Errorf("clean report has %d loud/caveat lines (budget %d); move invariant education to `depsound guide`, not the report:\n%s", loud, budget, out)
	}
}
