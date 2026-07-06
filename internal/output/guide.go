package output

import (
	"fmt"

	"github.com/rvagg/depsound/internal/stats"
)

// coverageChecked and coverageNotChecked are the honest inverse of the
// tool's capabilities: the boundary that stops "no signals" being read as
// "safe". Static, because the boundary is the same for every report; the
// NOT-checked list doubles as a live map of the roadmap.
var coverageChecked = []string{
	"the published-artifact diff (what installs, not the repo)",
	"file classification (source vs generated/test/docs, heuristic)",
	"manifest compatibility: constraints, exports, dependency deltas",
	"build/install execution surface (lifecycle scripts, build.rs, cgo, gyp, proc-macro)",
	"KNOWN CVEs via OSV (backward-looking)",
}

var coverageNotChecked = []string{
	"whether YOUR code reaches the changed code (reachability)",
	"what the change DOES at runtime (behavioural / semantic effects)",
	"whether your own tests cover the change",
	"transitive dependencies this bump pulls in",
	"how the release was published (provenance, anomaly vs history)",
}

// Guide computes the coverage boundary and directed next-steps for a
// report. It is deliberately loud about limits: depsound is a heuristic
// triage tool, and a clean result is a STARTING POINT, not a verdict.
func Guide(s *stats.Stats) (*stats.Coverage, []stats.NextAction) {
	cov := &stats.Coverage{Checked: coverageChecked, NotChecked: coverageNotChecked}

	ref := fmt.Sprintf("%s:%s %s %s", s.Package.Ecosystem, s.Package.Name, s.Package.From, s.Package.To)
	var na []stats.NextAction
	add := func(reason, cmd string) { na = append(na, stats.NextAction{Reason: reason, Command: cmd}) }

	r := s.Runnable
	if len(r.Lifecycle) > 0 || (!r.GypFrom && r.GypTo) || (!r.CgoFrom && r.CgoTo) ||
		(!r.BuildRSFrom && r.BuildRSTo) || (!r.ProcMacroFrom && r.ProcMacroTo) {
		add("install/build code runs on the consumer's machine; read it",
			"depsound show "+ref+" --file=<the script>")
	}
	// Only NEW or RESIDUAL risk earns a next-step; FixedByUpgrade needs no
	// action (it is the argument FOR the upgrade) and is shown in the
	// security section, not repeated here as a to-do.
	if n := len(s.Security.Introduced); n > 0 {
		add(fmt.Sprintf("this upgrade INTRODUCES %d advisory(ies); confirm exposure", n), "")
	}
	if n := len(s.Security.StillPresent); n > 0 {
		add(fmt.Sprintf("%d advisory(ies) REMAIN after this upgrade; check whether your code path reaches them", n), "")
	}
	if s.Compat.TypeFrom != s.Compat.TypeTo || len(s.Compat.Constraints) > 0 || len(s.Compat.Exports) > 0 {
		add("compatibility constraints changed; check your usage against the compat section", "")
	}

	// Always last, and always present: reachability is the tool's blind
	// spot, so the standing next-step is to intersect the diff with actual
	// usage. This is the anti-closure nudge on an otherwise-quiet result.
	add("reachability and semantics are NOT assessed; if you rely on this dependency, intersect the diff with your usage",
		"depsound surface "+ref+" --uses=<your import paths>")
	return cov, na
}
