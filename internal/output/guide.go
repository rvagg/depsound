package output

import (
	"fmt"
	"strings"

	"github.com/rvagg/depsound/internal/stats"
)

// coverageChecked and coverageNotChecked are the honest inverse of the
// tool's capabilities: the boundary that stops "no signals" being read as
// "safe". Static, because the boundary is the same for every report; the
// NOT-checked list doubles as a live map of the roadmap.
// OSV is deliberately NOT here: it can be disabled/unsupported/failed, so it is
// added to checked or not-checked per report by osvCoverageLine, never claimed
// unconditionally.
var coverageChecked = []string{
	"the published-artifact diff (what installs, not the repo)",
	"file classification (source vs generated/test/docs, heuristic)",
	"manifest compatibility: constraints, exports, dependency deltas",
	"execution surface (lifecycle scripts, cgo, build.rs, proc-macro, gyp)",
}

// osvCoverageLine states OSV's place in a coverage boundary: whether it belongs
// under "checked", and the exact line. A scan that ran is checked; one that did
// not (disabled/failed) or does not apply (unsupported) is stated as a gap, so
// the boundary never implies OSV ran when it did not. Shared by the diff Guide
// and CensusGuide so both coverage renderers stay honest identically.
func osvCoverageLine(eco string, queried bool, note string) (checked bool, line string) {
	switch {
	case queried:
		return true, "known CVEs via OSV (backward-looking)"
	case !osvSupported(eco):
		return false, "known CVEs via OSV: not applicable (no OSV index for this ecosystem)"
	case note != "":
		return false, "known CVEs via OSV: scan did NOT complete (" + note + ")"
	default:
		return false, "known CVEs via OSV: scan disabled for this run"
	}
}

var coverageNotChecked = []string{
	"whether YOUR code reaches the changed code (reachability)",
	"what the change does at runtime (behavioural / semantic effects)",
	"whether your own tests cover the change",
	"transitive dependencies this bump pulls in",
	"how the release was published (provenance, anomaly vs history)",
}

// transitiveLock names the lockfile each ecosystem's transitive mode diffs,
// so a single-pair diff can point at it (pnpm shares npm's analysis).
var transitiveLock = map[string]string{"go": "go.mod", "npm": "package-lock.json", "crates": "Cargo.lock"}

// Guide computes the coverage boundary and directed next-steps for a
// report. It is deliberately loud about limits: depsound is a heuristic
// triage tool, and a clean result is a STARTING POINT, not a verdict.
func Guide(s *stats.Stats) (*stats.Coverage, []stats.NextAction) {
	checked, notChecked := coverageChecked, coverageNotChecked
	if s.Action != nil { // gha: the execution surface we check is action.yml
		checked = append([]string(nil), coverageChecked...)
		for i, c := range checked {
			if strings.HasPrefix(c, "build/install execution surface") {
				checked[i] = "action.yml execution model (using, entrypoints, composite uses)"
			}
		}
		checked = append(checked, "capability references in the executed code (OIDC/secrets/network/step-injection/exec; grep of the dist bundle, evadable)")
		// we now grep for capability references, but not for intent
		notChecked = append([]string{
			"whether the referenced capabilities are used maliciously (grep finds references, not intent; an obfuscated payload evades it)",
		}, coverageNotChecked...)
	}
	// provenance runs by default; when it answered, flip its blind-spot line
	// to checked (copying, never mutating the shared slices)
	if s.Provenance != nil && s.Provenance.Queried {
		nc := make([]string, 0, len(notChecked))
		for _, x := range notChecked {
			if !strings.HasPrefix(x, "how the release was published") {
				nc = append(nc, x)
			}
		}
		notChecked = nc
		checked = append(append([]string(nil), checked...),
			"provenance deltas (shallow, history-only, not a pass)")
	}
	// OSV: claim it checked only when it actually ran, else state the gap.
	if ok, line := osvCoverageLine(s.Package.Ecosystem, s.Security.Queried, s.Security.Note); ok {
		checked = append(append([]string(nil), checked...), line)
	} else {
		notChecked = append(append([]string(nil), notChecked...), line)
	}
	cov := &stats.Coverage{Checked: checked, NotChecked: notChecked}

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
		add(fmt.Sprintf("this upgrade introduces %d advisory(ies); confirm exposure", n), "")
	}
	if n := len(s.Security.StillPresent); n > 0 {
		add(fmt.Sprintf("%d advisory(ies) remain after this upgrade; check whether your code path reaches them", n), "")
	}
	if s.Compat.TypeFrom != s.Compat.TypeTo || len(s.Compat.Constraints) > 0 || len(s.Compat.Exports) > 0 {
		add("compatibility constraints changed; check your usage against the compat section", "")
	}

	// route the transitive NOT-checked line to a real command for every
	// ecosystem that has a lockfile transitive mode, so a single-pair diff
	// never leaves the agent thinking the subtree is unreachable.
	if lock := transitiveLock[s.Package.Ecosystem]; lock != "" {
		add("this bump moves your whole transitive subtree, not just this dep; diff the lockfile pair (pass github:owner/repo@sha, no download)",
			fmt.Sprintf("depsound transitive %s --old=<base %s> --new=<PR %s>", s.Package.Ecosystem, lock, lock))
	}

	// The standing anti-closure nudge differs by threat model. An action runs
	// on the runner, not in your code, so import-path intersection (surface)
	// is meaningless there; the gha next-steps are the pin and the payload.
	if a := s.Action; a != nil {
		if sha := pinSHA(a.Pins, "to"); sha != "" {
			add("a tag can re-point after this review; pin the commit the review actually covered",
				fmt.Sprintf("uses: %s@%s # %s", s.Package.Name, sha, s.Package.To))
		}
		add("the dist bundle is what executes on the runner; read the changed entrypoint files in the workspace diff", "")
		if len(a.Nested) > 0 {
			add(fmt.Sprintf("%d nested action(s) are their own supply chain; vet each pin", len(a.Nested)),
				"depsound gha:<owner/repo> <ref>   (census each nested pin)")
		}
	} else {
		// Always last, and always present: reachability is the tool's blind
		// spot, so the standing next-step is to intersect the diff with actual
		// usage. This is the anti-closure nudge on an otherwise-quiet result.
		add("reachability and semantics are not assessed; if you rely on this dependency, intersect the diff with your usage",
			"depsound surface "+ref+" --uses=<your import paths>")
	}
	return cov, na
}

// pinSHA returns the resolved commit of the named side's pin, "" if absent.
func pinSHA(pins []stats.ActionPin, side string) string {
	for _, p := range pins {
		if p.Side == side {
			return p.SHA
		}
	}
	return ""
}
