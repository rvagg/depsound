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
		return true, "reported advisories via OSV (vulnerabilities and malicious packages, backward-looking)"
	case !osvSupported(eco):
		return false, "reported advisories via OSV: not applicable (no OSV index for this ecosystem)"
	case note != "":
		return false, "reported advisories via OSV: scan did NOT complete (" + note + ")"
	default:
		return false, "reported advisories via OSV: scan disabled for this run"
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

// projectable marks the ecosystems whose subtree deps.dev can resolve, so the
// no-lockfile route can offer the zero-setup projection. Go is absent by
// nature, not by gap: go.mod IS the resolved set.
var projectable = map[string]bool{"npm": true, "crates": true}

// Guide computes the coverage boundary and directed next-steps for a
// report. It is deliberately loud about limits: depsound is a heuristic
// triage tool, and a clean result is a STARTING POINT, not a verdict.
func Guide(s *stats.Stats) (*stats.Coverage, []stats.NextAction) {
	checked, notChecked := coverageChecked, coverageNotChecked
	// an action is reviewed on its own terms: it runs on a runner rather than
	// inside your code, so what it can reach is decided by the calling
	// workflow, and import reachability says nothing about it
	if s.Action != nil {
		checked = []string{
			"the repo tree at the pinned commit (what the runner checks out)",
			"file classification (source vs generated/test/docs, heuristic)",
			"pin grade (sha immutable; tag and branch re-pointable)",
			"action.yml execution model (using, entrypoints, composite uses)",
			"capability references in the executed code (OIDC/secrets/network/step-injection/exec; grep of the dist bundle, evadable)",
		}
		notChecked = []string{
			"whether the referenced capabilities are used maliciously (grep finds references, not intent; an obfuscated payload evades it)",
			"the permissions, secrets and trigger the calling workflow grants at each callsite",
			"self-hosted runner network reach and persistence",
			"what the change does at runtime (behavioural / semantic effects)",
			"nested actions and their own pins (listed, not analysed)",
			"how the release was published (provenance, anomaly vs history)",
		}
	}
	// provenance runs by default; when EVERY source answered, flip its
	// blind-spot line to checked (copying, never mutating the shared
	// slices). A partial answer keeps the line, naming exactly what failed:
	// partial coverage is a gap, not a discount on the claim.
	switch p := s.Provenance; {
	case p != nil && p.Complete():
		nc := make([]string, 0, len(notChecked))
		for _, x := range notChecked {
			if !strings.HasPrefix(x, "how the release was published") {
				nc = append(nc, x)
			}
		}
		notChecked = nc
		checked = append(append([]string(nil), checked...),
			"provenance deltas (shallow, history-only, not a pass)")
	case p != nil && p.Queried:
		nc := make([]string, 0, len(notChecked))
		for _, x := range notChecked {
			if strings.HasPrefix(x, "how the release was published") {
				x += " (partially checked; failed: " + strings.Join(p.FailedSources(), "; ") + ")"
			}
			nc = append(nc, x)
		}
		notChecked = nc
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
	// never leaves the agent thinking the subtree is unreachable. A
	// range-valued endpoint means no lockfile resolved this change, so naming
	// a lockfile pair would route to files that do not exist: point at the
	// recipe that generates the pair instead.
	if eco := s.Package.Ecosystem; transitiveLock[eco] != "" {
		switch r := s.Resolution; {
		case r != nil && (r.FromSpec != "" || r.ToSpec != "") && projectable[eco]:
			add("this bump moves your whole transitive subtree, and no lockfile resolved it here: project it (deps.dev resolves in isolation, an upper bound, not your tree; exact route in `depsound guide`)",
				fmt.Sprintf("depsound transitive %s:%s %s %s", eco, s.Package.Name, s.Package.From, s.Package.To))
		default:
			add("this bump moves your whole transitive subtree, not just this dep; diff the lockfile pair (pass github:owner/repo@sha, no download)",
				fmt.Sprintf("depsound transitive %s --old=<base %s> --new=<PR %s>", eco, transitiveLock[eco], transitiveLock[eco]))
		}
	}

	// The standing anti-closure nudge differs by threat model. An action runs
	// on the runner, not in your code, so import-path intersection (surface)
	// is meaningless there; the gha next-steps are the pin and the payload.
	if a := s.Action; a != nil {
		// only a mutable ref can be re-pointed under a completed review
		if p := pinOf(a.Pins, "to"); p != nil && p.Kind != "sha" {
			add(fmt.Sprintf("a %s can be re-pointed after this review; pin the commit the review actually covered", p.Kind),
				fmt.Sprintf("uses: %s@%s # %s", s.Package.Name, p.SHA, s.Package.To))
		}
		// route to the payload only where there is one: a composite action has
		// no bundle, and an empty scoped diff has nothing to read
		switch {
		case s.Files.Changed == 0:
		case a.UsingTo == "composite":
			add("a composite action executes its own steps plus the actions it nests; read the changed steps in the workspace diff", "")
		case a.MainTo != "":
			add(fmt.Sprintf("%s is what executes on the runner; read it in the workspace diff", a.MainTo),
				"depsound show "+ref+" --file="+a.MainTo)
		default:
			add("the executed entrypoint is what runs on the runner; read the changed files in the workspace diff", "")
		}
		if len(a.Nested) > 0 {
			add(fmt.Sprintf("%d nested action(s) are their own supply chain; vet each pin", len(a.Nested)),
				"depsound gha:<owner/repo> <ref>   (census each nested pin)")
		}
		// the standing gha nudge: what the runner hands the action is decided
		// at the callsite, which is in the consumer's workflows, not here
		add("an action runs with whatever the calling workflow grants it; check permissions, secrets and trigger at each callsite",
			fmt.Sprintf("grep -rn %q .github/workflows/", s.Package.Name))
	} else {
		// Always last, and always present: reachability is the tool's blind
		// spot, so the standing next-step is to intersect the diff with actual
		// usage. This is the anti-closure nudge on an otherwise-quiet result.
		add("reachability and semantics are not assessed; if you rely on this dependency, intersect the diff with your usage",
			"depsound surface "+ref+" --uses=<your import paths>")
	}
	return cov, na
}

// pinOf returns the named side's pin, nil if absent.
func pinOf(pins []stats.ActionPin, side string) *stats.ActionPin {
	for _, p := range pins {
		if p.Side == side {
			return &p
		}
	}
	return nil
}
