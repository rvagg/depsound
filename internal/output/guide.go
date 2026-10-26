package output

import (
	"fmt"
	"net/url"
	"path/filepath"
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

const checksumLookupGap = "registry checksum index lookup failed (local sha256 only)"

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
func Guide(s *stats.Stats, cacheRoot string) (*stats.Coverage, []stats.NextAction) {
	checked, notChecked := coverageChecked, coverageNotChecked
	if len(s.Artifact.Unavailable) > 0 {
		checked = []string{"artifact acquisition status"}
		notChecked = []string{
			"published artifact contents (one or more endpoint artifacts were not inspected)",
			"file classification and content diff",
			"manifest compatibility and dependency deltas",
			"execution surface",
			"whether YOUR code reaches the changed code (reachability)",
			"what the change does at runtime (behavioural / semantic effects)",
			"whether your own tests cover the change",
			"transitive dependencies this bump pulls in",
			"how the release was published (provenance, anomaly vs history)",
		}
	}
	if len(s.Artifact.Unavailable) == 0 && (localSource(s.Artifact.SourceFrom) || localSource(s.Artifact.SourceTo)) {
		checked = append([]string(nil), coverageChecked...)
		checked[0] = "caller-supplied quarantined artifact diff (origin + sha256 recorded; registry checksum cross-checked when obtained)"
	}
	// An action runs on a runner. The calling workflow determines what it can
	// reach, so import reachability in your code does not apply.
	if len(s.Artifact.Unavailable) == 0 && s.Package.Ecosystem == "gha" {
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
	for _, source := range []*stats.Source{s.Artifact.SourceFrom, s.Artifact.SourceTo} {
		if source != nil && source.RegistryChecksum != nil && source.RegistryChecksum.State == "lookup-failed" {
			notChecked = append(append([]string(nil), notChecked...), checksumLookupGap)
		}
	}
	cov := &stats.Coverage{Checked: checked, NotChecked: notChecked}

	var na []stats.NextAction
	add := func(reason, cmd string) { na = append(na, stats.NextAction{Reason: reason, Command: cmd}) }
	for _, u := range s.Artifact.Unavailable {
		cmd := ""
		reason := "obtain the exact labelled artifact from a source you trust, then supply it for inert inspection"
		if u.Reason == "policy-blocked" {
			reason = "ask the platform operator for the policy basis or a permitted evidence path; do not bypass the policy"
		} else if s.Package.Ecosystem == "crates" && (u.Side == "from" || u.Side == "to") {
			cmd = reviewCommand(s, cacheRoot, "", "--"+u.Side+"-artifact=<quarantined-"+u.Version+".crate>")
		}
		add(reason, cmd)
	}
	if len(s.Artifact.Unavailable) > 0 {
		if n := len(s.Security.Introduced); n > 0 {
			add(fmt.Sprintf("%d advisory record(s) match only the target version; respond from the advisory facts, not endpoint bytes", n), "")
		}
		if n := len(s.Security.StillPresent); n > 0 {
			add(fmt.Sprintf("%d advisory record(s) match both endpoints; check exposure", n), "")
		}
		return cov, na
	}

	r := s.Runnable
	if len(r.Lifecycle) > 0 || (!r.GypFrom && r.GypTo) || (!r.CgoFrom && r.CgoTo) ||
		(!r.BuildRSFrom && r.BuildRSTo) || (!r.ProcMacroFrom && r.ProcMacroTo) {
		file := "<the script>"
		switch {
		case !r.BuildRSFrom && r.BuildRSTo:
			file = "build.rs"
		case !r.GypFrom && r.GypTo:
			file = "binding.gyp"
		}
		add("install/build code runs on the consumer's machine; read it",
			reviewCommand(s, cacheRoot, "show", "--file="+file))
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

	// Route the transitive NOT-checked line to a real command for every
	// ecosystem with a lockfile transitive mode. When an endpoint came from a
	// range, this review did not use a lockfile; point to the recipe that
	// generates the pair instead.
	if eco := s.Package.Ecosystem; transitiveLock[eco] != "" {
		switch r := s.Resolution; {
		case r != nil && (r.FromSpec != "" || r.ToSpec != "") && projectable[eco]:
			add("this bump moves your whole transitive subtree, and no lockfile resolved it here: project it (deps.dev resolves in isolation, an upper bound, not your tree; exact route in `depsound guide`)",
				fmt.Sprintf("depsound transitive %s %s %s", shellQuote(eco+":"+s.Package.Name), shellQuote(s.Package.From), shellQuote(s.Package.To)))
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
				fmt.Sprintf("uses: %s@%s # %s", EscapeText(s.Package.Name), EscapeText(p.SHA), EscapeText(s.Package.To)))
		}
		// route to the payload only where there is one: a composite action has
		// no bundle, and an empty scoped diff has nothing to read
		switch {
		case s.Files.Changed == 0:
		case a.UsingTo == "composite":
			add("a composite action executes its own steps plus the actions it nests; read the changed steps in the workspace diff", "")
		case a.MainTo != "":
			add(fmt.Sprintf("%s is what executes on the runner; read it in the workspace diff", EscapeText(a.MainTo)),
				reviewCommand(s, cacheRoot, "show", "--file="+a.MainTo))
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
			"grep -rn -- "+shellQuote(s.Package.Name)+" .github/workflows/")
	} else {
		// Always last, and always present: reachability is the tool's blind
		// spot, so the standing next-step is to intersect the diff with actual
		// usage. This is the anti-closure nudge on an otherwise-quiet result.
		add("reachability and semantics are not assessed; if you rely on this dependency, intersect the diff with your usage",
			reviewCommand(s, cacheRoot, "surface", "--uses=<your import paths>"))
	}
	return cov, na
}

func localSource(source *stats.Source) bool {
	return source != nil && strings.HasPrefix(source.Verification, "local-")
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

func reviewCommand(s *stats.Stats, cacheRoot, verb string, extra ...string) string {
	identities := []string{s.Package.Ecosystem + ":" + s.Package.Name, s.Package.From, s.Package.To}
	for _, identity := range identities {
		if EscapeText(identity) != identity {
			return ""
		}
	}
	args := []string{"depsound"}
	if verb != "" {
		args = append(args, verb)
	}
	args = append(args, identities...)
	if cacheRoot != "" {
		root, err := filepath.Abs(cacheRoot)
		if err != nil {
			return ""
		}
		args = append(args, "--cache-dir="+root)
	}
	for _, local := range []struct {
		side   string
		source *stats.Source
	}{{"from", s.Artifact.SourceFrom}, {"to", s.Artifact.SourceTo}} {
		if !localSource(local.source) {
			continue
		}
		u, err := url.Parse(local.source.URL)
		if err != nil || u.Scheme != "file" || u.Host != "" || u.Path == "" {
			return ""
		}
		path := u.Path
		// File URLs prefix Windows drive paths with a slash.
		if len(path) > 1 && filepath.VolumeName(path[1:]) != "" {
			path = path[1:]
		}
		path = filepath.FromSlash(path)
		if !filepath.IsAbs(path) {
			return ""
		}
		args = append(args, "--"+local.side+"-artifact="+path)
	}
	for _, arg := range extra {
		if value, ok := strings.CutPrefix(arg, "--file="); ok && EscapeText(value) != value {
			return ""
		}
	}
	args = append(args, extra...)
	for i, arg := range args {
		args[i] = shellQuote(arg)
	}
	return strings.Join(args, " ")
}

func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_./:@%+=,-", r))
	}) == -1 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
