package output

import (
	"fmt"
	"strings"

	"github.com/rvagg/depsound/internal/stats"
)

// writeAction renders the GitHub Actions section: pinning (escalating
// sha < tag < branch) and the action.yml execution model + delta. Consumes
// the tool-computed ActionSection; embedded strings stay tainted.
func writeAction(w func(string, ...any), a *stats.ActionSection) {
	if a == nil {
		return
	}
	w("")
	w("github action  (runs on a CI RUNNER, not your machine; the risk is the")
	w("runner's SECRETS, GITHUB_TOKEN and OIDC, plus push/publish powers, and")
	w("more on self-hosted runners. Running code IS an action's whole job, so")
	w("the execution model below is CONTEXT, not an alarm; the load-bearing")
	w("questions are the PIN and what the code REACHES, read the dist bundle.)")
	for _, p := range a.Pins {
		w("  %s", renderPin(p))
	}

	// execution model is context, never a red flag (running code is the
	// point). A using-version bump (node16->node20) is maintenance; a MODEL
	// class change (node<->docker<->composite) is a bigger shift, so name it.
	switch {
	case a.UsingFrom == "" && a.UsingTo == "":
		w("  execution model: no action.yml parsed (composite/nested detail unavailable)")
	case a.UsingFrom == a.UsingTo:
		w("  execution model: %s", taint(a.UsingTo))
	default:
		note := "runtime bump, maintenance"
		if usingClass(a.UsingFrom) != usingClass(a.UsingTo) {
			note = "MODEL CLASS changed, a bigger shift in what it can do"
		}
		w("  execution model: %s -> %s (%s)", taint(orNone(a.UsingFrom)), taint(orNone(a.UsingTo)), note)
	}
	for _, c := range a.Exec {
		// pre/post/main are execution STRUCTURE, not install-hook alarms:
		// every action runs code, so a changed entrypoint is context to read
		// alongside the code diff, not a red flag in itself
		w("  entrypoint %s %s: %s", taint(c.Key), c.Status, changeDetail(c))
	}
	if n := len(a.Nested); n > 0 {
		w("  composite uses %d nested action(s) (TRANSITIVE supply chain, each its own pin to vet):", n)
		for _, u := range a.Nested {
			w("    %s", taint(u))
		}
	}
}

// usingClass collapses a runs.using value to its model class, so a mere
// node version bump reads differently from a node->docker switch.
func usingClass(using string) string {
	switch {
	case using == "docker":
		return "docker"
	case using == "composite":
		return "composite"
	case strings.HasPrefix(using, "node"):
		return "node"
	default:
		return using
	}
}

// renderPin is the escalating pinning warning: sha (immutable, good) < tag
// (mutable, re-pointable, the tj-actions vector) < branch (unpinned, moves
// every push, worst). ref is attacker-influenced, so tainted.
func renderPin(p stats.ActionPin) string {
	switch p.Kind {
	case "sha":
		return fmt.Sprintf("%s: SHA pin %s (immutable, good practice)", p.Side, taint(p.Ref))
	case "branch":
		return fmt.Sprintf("WARNING %s: BRANCH pin %q is UNPINNED (moves on EVERY push; you run whatever is there at run time, worst practice). It is %s now, pin a tag or a SHA", p.Side, taint(p.Ref), p.SHA)
	default: // tag
		return fmt.Sprintf("WARNING %s: TAG pin %q is MUTABLE (re-pointable, the tj-actions vector); resolves to %s today, prefer a SHA pin", p.Side, taint(p.Ref), p.SHA)
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
