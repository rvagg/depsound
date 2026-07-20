package output

import (
	"fmt"
	"strings"

	"github.com/rvagg/depsound/internal/stats"
)

// writeAction renders the GitHub Actions section: pinning (escalating
// sha < tag < branch), any observed ref movement, and the action.yml
// execution model + delta. Consumes the tool-computed ActionSection;
// embedded strings stay tainted.
func writeAction(w func(string, ...any), a *stats.ActionSection, moved []stats.MovedRef) {
	if a == nil {
		return
	}
	w("")
	w("github action  (runs on a CI runner, not your machine; the risk is the")
	w("runner's secrets, GITHUB_TOKEN and OIDC, plus push/publish powers, and")
	w("more on self-hosted runners. Running code is an action's whole job, so")
	w("the execution model below is context, not an alarm; the questions that")
	w("matter are the pin and what the code reaches, read the dist bundle.)")
	for _, p := range a.Pins {
		w("  %s", renderPin(p))
	}
	for _, m := range moved {
		vector := "floating refs re-point routinely; noted for the record"
		if looksExactRelease(m.Ref) {
			vector = "an exact release tag re-pointing is the tj-actions vector, look at the new commit"
		}
		w("  moved: %s ref %q re-pointed since last fetch, %.12s -> %.12s (%s)",
			m.Side, taint(m.Ref), m.Prev, m.SHA, vector)
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
			note = "model class changed, a bigger shift in what it can do"
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
		w("  composite uses %d nested action(s) (transitive supply chain, each its own pin to vet):", n)
		for _, u := range a.Nested {
			w("    %s", taint(u))
		}
	}
	writeCaps(w, a.Caps, a.CapsIntroduced)
}

// writeCaps reports the runner powers the executed code references. It is a
// grep (evadable, a lead not proof), so present-in-both is context; an
// INTRODUCED capability (new in this bump) is the signal that matters, the
// tj-actions shape of adding a secret+network exfil path.
func writeCaps(w func(string, ...any), present, introduced []string) {
	if len(present) == 0 {
		w("  capabilities referenced: none matched (grep; an obfuscated payload can hide)")
		return
	}
	if len(introduced) > 0 {
		w("  capabilities introduced by this bump (grep, evadable lead; inspect):")
		for _, c := range introduced {
			w("    %s", c)
		}
	}
	intro := map[string]bool{}
	for _, c := range introduced {
		intro[c] = true
	}
	var both []string
	for _, c := range present {
		if !intro[c] {
			both = append(both, c)
		}
	}
	if len(both) > 0 {
		w("  capabilities present in both versions (context): %s", strings.Join(both, "; "))
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
		return fmt.Sprintf("%s: branch pin %q is unpinned (moves on every push; you run whatever is there at run time, worst practice). It is %s now, pin a tag or a SHA", p.Side, taint(p.Ref), p.SHA)
	default: // tag
		return fmt.Sprintf("%s: tag pin %q is mutable (re-pointable, the tj-actions vector); resolves to %s today, prefer a SHA pin", p.Side, taint(p.Ref), p.SHA)
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
