package output

import (
	"fmt"
	"strings"
)

// ModuleRef is a module that entered or left the resolved graph (no diff to
// analyse: added is new to the tree, removed is gone).
type ModuleRef struct {
	Path     string `json:"path"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Indirect bool   `json:"indirect"`
}

// TransitiveResult is the whole change set a bump drags in: the analysed
// version-changes (through the bulk router) plus the added/removed modules.
type TransitiveResult struct {
	// Ecosystem is where packages are analysed (npm/go/crates); Kind is the
	// lockfile the user gave (pnpm resolves npm packages, so they differ).
	Ecosystem string       `json:"ecosystem"`
	Kind      string       `json:"kind,omitempty"`
	Changed   []BulkResult `json:"changed"`
	Added     []ModuleRef  `json:"added"`
	Removed   []ModuleRef  `json:"removed"`
	// Flat marks a lockfile with no direct/indirect distinction (Cargo.lock),
	// so the direct/indirect breakdown is suppressed rather than faked.
	Flat            bool `json:"flat,omitempty"`
	DirectChanged   int  `json:"directChanged"`
	IndirectChanged int  `json:"indirectChanged"`
}

// Transitive renders the change set: the framing (this is the WHOLE subtree,
// direct and indirect), the newly-added modules (each a fresh dep to census),
// the removed ones, then the bulk router over the version-changes.
func Transitive(t TransitiveResult) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	if t.Flat {
		w("depsound transitive %s: %d version-change(s), %d added, %d removed.",
			t.label(), len(t.Changed), len(t.Added), len(t.Removed))
		w("  This is the WHOLE resolved set the bump moves (from the lockfile).")
	} else {
		w("depsound transitive %s: %d module version-change(s) (%d direct, %d indirect),",
			t.label(), len(t.Changed), t.DirectChanged, t.IndirectChanged)
		w("  %d added, %d removed. This is the WHOLE subtree the bump moves, direct AND", len(t.Added), len(t.Removed))
		w("  indirect (from go.mod incl. // indirect; go.sum is fuller with test-only).")
	}

	if len(t.Added) > 0 {
		w("")
		w("ADDED to your tree (%d) - NEW code, not a diff; census each you rely on:", len(t.Added))
		for _, m := range t.Added {
			w("  %s %s%s   depsound %s:%s %s", taint(m.Path), taint(m.To), t.tag(m.Indirect), t.Ecosystem, taint(m.Path), taint(m.To))
		}
	}
	if len(t.Removed) > 0 {
		w("")
		w("REMOVED from your tree (%d) - gone, nothing to fetch:", len(t.Removed))
		for _, m := range t.Removed {
			w("  %s %s%s", taint(m.Path), taint(m.From), t.tag(m.Indirect))
		}
	}

	if len(t.Changed) > 0 {
		w("")
		writeRouter(w, t.Changed, true)
	} else {
		w("")
		w("no version-changes to analyse (only additions/removals above).")
	}
	return b.String()
}

// label names the report by the lockfile the user gave, noting the analysis
// ecosystem when it differs (pnpm -> npm), so `transitive pnpm` never reads
// as if it ignored the pnpm argument.
func (t TransitiveResult) label() string {
	if t.Kind != "" && t.Kind != t.Ecosystem {
		return t.Kind + " (" + t.Ecosystem + " packages)"
	}
	return t.Ecosystem
}

// tag labels a module direct/indirect, unless the lockfile is flat (Cargo),
// where the distinction does not exist and would mislead.
func (t TransitiveResult) tag(indirect bool) string {
	if t.Flat {
		return ""
	}
	if indirect {
		return "  [indirect]"
	}
	return "  [direct]"
}
