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
	// Tree is the changed subtree rooted at the consumer's direct deps: only
	// branches leading to a changed/added node, so the churn reads with its
	// causality ("bumping A moved x and y") instead of as a flat list.
	// Populated when the lockfile kind carries edges (npm today); omitted,
	// never faked, otherwise.
	Tree []*ChurnNode `json:"churnTree,omitempty"`
	// TreeNote states why a tree is absent when one was possible (over the
	// churn budget): an elision is always said, never silent.
	TreeNote string `json:"churnTreeNote,omitempty"`
}

// ChurnNode is one node of the changed subtree. Mark: "^" bumped, "+" added,
// "" an unchanged node on the path to a change. Dedup marks a node whose
// subtree already rendered under an earlier branch, printed as (*).
type ChurnNode struct {
	Label string       `json:"label"`
	Mark  string       `json:"mark,omitempty"`
	Kids  []*ChurnNode `json:"children,omitempty"`
	Dedup bool         `json:"dedup,omitempty"`
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
		w("  This is the whole resolved set the bump moves (from the lockfile).")
	} else {
		w("depsound transitive %s: %d module version-change(s) (%d direct, %d indirect),",
			t.label(), len(t.Changed), t.DirectChanged, t.IndirectChanged)
		w("  %d added, %d removed. This is the whole subtree the bump moves, direct and", len(t.Added), len(t.Removed))
		w("  indirect (from go.mod incl. // indirect; go.sum is fuller with test-only).")
	}

	writeChurnTree(w, t.Tree)
	if t.TreeNote != "" {
		w("")
		w("  note: %s", t.TreeNote)
	}

	if len(t.Added) > 0 {
		w("")
		w("added to your tree (%d), new code, not a diff; census each you rely on:", len(t.Added))
		for _, m := range t.Added {
			w("  %s %s%s   depsound %s:%s %s", taint(m.Path), taint(m.To), t.tag(m.Indirect), t.Ecosystem, taint(m.Path), taint(m.To))
		}
	}
	if len(t.Removed) > 0 {
		w("")
		w("removed from your tree (%d), gone, nothing to fetch:", len(t.Removed))
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

// writeChurnTree renders the changed subtree with box-drawing and delta
// marks. Every elision is stated: a deduped subtree prints (*), and the
// caller flips to the flat summary instead of passing a tree it cannot
// honestly draw.
func writeChurnTree(w func(string, ...any), roots []*ChurnNode) {
	if len(roots) == 0 {
		return
	}
	w("")
	w("changed subtree (branches leading to a change; ^ bumped, + added, (*) shown above):")
	var walk func(n *ChurnNode, prefix string, last bool)
	walk = func(n *ChurnNode, prefix string, last bool) {
		branch, next := "|- ", "|  "
		if last {
			branch, next = "`- ", "   "
		}
		label := taint(n.Label)
		if n.Mark != "" {
			label = n.Mark + " " + label
		}
		if n.Dedup {
			label += " (*)"
		}
		w("  %s%s%s", prefix, branch, label)
		for i, k := range n.Kids {
			walk(k, prefix+next, i == len(n.Kids)-1)
		}
	}
	for i, r := range roots {
		walk(r, "", i == len(roots)-1)
	}
}
