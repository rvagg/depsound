package output

import (
	"fmt"
	"sort"
	"strings"
)

// ModuleRef is a module that entered or left the resolved graph (no diff to
// analyse: added is new to the tree, removed is gone).
type ModuleRef struct {
	Path     string `json:"path"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Indirect bool   `json:"indirect"`
	// Via is what pulls this module in (a parent id, "+N more" when several),
	// so churn reads causally even where the tree is suppressed. Set only
	// where the source carries edges; empty is "not known", never "no parent".
	Via string `json:"via,omitempty"`
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
	// Projected names the package whose subtree was resolved (deps.dev) rather
	// than diffed from a lockfile pair: set only in the no-lockfile mode, and
	// the renderer scopes trust on it.
	Projected string `json:"projected,omitempty"`
	// Flat marks a set with no direct/indirect distinction the consumer can
	// use: Cargo.lock does not carry one, and a projected subtree's is
	// relative to the dep, not to you. Suppressed rather than faked.
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

	switch {
	case t.Projected != "":
		w("depsound transitive %s: %d version-change(s), %d added, %d removed.",
			t.label(), len(t.Changed), len(t.Added), len(t.Removed))
		w("  %s's own tree at each endpoint, resolved live by deps.dev in isolation:", taint(t.Projected))
		w("  an upper bound on what it adds to you (your tree may already carry some, and")
		w("  optional/platform-conditional deps are counted whole), and not reproducible")
		w("  the way a diff is. For your actual tree, generate a lockfile per endpoint")
		w("  (resolution only, no package code runs) -> depsound guide, \"No lockfile?\".")
	case t.Flat:
		w("depsound transitive %s: %d version-change(s), %d added, %d removed.",
			t.label(), len(t.Changed), len(t.Added), len(t.Removed))
		w("  This is the whole resolved set the bump moves (from the lockfile).")
	default:
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
		where := "added to your tree"
		if t.Projected != "" {
			where = "added under " + taint(t.Projected)
		}
		w("")
		w("%s (%d), new code, not a diff; census any you rely on -> depsound %s:<name> <version>:",
			where, len(t.Added), t.Ecosystem)
		t.writeGrouped(w, t.Added, func(m ModuleRef) string { return m.To })
	}
	if len(t.Removed) > 0 {
		where := "removed from your tree"
		if t.Projected != "" {
			where = "no longer pulled by " + taint(t.Projected)
		}
		w("")
		w("%s (%d), gone, nothing to fetch:", where, len(t.Removed))
		t.writeGrouped(w, t.Removed, func(m ModuleRef) string { return m.From })
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
// as if it ignored the pnpm argument. A projected run names the package
// instead: there was no lockfile.
func (t TransitiveResult) label() string {
	switch {
	case t.Projected != "":
		return t.Ecosystem + ":" + taint(t.Projected) + " (projected)"
	case t.Kind != "" && t.Kind != t.Ecosystem:
		return t.Kind + " (" + t.Ecosystem + " packages)"
	}
	return t.Ecosystem
}

// writeGrouped renders a module set grouped by what pulls it in, biggest
// cause first, so a wide churn reads as "X pulled these N" instead of an
// alphabetical wall (the why-path collapse). Groups keep every name: this
// compresses the render, never the set. Modules the source could not
// attribute get their own heading rather than folding into a neighbour's
// cause. version picks the end of the change this list is about.
func (t TransitiveResult) writeGrouped(w func(string, ...any), refs []ModuleRef, version func(ModuleRef) string) {
	byVia := map[string][]ModuleRef{}
	var vias []string
	for _, m := range refs {
		if _, ok := byVia[m.Via]; !ok {
			vias = append(vias, m.Via)
		}
		byVia[m.Via] = append(byVia[m.Via], m)
	}
	sort.Slice(vias, func(i, j int) bool {
		if a, b := len(byVia[vias[i]]), len(byVia[vias[j]]); a != b {
			return a > b
		}
		return vias[i] < vias[j]
	})
	for _, via := range vias {
		items := byVia[via]
		labels := make([]string, len(items))
		for i, m := range items {
			labels[i] = taint(m.Path) + " " + taint(version(m)) + t.tag(m.Indirect)
		}
		indent := "  "
		if via != "" {
			w("  via %s (%d):", taint(via), len(items))
			indent = "    "
		} else if len(vias) > 1 {
			// with other groups attributed, the gap is worth naming; alone it
			// just means this source carries no edges, said in the header
			w("  not attributed (%d) (new direct dep, or outside the resolved graph):", len(items))
			indent = "    "
		}
		for _, line := range wrapJoin(labels, 72) {
			w("%s%s", indent, line)
		}
	}
}

// wrapJoin packs comma-separated items into lines of at most width runes,
// never splitting an item.
func wrapJoin(items []string, width int) []string {
	var lines []string
	cur := ""
	for _, it := range items {
		switch {
		case cur == "":
			cur = it
		case len([]rune(cur))+2+len([]rune(it)) <= width:
			cur += ", " + it
		default:
			lines = append(lines, cur+",")
			cur = it
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
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
	w("changed subtree (branches leading to a change; ↑/↓ up/downgrade, + added, (*) already shown):")
	var walk func(n *ChurnNode, prefix string, last bool)
	walk = func(n *ChurnNode, prefix string, last bool) {
		branch, next := "├── ", "│   "
		if last {
			branch, next = "└── ", "    "
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
