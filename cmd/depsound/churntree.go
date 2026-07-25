package main

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/rvagg/depsound/internal/output"
)

// versionArrow marks a change by direction: ↓ downgrade, ↑ otherwise. Not-
// comparable versions (non-semver, or equal) default to ↑; the from→to in the
// label carries the truth, the glyph is only a scan hint.
func versionArrow(from, to string) string {
	f, t := "v"+strings.TrimPrefix(from, "v"), "v"+strings.TrimPrefix(to, "v")
	if semver.IsValid(f) && semver.IsValid(t) && semver.Compare(f, t) > 0 {
		return "↓"
	}
	return "↑"
}

// The tree is a scan aid, so its cost is bounded by rows, not by node count:
// it is drawn as deep as fits, and a churn that will not fit even shallow
// falls back to the attributed list (which names every module either way).
const (
	churnRowBudget   = 45
	maxChurnDepth    = 3
	leafRunCollapse  = 6
	dedupRunCollapse = 4
)

// buildChurnTree prunes a lockfile's who-pulls-whom graph to the branches
// that lead to a changed or added node, rooted at the consumer's direct deps,
// so churn reads with its causality. Marks come from the diff: an arrow for a
// version change (node id keyed by the new version), "+" for an added node.
// The first encounter of a node renders its subtree; repeats print (*) (npm
// graphs also carry cycles, which the seen-set breaks). The returned note
// states any elision; an empty tree with an empty note means the graph simply
// held none of the changed modules.
func buildChurnTree(roots []string, edges map[string][]string, changed []output.ModuleRef, added []output.ModuleRef) ([]*output.ChurnNode, string) {
	mark := map[string]string{} // node id -> display label override
	kind := map[string]string{}
	for _, c := range changed {
		id := c.Path + "@" + c.To
		mark[id] = fmt.Sprintf("%s %s → %s", c.Path, c.From, c.To)
		kind[id] = versionArrow(c.From, c.To)
	}
	for _, a := range added {
		id := a.Path + "@" + a.To
		mark[id] = id
		kind[id] = "+"
	}

	// include = nodes that reach a marked node (reverse reachability)
	rev := map[string][]string{}
	for from, kids := range edges {
		for _, k := range kids {
			rev[k] = append(rev[k], from)
		}
	}
	include := map[string]bool{}
	var queue []string
	for id := range mark {
		include[id] = true
		queue = append(queue, id)
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, p := range rev[n] {
			if !include[p] {
				include[p] = true
				queue = append(queue, p)
			}
		}
	}
	if len(include) == 0 {
		return nil, ""
	}

	build := func() []*output.ChurnNode {
		seen := map[string]bool{}
		var node func(id string) *output.ChurnNode
		node = func(id string) *output.ChurnNode {
			n := &output.ChurnNode{Label: id, Mark: kind[id]}
			if m := mark[id]; m != "" {
				n.Label = m
			}
			if seen[id] {
				n.Dedup = true
				return n
			}
			seen[id] = true
			kids := append([]string(nil), edges[id]...)
			sort.Strings(kids)
			prev := ""
			for _, k := range kids {
				if k == prev || !include[k] {
					continue // duplicate edge (npm dedup copies), or a clean branch
				}
				prev = k
				n.Kids = append(n.Kids, node(k))
			}
			return n
		}
		var out []*output.ChurnNode
		rootSet := append([]string(nil), roots...)
		sort.Strings(rootSet)
		prev := ""
		for _, r := range rootSet {
			if r == prev || !include[r] {
				continue
			}
			prev = r
			out = append(out, node(r))
		}
		// a marked node no root reaches (an orphaned edge, or a root-level dep
		// list the lockfile did not carry) still renders, never drops
		var orphans []string
		for id := range mark {
			if !seen[id] {
				orphans = append(orphans, id)
			}
		}
		sort.Strings(orphans)
		for _, id := range orphans {
			if !seen[id] {
				out = append(out, node(id))
			}
		}
		return out
	}

	// draw as deep as the row budget allows, shallower before nothing
	for depth := maxChurnDepth; depth >= 1; depth-- {
		out := build()
		rows := 0
		for _, r := range out {
			compressChurn(r, 0, depth)
			countChurn(r, &rows, new(int))
		}
		if rows <= churnRowBudget {
			if depth < maxChurnDepth {
				return out, "churn tree shortened to fit: deeper branches show as a `N more below` count, and everything they stand for is named in the lists below"
			}
			return out, ""
		}
	}
	return nil, fmt.Sprintf("churn tree suppressed: %d changed/added modules do not fit a readable tree; the attributed list below is the honest render (--format=json carries the full set)",
		len(changed)+len(added))
}

// compressChurn bounds what a branch costs to read: past maxDepth it is
// replaced by a count of what it holds, and a wide run of added leaves or of
// already-shown repeats collapses to one line. Each replacement says what it
// stands for, and the names live on in the lists below, so this compresses
// the render, never the set.
func compressChurn(n *output.ChurnNode, depth, maxDepth int) {
	if len(n.Kids) == 0 {
		return
	}
	if depth >= maxDepth {
		nodes, marked := 0, 0
		for _, k := range n.Kids {
			countChurn(k, &nodes, &marked)
		}
		n.Kids = []*output.ChurnNode{{Label: fmt.Sprintf("%d more below, %d of them changed or added (named in the lists below)", nodes, marked)}}
		return
	}
	for _, k := range n.Kids {
		compressChurn(k, depth+1, maxDepth)
	}
	var leaves, dedups, keep []*output.ChurnNode
	for _, k := range n.Kids {
		switch {
		case k.Dedup:
			dedups = append(dedups, k)
		case len(k.Kids) == 0 && k.Mark == "+":
			leaves = append(leaves, k)
		default:
			keep = append(keep, k)
		}
	}
	n.Kids = keep
	n.Kids = append(n.Kids, collapseRun(leaves, leafRunCollapse, "+", "%d new packages, no changes below them (all named below)")...)
	n.Kids = append(n.Kids, collapseRun(dedups, dedupRunCollapse, "", "%d more already shown above")...)
}

// collapseRun returns the nodes as they are, or one node standing for all of
// them once the run reaches the threshold.
func collapseRun(run []*output.ChurnNode, threshold int, mark, format string) []*output.ChurnNode {
	if len(run) < threshold {
		return run
	}
	return []*output.ChurnNode{{Mark: mark, Label: fmt.Sprintf(format, len(run))}}
}

func countChurn(n *output.ChurnNode, nodes, marked *int) {
	*nodes++
	if n.Mark != "" {
		*marked++
	}
	for _, k := range n.Kids {
		countChurn(k, nodes, marked)
	}
}

// attributeCause fills each ref's Via with the dependency it hangs off, so a
// wide churn reads as "X dragged these in" rather than an alphabetical wall.
// The causes are the layer that explains the churn to the reviewer: your
// direct deps for a lockfile diff, the bumped package's direct deps for a
// projection (subject, which is what a cause itself is attributed to).
// Attribution is the shortest path from a cause, seeded in sorted order so it
// is deterministic; a node the graph does not reach keeps an empty Via.
func attributeCause(subject string, causes []string, edges map[string][]string, refs []output.ModuleRef) {
	cause := map[string]string{}
	queue := append([]string(nil), causes...)
	sort.Strings(queue)
	for _, c := range queue {
		cause[c] = c
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		kids := append([]string(nil), edges[n]...)
		sort.Strings(kids)
		for _, k := range kids {
			if _, seen := cause[k]; seen {
				continue
			}
			cause[k] = cause[n]
			queue = append(queue, k)
		}
	}
	for i := range refs {
		// a removed module exists only at its old version, so key on whichever
		// end this graph holds
		version := refs[i].To
		if version == "" {
			version = refs[i].From
		}
		id := refs[i].Path + "@" + version
		switch c := cause[id]; c {
		case "":
		case id:
			refs[i].Via = subject // a cause itself: nothing under it explains it
		default:
			refs[i].Via = c
		}
	}
}
