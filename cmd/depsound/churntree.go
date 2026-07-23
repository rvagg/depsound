package main

import (
	"fmt"
	"sort"

	"github.com/rvagg/depsound/internal/output"
)

// churnBudget is the flip point: past this many changed/added nodes a tree
// is noise, so the render falls back to the flat summary (stated, never
// silent).
const churnBudget = 30

// buildChurnTree prunes a lockfile's who-pulls-whom graph to the branches
// that lead to a changed or added node, rooted at the consumer's direct
// deps, so churn reads with its causality. Marks come from the diff: "^" a
// version change (node id keyed by the NEW version), "+" an added node.
// The first encounter of a node renders its subtree; repeats print (*)
// (npm graphs also carry cycles, which the seen-set breaks).
func buildChurnTree(roots []string, edges map[string][]string, changed []output.ModuleRef, added []output.ModuleRef) []*output.ChurnNode {
	if len(changed)+len(added) > churnBudget {
		return nil // over budget: the caller's flat summary is the honest render
	}
	mark := map[string]string{} // node id -> display label override
	kind := map[string]string{}
	for _, c := range changed {
		id := c.Path + "@" + c.To
		mark[id] = fmt.Sprintf("%s %s -> %s", c.Path, c.From, c.To)
		kind[id] = "^"
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
		return nil
	}

	seen := map[string]bool{}
	var build func(id string) *output.ChurnNode
	build = func(id string) *output.ChurnNode {
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
			n.Kids = append(n.Kids, build(k))
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
		out = append(out, build(r))
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
			out = append(out, build(id))
		}
	}
	return out
}

// churnSummaryNote is the flip side of the budget: what the caller prints
// instead of a tree it cannot honestly draw.
func churnSummaryNote(n int) string {
	return fmt.Sprintf("churn tree suppressed: %d changed/added nodes exceed the %d-node budget; the flat list below is the honest render (--format=json carries the full graph-free set)", n, churnBudget)
}
