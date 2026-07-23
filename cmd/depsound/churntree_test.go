package main

import (
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/npmpkg"
	"github.com/rvagg/depsound/internal/output"
)

// The churn tree keeps only branches leading to a change, dedups repeats
// with (*), survives cycles, and flips to nil past the budget.
func TestBuildChurnTree(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{
		"": {"dependencies":{"a":"^1","clean":"^1"}},
		"node_modules/a": {"version":"1.0.0","dependencies":{"b":"^1","c":"^1"}},
		"node_modules/b": {"version":"2.0.0","dependencies":{"c":"^1","a":"^1"}},
		"node_modules/c": {"version":"3.0.1"},
		"node_modules/clean": {"version":"1.0.0"}}}`
	roots, edges, err := npmpkg.PackageLockGraph([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	changed := []output.ModuleRef{{Path: "c", From: "3.0.0", To: "3.0.1"}}
	tree := buildChurnTree(roots, edges, changed, nil)
	if len(tree) != 1 || !strings.HasPrefix(tree[0].Label, "a@") {
		t.Fatalf("want one root a@ (clean pruned), got %+v", tree)
	}
	var flat []string
	var walk func(n *output.ChurnNode, d int)
	walk = func(n *output.ChurnNode, d int) {
		flat = append(flat, n.Label)
		for _, k := range n.Kids {
			walk(k, d+1)
		}
	}
	walk(tree[0], 0)
	joined := strings.Join(flat, "\n")
	if !strings.Contains(joined, "c 3.0.0 → 3.0.1") {
		t.Errorf("changed node missing:\n%s", joined)
	}
	if strings.Contains(joined, "clean") {
		t.Errorf("clean branch must prune:\n%s", joined)
	}
	// c appears under a AND under b: exactly one full render + one dedup
	count := strings.Count(joined, "c 3.0.0 → 3.0.1")
	if count != 2 {
		t.Errorf("want c rendered twice (once deduped), got %d:\n%s", count, joined)
	}

	// over budget: nil (the caller states the flip)
	var many []output.ModuleRef
	for range churnBudget + 1 {
		many = append(many, output.ModuleRef{Path: "x", From: "1", To: "2"})
	}
	if buildChurnTree(roots, edges, many, nil) != nil {
		t.Error("over-budget must return nil")
	}
}
