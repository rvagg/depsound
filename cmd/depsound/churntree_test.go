package main

import (
	"fmt"
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
	tree, note := buildChurnTree(roots, edges, changed, nil)
	if note != "" {
		t.Errorf("a tiny tree needs no elision note: %q", note)
	}
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

	// a churn too wide to draw: no tree, and the note says so
	wide := map[string][]string{"top@1": nil}
	var many []output.ModuleRef
	for i := range churnRowBudget + 1 {
		id := fmt.Sprintf("x%d@2", i)
		wide["top@1"] = append(wide["top@1"], id)
		wide[id] = []string{fmt.Sprintf("y%d@2", i)} // a branch, so leaf-collapse cannot save it
		many = append(many, output.ModuleRef{Path: fmt.Sprintf("y%d", i), From: "1", To: "2"})
	}
	tree, note = buildChurnTree([]string{"top@1"}, wide, many, nil)
	if tree != nil || !strings.Contains(note, "suppressed") {
		t.Errorf("over-budget must suppress and say so: %d roots, note %q", len(tree), note)
	}
}

// Attribution answers "what dragged this in": the cause layer, by shortest
// path, with the subject standing in for a cause itself.
func TestAttributeCause(t *testing.T) {
	edges := map[string][]string{
		"root@1":  {"glob@10", "other@1"},
		"glob@10": {"deep@1"},
		"deep@1":  {"deeper@1"},
		"other@1": {"deeper@1"},
	}
	refs := []output.ModuleRef{
		{Path: "glob", To: "10"},    // a cause itself -> the subject
		{Path: "deep", To: "1"},     // under glob
		{Path: "deeper", To: "1"},   // reachable two ways; shortest wins
		{Path: "stranger", To: "1"}, // outside the graph
	}
	attributeCause("root@1", edges["root@1"], edges, refs)
	want := []string{"root@1", "glob@10", "other@1", ""}
	for i, w := range want {
		if refs[i].Via != w {
			t.Errorf("%s via %q, want %q", refs[i].Path, refs[i].Via, w)
		}
	}
}

// Compression bounds the render: deep branches summarise, wide runs of added
// leaves collapse, and both say so on the node they replace.
func TestCompressChurn(t *testing.T) {
	leaf := func(n string) *output.ChurnNode { return &output.ChurnNode{Label: n, Mark: "+"} }
	deep := &output.ChurnNode{Label: "d0", Kids: []*output.ChurnNode{
		{Label: "d1", Kids: []*output.ChurnNode{
			{Label: "d2", Kids: []*output.ChurnNode{
				{Label: "d3", Kids: []*output.ChurnNode{leaf("d4"), {Label: "d4b", Kids: []*output.ChurnNode{leaf("d5")}}}},
			}},
		}},
	}}
	compressChurn(deep, 0, maxChurnDepth)
	n := deep.Kids[0].Kids[0].Kids[0]
	if len(n.Kids) != 1 || !strings.Contains(n.Kids[0].Label, "3 more below, 2 of them changed or added") {
		t.Errorf("depth cap: %+v", n.Kids[0])
	}

	wide := &output.ChurnNode{Label: "w"}
	for i := range leafRunCollapse {
		wide.Kids = append(wide.Kids, leaf(string(rune('a'+i))))
	}
	wide.Kids = append(wide.Kids, &output.ChurnNode{Label: "branch", Kids: []*output.ChurnNode{leaf("x")}})
	compressChurn(wide, 0, maxChurnDepth)
	if len(wide.Kids) != 2 || wide.Kids[0].Label != "branch" ||
		!strings.Contains(wide.Kids[1].Label, "6 new packages") {
		t.Errorf("leaf collapse: %+v %+v", wide.Kids[0], wide.Kids[len(wide.Kids)-1])
	}
}
