package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/stats"
)

// A projected subtree is deps.dev's isolated resolve of the dep's own tree,
// so the render must never let it read as "your tree changed by this much".
func TestTransitiveProjectedScopesTheClaim(t *testing.T) {
	out := Transitive(TransitiveResult{
		Ecosystem: "npm",
		Projected: "typescript",
		Flat:      true,
		Added:     []ModuleRef{{Path: "@ts/linux-x64", To: "7.0.2"}},
		Removed:   []ModuleRef{{Path: "old-dep", From: "1.0.0"}},
	})
	for _, want := range []string{"(projected)", "in isolation", "upper bound", "added under typescript", "no longer pulled by typescript"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// the consumer-tree wording belongs to the lockfile modes only
	for _, deny := range []string{"added to your tree", "removed from your tree", "[direct]"} {
		if strings.Contains(out, deny) {
			t.Errorf("projected render claims %q:\n%s", deny, out)
		}
	}
}

// The lockfile modes keep their own framing: this is the tree you install.
func TestTransitiveLockfileFraming(t *testing.T) {
	out := Transitive(TransitiveResult{
		Ecosystem: "npm", Kind: "pnpm",
		Added: []ModuleRef{{Path: "left-pad", To: "1.3.0"}},
	})
	if !strings.Contains(out, "added to your tree") || strings.Contains(out, "projected") {
		t.Errorf("lockfile framing lost:\n%s", out)
	}
	// pnpm resolves npm packages; the label must not hide the argument given
	if !strings.Contains(out, "pnpm (npm packages)") {
		t.Errorf("label lost the lockfile kind:\n%s", out)
	}
}

func TestTransitiveAddedNodeCarriesCensus(t *testing.T) {
	analysis := &BulkResult{
		Ref:    "crates:proc-macro1 1.0.107",
		Census: &Census{Files: 14, BuildRS: true},
	}
	result := TransitiveResult{
		Ecosystem: "crates",
		Flat:      true,
		Added: []ModuleRef{{
			Path: "proc-macro1", To: "1.0.107", Via: "arrayref@0.3.10", Analysis: analysis,
		}},
	}
	out := Transitive(result)
	for _, want := range []string{"via arrayref@0.3.10", "proc-macro1 1.0.107", "14 files", "runs install/build code (build.rs)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"analysis":`, `"buildRs":true`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("JSON missing %s: %s", want, raw)
		}
	}
}

func TestTransitiveProjectionGapKeepsRootAnalysis(t *testing.T) {
	result := TransitiveResult{
		Ecosystem:     "crates",
		Projected:     "arrayref",
		Flat:          true,
		ProjectionGap: "deps.dev has not resolved cargo:arrayref@0.3.10",
		Changed: []BulkResult{{
			Ref: "crates:arrayref 0.3.9 -> 0.3.10",
			Stats: &stats.Stats{
				Package: stats.PkgRef{Ecosystem: "crates", Name: "arrayref", From: "0.3.9", To: "0.3.10"},
				Artifact: stats.Artifact{Unavailable: &stats.Unavailable{
					Side: "to", Version: "0.3.10", Kind: "absent", URL: "https://example.invalid/arrayref.crate",
				}},
				Security: stats.Security{Queried: true},
			},
		}},
	}
	out := Transitive(result)
	for _, want := range []string{"subtree projection unavailable", "root bump is still analysed", "artifact unavailable"} {
		if !strings.Contains(out, want) {
			t.Errorf("projection gap missing %q:\n%s", want, out)
		}
	}
	for _, falseClaim := range []string{"upper bound on what it adds", "whole resolved set"} {
		if strings.Contains(out, falseClaim) {
			t.Errorf("projection gap falsely claims %q:\n%s", falseClaim, out)
		}
	}
}
