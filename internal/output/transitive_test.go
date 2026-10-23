package output

import (
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/stats"
)

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
	for _, want := range []string{"arrayref@0.3.10", "proc-macro1 1.0.107", "14 files", "build.rs"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
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
				Artifact: stats.Artifact{Unavailable: []*stats.Unavailable{{
					Side: "to", Version: "0.3.10", Kind: "absent", Status: 404, Stage: "artifact", URL: "https://example.invalid/arrayref.crate",
				}}},
				Security: stats.Security{Queried: true, Introduced: []osv.Vuln{{ID: "MAL-ROOT", Kind: osv.KindMalware}}},
			},
		}},
	}
	out := Transitive(result)
	for _, want := range []string{"MAL-ROOT", "https://example.invalid/arrayref.crate"} {
		if !strings.Contains(out, want) {
			t.Errorf("projection gap missing %q:\n%s", want, out)
		}
	}
}

func TestTransitiveAdditionOnlyRetainsAdvisoryAndCoverage(t *testing.T) {
	result := TransitiveResult{
		Ecosystem: "crates", Flat: true,
		Added: []ModuleRef{
			{Path: "gone", To: "2.0.0", Analysis: &BulkResult{Census: &Census{
				Ecosystem: "crates", Name: "gone", Version: "2.0.0", OSVQueried: true,
				Unavailable: &stats.Unavailable{
					Kind: "absent", URL: "https://registry.example/" + strings.Repeat("u", 250), Status: 410,
					Hint: "operator-evidence-marker",
				},
				Vulns: []osv.Vuln{{ID: "MAL-ADDED", Kind: osv.KindMalware}},
			}}},
			{Path: "present", To: "1.0.0", Analysis: &BulkResult{Census: &Census{
				Ecosystem: "crates", Name: "present", Version: "1.0.0", Files: 3, BuildRS: true,
			}}},
		},
	}
	out := Transitive(result)
	for _, fact := range []string{"MAL-ADDED", "operator-evidence-marker", "build.rs", "run for 1", "not run or incomplete for 1", "1 acquisition failure(s)"} {
		if !strings.Contains(out, fact) {
			t.Errorf("addition-only report lost census evidence or coverage %q:\n%s", fact, out)
		}
	}
}
