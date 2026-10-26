package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/manifest"
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

func TestTransitiveRendersLockChangesOutsideVersionChanges(t *testing.T) {
	result := TransitiveResult{
		Ecosystem: "npm", Kind: "npm", Flat: true,
		LockChanges: []manifest.LockChange{{
			Ecosystem: "npm", Name: "mirror", Version: "1.2.3",
			From: []manifest.LockSource{{Location: "old", Resolved: "https://old.example/pkg.tgz", Host: "old.example", Integrity: "sha512-old"}},
			To:   []manifest.LockSource{{Location: "new", Resolved: "https://new.example/pkg.tgz", Host: "new.example", Integrity: "sha512-new"}},
		}},
	}
	out := Transitive(result)
	for _, value := range []string{"0 version-change(s), 1 source/integrity change(s)", "https://old.example/pkg.tgz", "https://new.example/pkg.tgz"} {
		if !strings.Contains(out, value) {
			t.Errorf("transitive lock change lost %q:\n%s", value, out)
		}
	}
	if strings.Contains(out, "only additions/removals") {
		t.Errorf("lock source changes must not be framed as additions/removals only:\n%s", out)
	}
}

func TestTransitiveSourceCollectionAndMetadataCoverage(t *testing.T) {
	metadata := &manifest.LockChange{
		Ecosystem: "npm", Name: "mirror", Kind: "added", ToVersion: "1",
		To: []manifest.LockSource{{Resolved: "https://mirror.example/x.tgz"}},
	}
	measured := TransitiveResult{
		Ecosystem: "npm", Kind: "npm", Flat: true,
		Added: []ModuleRef{{Path: "mirror", To: "1", Declared: metadata}},
	}
	measured.SetCoverage()
	if measured.Coverage.Uninspected != 1 || len(measured.Coverage.Checked) == 0 || len(measured.Coverage.NotChecked) == 0 {
		t.Fatalf("metadata coverage is incomplete: %+v", measured.Coverage)
	}
	coverageJSON, err := json.Marshal(measured)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"checked"`, `"notChecked"`, `"uninspected":1`} {
		if !strings.Contains(string(coverageJSON), key) {
			t.Errorf("coverage JSON missing %s: %s", key, coverageJSON)
		}
	}
	uncollected := TransitiveResult{Ecosystem: "go", Kind: "go", Flat: true}
	if measured.sourceFacts() == uncollected.sourceFacts() {
		t.Errorf("measured and uncollected source metadata were not distinguishable")
	}
}
