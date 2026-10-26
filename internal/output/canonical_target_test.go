package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/provenance"
)

func canonicalTargetResult() BulkResult {
	change := &manifest.LockChange{
		Ecosystem: "npm", Name: "legacy", Kind: "version", FromVersion: "1.0.0", ToVersion: "2.0.0", ToRegistry: true,
		From: []manifest.LockSource{{Resolved: "https://legacy.example/legacy.tgz", Host: "legacy.example"}},
		To:   []manifest.LockSource{{Resolved: "https://registry.npmjs.org/legacy/-/legacy-2.0.0.tgz", Host: "registry.npmjs.org"}},
	}
	return BulkResult{
		Ref: change.Ref(), LockChange: change,
		Census: &Census{
			Ecosystem: "npm", Name: "legacy", Version: "2.0.0", Files: 7, OSVQueried: true,
			Vulns:      []osv.Vuln{{ID: "GHSA-target-target-target"}},
			Lifecycle:  []manifest.Change{{Key: "postinstall", Status: "present"}},
			Provenance: &provenance.Result{Queried: true, Deprecated: true},
		},
	}
}

func TestCanonicalRegistryTargetRetainsDeclarationAndCensus(t *testing.T) {
	result := canonicalTargetResult()
	for name, render := range map[string]func([]BulkResult) string{"text": Bulk, "markdown": Markdown} {
		t.Run(name, func(t *testing.T) {
			out := render([]BulkResult{result})
			for _, want := range []string{"legacy.example", "GHSA-target-target-target", "postinstall", "deprecated"} {
				if !strings.Contains(out, want) {
					t.Errorf("combined result lost %q:\n%s", want, out)
				}
			}
		})
	}
}

func TestCanonicalRegistryTargetTransitiveCoverage(t *testing.T) {
	result := canonicalTargetResult()
	transitive := TransitiveResult{Ecosystem: "npm", Kind: "npm", Changed: []BulkResult{result}}
	transitive.SetCoverage()
	if transitive.Coverage.Uninspected != 0 {
		t.Fatalf("successful target census must not be wholly metadata-only: %#v", transitive.Coverage)
	}
	if transitive.Coverage.UninspectedBaselines != 1 {
		t.Fatalf("successful target census hid its missing baseline: %#v", transitive.Coverage)
	}
	encoded, err := json.Marshal(transitive)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"GHSA-target-target-target", `"toRegistry":true`} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("transitive JSON lost %q: %s", want, encoded)
		}
	}
}

func TestCanonicalRegistryTargetFailureKeepsBaselineGap(t *testing.T) {
	for name, failed := range map[string]BulkResult{
		"unavailable": func() BulkResult {
			result := canonicalTargetResult()
			result.Census = nil
			result.Unavailable = &Unavailable{Kind: "absent", Version: "2.0.0", URL: "https://registry.npmjs.org/legacy/-/legacy-2.0.0.tgz"}
			return result
		}(),
		"error": func() BulkResult {
			result := canonicalTargetResult()
			result.Census = nil
			result.Err = "registry target census failed"
			return result
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			ledger := DeriveBulkResult(failed)
			wantCode := CodeAnalysisFailed
			if failed.Unavailable != nil {
				wantCode = CodeArtifactAbsent
			}
			var declaration, failure bool
			for _, signal := range ledger.Signals {
				declaration = declaration || signal.Code == CodeLockSource
				failure = failure || signal.Code == wantCode
			}
			if !declaration || !failure {
				t.Fatalf("combined failure lost evidence: %+v", ledger)
			}
			for _, render := range []func([]BulkResult) string{Bulk, Markdown} {
				out := render([]BulkResult{failed})
				if !strings.Contains(out, "legacy.example") {
					t.Errorf("old acquisition lost from failed target review:\n%s", out)
				}
				if failed.Err != "" && !strings.Contains(out, failed.Err) {
					t.Errorf("target failure reason lost:\n%s", out)
				}
			}
		})
	}
}
