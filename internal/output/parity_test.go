package output

import (
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/stats"
)

// ledgerRenderers are the renderers driven by the shared ledger. bulk and text
// join here as they migrate onto it; the parity test then forces each to
// surface every signal code, so a renderer cannot silently narrow the ledger.
var ledgerRenderers = []struct {
	name string
	fn   func([]BulkResult) string
}{
	{"markdown", Markdown},
}

// signalMarkers is a stable substring each signal code must produce in rendered
// output, anchored on the code (not wording): wording may change, presence may
// not. It must cover exactly AllSignalCodes (asserted below), so a new code
// cannot be added without giving it a marker and a fixture.
func signalMarkers() map[Code]string {
	return map[Code]string{
		CodeOSVIntroduced:  "introduces",
		CodeOSVStill:       "still present",
		CodeOSVFixed:       "fixes",
		CodeOSVDisabled:    "scan not run",
		CodeExecIntroduced: "new execution surface",
		CodeExecPresent:    "execution surface present",
		CodeCompatChange:   "module format changed",
		CodeGeneratedDelta: "generated code changed",
		CodeGHACaps:        "runner capability",
		CodeGHAUsing:       "runtime changed",
		CodeBinaryAdded:    "binary/opaque file added",
		CodeRedirect:       "(redirect)",
		CodeCensusNew:      "adopting",
		CodeCensusCVE:      "at this version",
		CodeCensusExec:     "runs code on install/build",
		CodeCensusBig:      "largest unreviewed file",
		CodeAnalysisFailed: "could not be analysed",
	}
}

// parityFixture is a BulkResult set whose ledgers, together, emit every signal
// code, so one render exercises the whole matrix.
func parityFixture() []BulkResult {
	return []BulkResult{
		{Ref: "npm:a 1 -> 2", Stats: &stats.Stats{
			Security: stats.Security{Queried: true,
				Introduced:     []osv.Vuln{{ID: "GHSA-a"}},
				StillPresent:   []osv.Vuln{{ID: "GHSA-b"}},
				FixedByUpgrade: []osv.Vuln{{ID: "GHSA-c"}},
			},
			Runnable: stats.Runnable{CgoTo: true},
			Compat:   stats.Compat{TypeFrom: "commonjs", TypeTo: "module"},
			Files: stats.FilesSection{Entries: []stats.FileEntry{
				{Path: "native.node", Status: "A", Excluded: true},
				{Path: "dist/b.js", Status: "M", Class: "generated", Added: 200},
			}},
			Action: &stats.ActionSection{CapsIntroduced: []string{"id-token"}, UsingFrom: "node20", UsingTo: "node24"},
		}},
		{Ref: "go:b v1 -> v2", Stats: &stats.Stats{Security: stats.Security{Queried: true}, Runnable: stats.Runnable{CgoFrom: true, CgoTo: true}}},
		{Ref: "npm:c 1 -> 2", Stats: &stats.Stats{Security: stats.Security{Queried: false}}},
		{Ref: "npm:new 1.0.0", Census: &Census{Files: 12, Vulns: []osv.Vuln{{ID: "V"}}, Lifecycle: []manifest.Change{{Key: "postinstall"}}, BigExcluded: "blob.bin"}},
		{Ref: "go:trusted/x", Redirect: "github.com/fork/x@v1.0.0"},
		{Ref: "npm:broke 1 -> 2", Err: "fetch failed"},
	}
}

// TestSignalMarkersCoverAllCodes: every declared code needs a marker, so adding
// a code forces a parity marker (and thus a fixture in parityFixture).
func TestSignalMarkersCoverAllCodes(t *testing.T) {
	m := signalMarkers()
	for _, code := range AllSignalCodes() {
		if _, ok := m[code]; !ok {
			t.Errorf("signal code %q has no parity marker; add one so every renderer is checked for it", code)
		}
	}
	if len(m) != len(AllSignalCodes()) {
		t.Errorf("signalMarkers has %d entries, AllSignalCodes has %d; a marker exists for a code that was removed", len(m), len(AllSignalCodes()))
	}
}

// TestRendererParity is the enforcement spine: every ledger-driven renderer must
// surface every signal code. A renderer that drops one, or a new renderer that
// narrows the ledger, fails here.
func TestRendererParity(t *testing.T) {
	results := parityFixture()
	markers := signalMarkers()
	for _, rd := range ledgerRenderers {
		out := rd.fn(results)
		for code, marker := range markers {
			if !strings.Contains(out, marker) {
				t.Errorf("renderer %s omits signal %q (marker %q)\n%s", rd.name, code, marker, out)
			}
		}
	}
}
