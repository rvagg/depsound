package output

import (
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/stats"
)

// ledgerRenderers are the renderers driven by the shared ledger, each with its
// OWN marker per code: bulk shouts terminal WARNINGs while markdown stays calm,
// so a shared marker cannot check both. The parity test forces each renderer to
// surface every code; a renderer that narrows the ledger, or a new one added
// without markers, fails. text/census stay off the list (they are the detailed
// reports, not summaries).
var ledgerRenderers = []struct {
	name    string
	fn      func([]BulkResult) string
	markers map[Code]string
}{
	{"markdown", Markdown, markdownMarkers()},
	{"bulk", Bulk, bulkMarkers()},
}

// markers are anchored on the code, not exact wording: each is a stable
// substring the renderer must emit for that code. Both maps must cover exactly
// AllSignalCodes (asserted below), so a code cannot ship without a marker (and
// thus a rendering) in every ledger renderer.
func markdownMarkers() map[Code]string {
	return map[Code]string{
		CodeOSVIntroduced:  "introduces",
		CodeOSVStill:       "still present",
		CodeOSVFixed:       "fixes",
		CodeOSVDisabled:    "scan not run",
		CodeOSVFailed:      "scan failed",
		CodeOSVUnsupported: "not applicable",
		CodeExecIntroduced: "new execution surface",
		CodeExecPresent:    "execution surface present",
		CodeCompatChange:   "module format changed",
		CodeGeneratedDelta: "generated code changed",
		CodeGHACaps:        "runner capability",
		CodeGHAUsing:       "runtime changed",
		CodeBinaryAdded:    "file(s) added",
		CodeBinaryChanged:  "file(s) changed",
		CodeRedirect:       "(redirect)",
		CodeCensusNew:      "adopting",
		CodeCensusCVE:      "at this version",
		CodeCensusExec:     "runs code on install/build",
		CodeCensusBig:      "largest unreviewed file",
		CodeAnalysisFailed: "could not be analysed",
		CodeArtifactAbsent: "artifact unavailable",
		CodeArtifactDenied: "access denied",
		CodeArtifactFetch:  "fetch failed",
	}
}

func bulkMarkers() map[Code]string {
	return map[Code]string{
		CodeOSVIntroduced:  "introduces",
		CodeOSVStill:       "still present",
		CodeOSVFixed:       "fixes",
		CodeOSVDisabled:    "scan not run",
		CodeOSVFailed:      "scan failed",
		CodeOSVUnsupported: "not applicable",
		CodeExecIntroduced: "new execution surface",
		CodeExecPresent:    "execution surface present",
		CodeCompatChange:   "compatibility changed",
		CodeGeneratedDelta: "generated/bundled code changed",
		CodeGHACaps:        "runner capability",
		CodeGHAUsing:       "runtime changed",
		CodeBinaryAdded:    "file(s) added",
		CodeBinaryChanged:  "file(s) changed",
		CodeRedirect:       "REDIRECTED off the registry",
		CodeCensusNew:      "whole footprint unreviewed",
		CodeCensusCVE:      "known CVE(s)",
		CodeCensusExec:     "runs install/build code",
		CodeCensusBig:      "largest unreviewed",
		CodeAnalysisFailed: "FAILED (not analysed)",
		CodeArtifactAbsent: "artifact unavailable",
		CodeArtifactDenied: "access denied",
		CodeArtifactFetch:  "fetch failed",
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
				{Path: "native.node", Status: "A", Excluded: true, Binary: true, BytesTo: 2 << 20},
				{Path: "prebuilt.wasm", Status: "M", Excluded: true, Binary: true, BytesFrom: 1 << 20, BytesTo: 3 << 20},
				{Path: "dist/b.js", Status: "M", Class: "generated", Added: 200},
			}},
			Action: &stats.ActionSection{CapsIntroduced: []string{"id-token"}, UsingFrom: "node20", UsingTo: "node24"},
		}},
		{Ref: "go:b v1 -> v2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "go"}, Security: stats.Security{Queried: true}, Runnable: stats.Runnable{CgoFrom: true, CgoTo: true}}},
		{Ref: "npm:c 1 -> 2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: false}}},                            // disabled
		{Ref: "npm:f 1 -> 2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: false, Note: "OSV lookup failed"}}}, // failed
		{Ref: "gha:u v1 -> v2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "gha"}, Security: stats.Security{Queried: false}}},                          // unsupported
		{Ref: "npm:new 1.0.0", Census: &Census{Files: 12, Vulns: []osv.Vuln{{ID: "V"}}, Lifecycle: []manifest.Change{{Key: "postinstall"}}, BigExcluded: "blob.bin"}},
		{Ref: "go:trusted/x", Redirect: "github.com/fork/x@v1.0.0"},
		{Ref: "npm:broke 1 -> 2", Err: "extraction failed"},
		{Ref: "npm:gone 1 -> 2", Unavailable: &Unavailable{Kind: "absent", Status: 404, URL: "https://registry.npmjs.org/gone/-/gone-2.tgz"}},
		{Ref: "npm:locked 1 -> 2", Unavailable: &Unavailable{Kind: "denied", Status: 403, URL: "https://registry.example/locked"}},
		{Ref: "npm:flaky 1 -> 2", Unavailable: &Unavailable{Kind: "transient", Status: 503, URL: "https://registry.example/flaky"}},
	}
}

// TestSignalMarkersCoverAllCodes: every renderer must declare a marker for every
// code, so a code cannot be added without forcing a marker (and thus a
// rendering) in each ledger renderer.
func TestSignalMarkersCoverAllCodes(t *testing.T) {
	for _, rd := range ledgerRenderers {
		for _, code := range AllSignalCodes() {
			if _, ok := rd.markers[code]; !ok {
				t.Errorf("renderer %s has no marker for code %q; add one so it is checked for it", rd.name, code)
			}
		}
		if len(rd.markers) != len(AllSignalCodes()) {
			t.Errorf("renderer %s has %d markers, AllSignalCodes has %d; a marker exists for a removed code", rd.name, len(rd.markers), len(AllSignalCodes()))
		}
	}
}

// TestRendererParity is the enforcement spine: every ledger-driven renderer must
// surface every signal code. A renderer that drops one, or a new renderer that
// narrows the ledger, fails here.
func TestRendererParity(t *testing.T) {
	results := parityFixture()
	for _, rd := range ledgerRenderers {
		out := rd.fn(results)
		for code, marker := range rd.markers {
			if !strings.Contains(out, marker) {
				t.Errorf("renderer %s omits signal %q (marker %q)\n%s", rd.name, code, marker, out)
			}
		}
	}
}
