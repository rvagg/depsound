package output

import (
	"testing"

	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/provenance"
	"github.com/rvagg/depsound/internal/stats"
)

// TestLedgerEveryCodeReachable is the first half of the enforcement contract:
// every code in AllSignalCodes must be produced by some derivation. A declared
// code with no fixture is dead (or a typo); adding a code forces adding a
// fixture here, which the renderer parity test (added with the migration) then
// forces into every output.
func TestLedgerEveryCodeReachable(t *testing.T) {
	got := map[Code]bool{}
	collect := func(l Ledger) {
		for _, s := range l.Signals {
			got[s.Code] = true
		}
	}

	// one Stats exercising every diff-derived code at once
	collect(Derive("all", &stats.Stats{
		Package: stats.PkgRef{Ecosystem: "gha"},
		Security: stats.Security{
			Queried:        true,
			Introduced:     []osv.Vuln{{ID: "GHSA-a"}},
			StillPresent:   []osv.Vuln{{ID: "GHSA-b"}},
			FixedByUpgrade: []osv.Vuln{{ID: "GHSA-c"}},
		},
		Runnable: stats.Runnable{CgoTo: true, Bin: []manifest.Change{{Key: "mycli"}}}, // cgo newly introduced, a new bin
		Compat:   stats.Compat{TypeFrom: "commonjs", TypeTo: "module"},
		Files: stats.FilesSection{Entries: []stats.FileEntry{
			{Path: "native.node", Status: "A", Excluded: true, Binary: true, BytesTo: 2 << 20},
			{Path: "prebuilt.wasm", Status: "M", Excluded: true, Binary: true, BytesFrom: 1 << 20, BytesTo: 3 << 20},
			{Path: "dist/b.js", Status: "M", Class: "generated", Added: 200},
		}},
		Action: &stats.ActionSection{
			CapsIntroduced: []string{"id-token"},
			UsingFrom:      "node20", UsingTo: "node24",
		},
		MovedRefs: []stats.MovedRef{{Side: "to", Ref: "v2.0.1", Prev: "aaaa", SHA: "bbbb"}},
	}))
	// exec present-in-both (not introduced), and the three not-queried OSV
	// states: disabled (covered eco, no scan), failed (scan errored),
	// unsupported (no OSV index for the eco).
	collect(Derive("present", &stats.Stats{Package: stats.PkgRef{Ecosystem: "go"}, Security: stats.Security{Queried: true}, Runnable: stats.Runnable{CgoFrom: true, CgoTo: true}}))
	collect(Derive("disabled", &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: false}}))
	collect(Derive("failed", &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: false, Note: "OSV lookup failed"}}))
	collect(Derive("unsupported", &stats.Stats{Package: stats.PkgRef{Ecosystem: "gha"}, Security: stats.Security{Queried: false}}))
	// artifact-hardening facts + integrity/exports degradations (the false-clean holes)
	collect(Derive("hard", &stats.Stats{
		Package:  stats.PkgRef{Ecosystem: "npm"},
		Security: stats.Security{Queried: true},
		Artifact: stats.Artifact{HostileEntries: []string{"../e"}, SkippedLinks: []string{"l"}, SourceTo: &stats.Source{Verification: "tls-only"}},
		Compat:   stats.Compat{ExportsError: "bad exports"},
	}))
	// census (incl. the biggest-unreviewed-file lead), redirect, failure
	collect(Derive("prov", &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: true}, Provenance: &provenance.Result{Queried: true, MaintainerChanged: true}}))
	collect(DeriveCensus("cen", &Census{Files: 10, OSVQueried: true, Vulns: []osv.Vuln{{ID: "V"}}, Lifecycle: []manifest.Change{{Key: "postinstall"}}, BigExcluded: "blob.bin"}))
	collect(DeriveRedirect("red", "github.com/fork/x@v1.0.0"))
	collect(DeriveFailure("bad", "extraction failed"))
	collect(DeriveUnavailable("gone", &Unavailable{Kind: "absent", Status: 404, URL: "u"}))
	collect(DeriveUnavailable("locked", &Unavailable{Kind: "denied", Status: 403, URL: "u"}))
	collect(DeriveUnavailable("flaky", &Unavailable{Kind: "transient", Status: 503, URL: "u"}))

	for _, code := range AllSignalCodes() {
		if !got[code] {
			t.Errorf("signal code %q is declared in AllSignalCodes but no fixture emits it; add a fixture or remove the code", code)
		}
	}
}

// TestLedgerVerdict: the headline is a pure function of the ledger, and a
// degradation can never read as clean.
func TestLedgerVerdict(t *testing.T) {
	// a disabled scan on a COVERED ecosystem: a degradation, not clean
	deg := Assess(Derive("d", &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: false}}))
	if deg.Clean() || deg.CoverageComplete {
		t.Errorf("a degradation must not read clean: %+v", deg)
	}

	// OSV unsupported for the ecosystem (gha) is a NOTE, not a gap: it must
	// still read clean, since there was no coverage to lose.
	na := Assess(Derive("n", &stats.Stats{Package: stats.PkgRef{Ecosystem: "gha"}, Security: stats.Security{Queried: false}}))
	if !na.Clean() {
		t.Errorf("an unsupported-OSV note must read clean (no gap): %+v", na)
	}

	// OSV ran, nothing found, no other change: actually clean
	clean := Assess(Derive("c", &stats.Stats{
		Security: stats.Security{Queried: true},
		Compat:   stats.Compat{TypeFrom: "commonjs", TypeTo: "commonjs"},
	}))
	if !clean.Clean() {
		t.Errorf("a completed clean scan should read clean: %+v", clean)
	}

	// a redirect is the loud tier
	if v := Assess(DeriveRedirect("r", "fork")); v.Tier != weightLook {
		t.Errorf("redirect should be the look tier, got %+v", v)
	}

	// a census whose OSV scan did not run on a covered ecosystem is a coverage
	// gap, never a silent clean-on-security
	if v := Assess(DeriveCensus("cg", &Census{Ecosystem: "npm", Files: 5, OSVQueried: false})); v.CoverageComplete {
		t.Errorf("a census with no OSV scan must not read coverage-complete: %+v", v)
	}
}

// TestLedgerDeterministicOrder: signals sort by weight desc then code, so every
// renderer inherits identical order regardless of derivation sequence.
func TestLedgerDeterministicOrder(t *testing.T) {
	l := Derive("o", &stats.Stats{
		Security: stats.Security{Queried: true, Introduced: []osv.Vuln{{ID: "X"}}},
		Compat:   stats.Compat{TypeFrom: "commonjs", TypeTo: "module"},
	})
	// osv.introduced (look) must sort before compat.change (weigh)
	if len(l.Signals) < 2 || l.Signals[0].Code != "osv.introduced" {
		t.Fatalf("expected osv.introduced first by weight, got %+v", l.Signals)
	}
	for i := 1; i < len(l.Signals); i++ {
		if l.Signals[i-1].Weight < l.Signals[i].Weight {
			t.Errorf("signals not weight-descending: %+v", l.Signals)
		}
	}
}

// looksExactRelease drives the moved-ref weight: an exact release tag
// re-pointing is the tj-actions vector, a floating tag re-points routinely.
func TestLooksExactRelease(t *testing.T) {
	exact := []string{"v4.2.1", "4.2.1", "v1.0.0.1"}
	floating := []string{"v4", "v4.2", "main", "release/v4", "v4.x", ""}
	for _, ref := range exact {
		if !looksExactRelease(ref) {
			t.Errorf("looksExactRelease(%q) = false, want true", ref)
		}
	}
	for _, ref := range floating {
		if looksExactRelease(ref) {
			t.Errorf("looksExactRelease(%q) = true, want false", ref)
		}
	}
}

// A census must carry the extractor's refusal evidence with the same weight
// as a diff: hostile members are the look tier, skipped links a coverage
// degradation, and neither can reach a clean verdict.
func TestDeriveCensusExtractionEvidence(t *testing.T) {
	l := DeriveCensus("cen", &Census{Files: 3, OSVQueried: true,
		HostileEntries: []string{"../evil", "/abs"}, SkippedLinks: []string{"l -> /etc"}})
	byCode := map[Code]Signal{}
	for _, s := range l.Signals {
		byCode[s.Code] = s
	}
	h, ok := byCode[CodeHostileEntry]
	if !ok || h.Weight != weightLook || h.Kind != KindFact {
		t.Errorf("hostile entries: want look-tier fact, got %+v", h)
	}
	if _, ok := byCode[CodeSkippedLink]; !ok {
		t.Errorf("skipped links missing from census ledger: %+v", l.Signals)
	}
	if Assess(l).Clean() {
		t.Error("a census with hostile entries must not read clean")
	}
}
