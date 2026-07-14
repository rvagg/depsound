package output

import (
	"testing"

	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/stats"
)

// TestLedgerEveryCodeReachable is the first half of the enforcement contract:
// every code in AllSignalCodes must be produced by some derivation. A declared
// code with no fixture is dead (or a typo); adding a code forces adding a
// fixture here, which the renderer parity test (added with the migration) then
// forces into every output.
func TestLedgerEveryCodeReachable(t *testing.T) {
	got := map[string]bool{}
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
		Runnable: stats.Runnable{CgoTo: true}, // cgo newly introduced
		Compat:   stats.Compat{TypeFrom: "commonjs", TypeTo: "module"},
		Files: stats.FilesSection{Entries: []stats.FileEntry{
			{Path: "native.node", Status: "A", Excluded: true},
			{Path: "dist/b.js", Status: "M", Class: "generated", Added: 200},
		}},
		Action: &stats.ActionSection{
			CapsIntroduced: []string{"id-token"},
			UsingFrom:      "node20", UsingTo: "node24",
		},
	}))
	// exec present-in-both (not introduced) and the disabled-OSV degradation
	collect(Derive("present", &stats.Stats{Security: stats.Security{Queried: true}, Runnable: stats.Runnable{CgoFrom: true, CgoTo: true}}))
	collect(Derive("noosv", &stats.Stats{Security: stats.Security{Queried: false}}))
	// census + redirect
	collect(DeriveCensus("cen", &Census{Files: 10, Vulns: []osv.Vuln{{ID: "V"}}, Lifecycle: []manifest.Change{{Key: "postinstall"}}}))
	collect(DeriveRedirect("red", "github.com/fork/x@v1.0.0"))

	for _, code := range AllSignalCodes() {
		if !got[code] {
			t.Errorf("signal code %q is declared in AllSignalCodes but no fixture emits it; add a fixture or remove the code", code)
		}
	}
}

// TestLedgerVerdict: the headline is a pure function of the ledger, and a
// degradation can never read as clean.
func TestLedgerVerdict(t *testing.T) {
	// a disabled scan alone: not clean, coverage incomplete
	deg := Assess(Derive("d", &stats.Stats{Security: stats.Security{Queried: false}}))
	if deg.Clean() || deg.CoverageComplete {
		t.Errorf("a degradation must not read clean: %+v", deg)
	}

	// OSV ran, nothing found, no other change: genuinely clean
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
