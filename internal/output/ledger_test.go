package output

import (
	"strings"
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
			Pins: []stats.ActionPin{{Side: "from", Kind: "sha", Ref: "aaaa"}, {Side: "to", Kind: "tag", Ref: "v2"}}, // weakened
		},
		MovedRefs: []stats.MovedRef{{Side: "to", Ref: "v2.0.1", Prev: "aaaa", SHA: "bbbb"}},
	}))
	// the other pin-delta shapes: strengthened, and same-grade standing context
	collect(Derive("pinup", &stats.Stats{Package: stats.PkgRef{Ecosystem: "gha"}, Security: stats.Security{Queried: false},
		Action: &stats.ActionSection{Pins: []stats.ActionPin{{Side: "from", Kind: "tag", Ref: "v1"}, {Side: "to", Kind: "sha", Ref: "bbbb"}}}}))
	collect(Derive("pinsame", &stats.Stats{Package: stats.PkgRef{Ecosystem: "gha"}, Security: stats.Security{Queried: false},
		Action: &stats.ActionSection{Pins: []stats.ActionPin{{Side: "from", Kind: "tag", Ref: "v1"}, {Side: "to", Kind: "tag", Ref: "v2"}}}}))
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
		Artifact: stats.Artifact{HostileEntries: []string{"../e"}, SkippedLinks: []string{"l"}, SourceTo: &stats.Source{Verification: "tls-only"},
			BytesFrom: 4 << 20, BytesTo: 4 << 20, UnreviewableTo: 3 << 20}, // became bundle-dominated
		Compat: stats.Compat{ExportsError: "bad exports"},
	}))
	// census (incl. the biggest-unreviewed-file lead), redirect, failure
	collect(Derive("range", &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: true},
		Resolution: &stats.Resolution{ToSpec: "^2.0.0"}}))
	collect(Derive("prov", &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: true},
		Provenance: &provenance.Result{Queried: true, MaintainerChanged: true, Sources: map[string]string{"depsdev": "complete", "registry": "failed"}}}))
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

// The pin-grade delta doctrine: a downgrade is the re-point-enabling move
// (look), an upgrade is a positive note, tag->tag is standing context that
// must NOT weigh (a Dependabot tag bump every cycle tripping the headline is
// exactly the stale-noise this tool exists to kill), and a branch pin weighs
// every time.
func TestDerivePinDelta(t *testing.T) {
	derive := func(fromKind, toKind string) Ledger {
		return Derive("p", &stats.Stats{Package: stats.PkgRef{Ecosystem: "gha"}, Security: stats.Security{Queried: false},
			Action: &stats.ActionSection{Pins: []stats.ActionPin{
				{Side: "from", Kind: fromKind, Ref: "a"}, {Side: "to", Kind: toKind, Ref: "b"}}}})
	}
	find := func(l Ledger, code Code) *Signal {
		for i := range l.Signals {
			if l.Signals[i].Code == code {
				return &l.Signals[i]
			}
		}
		return nil
	}

	if s := find(derive("sha", "tag"), CodeGHAPinWeakened); s == nil || s.Weight != weightLook {
		t.Errorf("sha->tag: want look-tier weakened, got %+v", s)
	}
	if s := find(derive("tag", "branch"), CodeGHAPinWeakened); s == nil || s.Weight != weightLook {
		t.Errorf("tag->branch: want look-tier weakened, got %+v", s)
	}
	if s := find(derive("tag", "sha"), CodeGHAPinRaised); s == nil || s.Weight != weightPositive {
		t.Errorf("tag->sha: want positive raised, got %+v", s)
	}
	tagBoth := derive("tag", "tag")
	if s := find(tagBoth, CodeGHAPinGrade); s == nil || s.Weight != weightPositive {
		t.Errorf("tag->tag: want positive context, got %+v", s)
	}
	if !Assess(tagBoth).Clean() {
		t.Error("a tag->tag bump must stay clean (context, not a headline flip)")
	}
	if s := find(derive("branch", "branch"), CodeGHAPinGrade); s == nil || s.Weight != weightWeigh {
		t.Errorf("branch->branch: want weigh, got %+v", s)
	}
	if s := find(derive("sha", "sha"), CodeGHAPinGrade); s != nil {
		t.Errorf("sha->sha: immutable both sides needs no grade line, got %+v", s)
	}
}

// Adoption is the moment the pin is chosen: the same tag grade that is quiet
// context in a diff weighs in a census, and capabilities present are a
// context heuristic.
func TestDeriveCensusGHA(t *testing.T) {
	l := DeriveCensus("cen", &Census{Ecosystem: "gha", Files: 3, GHAPinKind: "tag", GHACaps: []string{"network egress"}})
	var pin, caps *Signal
	for i := range l.Signals {
		switch l.Signals[i].Code {
		case CodeGHAPinGrade:
			pin = &l.Signals[i]
		case CodeGHACaps:
			caps = &l.Signals[i]
		}
	}
	if pin == nil || pin.Weight != weightWeigh {
		t.Errorf("census tag pin: want weigh, got %+v", pin)
	}
	if caps == nil || caps.Weight != weightPositive || caps.Kind != KindHeuristic {
		t.Errorf("census caps: want positive heuristic, got %+v", caps)
	}
	if l2 := DeriveCensus("cen2", &Census{Ecosystem: "gha", Files: 3, GHAPinKind: "branch"}); Assess(l2).Tier != weightLook {
		t.Errorf("census branch pin: want look tier, got %+v", Assess(l2))
	}
}

// A provenance source that failed is lost coverage: the gap signal fires, and
// a partial answer can never read Clean().
func TestProvenanceGapSignal(t *testing.T) {
	partial := Derive("p", &stats.Stats{Security: stats.Security{Queried: true},
		Provenance: &provenance.Result{Queried: true, Sources: map[string]string{"depsdev": "complete", "registry": "failed"}}})
	var gap *Signal
	for i := range partial.Signals {
		if partial.Signals[i].Code == CodeProvenanceGap {
			gap = &partial.Signals[i]
		}
	}
	if gap == nil || gap.Kind != KindDegradation || !strings.Contains(gap.Detail, "registry") {
		t.Errorf("want a degradation naming the failed source, got %+v", gap)
	}
	if Assess(partial).Clean() {
		t.Error("a partial provenance answer must not read clean")
	}

	full := Derive("f", &stats.Stats{Security: stats.Security{Queried: true},
		Provenance: &provenance.Result{Queried: true, Sources: map[string]string{"depsdev": "complete", "registry": "complete"}}})
	for _, s := range full.Signals {
		if s.Code == CodeProvenanceGap {
			t.Errorf("full coverage must not emit a gap: %+v", s)
		}
	}
	// unsupported sources are not lost coverage (go has no registry concept)
	goP := Derive("g", &stats.Stats{Package: stats.PkgRef{Ecosystem: "go"}, Security: stats.Security{Queried: true},
		Provenance: &provenance.Result{Queried: true, Sources: map[string]string{"depsdev": "complete", "registry": "unsupported"}}})
	for _, s := range goP.Signals {
		if s.Code == CodeProvenanceGap {
			t.Errorf("unsupported source must not emit a gap: %+v", s)
		}
	}
}

// Structural unreviewability follows the delta doctrine: the flip to
// bundle-dominated weighs, present-in-both is calm context that must stay
// Clean() (tripping every typescript/wrangler bump forever is the noise this
// tool exists to kill), and adoption weighs because the cost is still
// avoidable there.
func TestUnreviewableMassDoctrine(t *testing.T) {
	derive := func(fromUnrev, toUnrev int64) Ledger {
		return Derive("u", &stats.Stats{Security: stats.Security{Queried: true},
			Artifact: stats.Artifact{BytesFrom: 4 << 20, BytesTo: 4 << 20,
				UnreviewableFrom: fromUnrev, UnreviewableTo: toUnrev}})
	}
	find := func(l Ledger) *Signal {
		for i := range l.Signals {
			if l.Signals[i].Code == CodeUnreviewable {
				return &l.Signals[i]
			}
		}
		return nil
	}

	if s := find(derive(0, 3<<20)); s == nil || s.Weight != weightWeigh {
		t.Errorf("flip to dominated: want weigh, got %+v", s)
	}
	both := derive(3<<20, 3<<20)
	if s := find(both); s == nil || s.Weight != weightPositive {
		t.Errorf("dominated both sides: want positive context, got %+v", s)
	}
	if !Assess(both).Clean() {
		t.Error("present-in-both must stay clean (context, not a headline flip)")
	}
	if s := find(derive(3<<20, 0)); s == nil || s.Weight != weightPositive {
		t.Errorf("flip away from dominated: want positive note, got %+v", s)
	}
	if s := find(derive(0, 0)); s != nil {
		t.Errorf("source-dominated artifact needs no line, got %+v", s)
	}
	// below the floor: half the bytes but under a megabyte stays quiet
	small := Derive("s", &stats.Stats{Security: stats.Security{Queried: true},
		Artifact: stats.Artifact{BytesFrom: 400 << 10, BytesTo: 400 << 10, UnreviewableTo: 300 << 10}})
	if s := find(small); s != nil {
		t.Errorf("small artifacts stay quiet, got %+v", s)
	}

	cen := DeriveCensus("c", &Census{Ecosystem: "npm", Files: 50, OSVQueried: true, Bytes: 10 << 20,
		ByClass: []stats.ClassAgg{{Class: "generated", Bytes: 6 << 20}, {Class: "source", Bytes: 4 << 20}}})
	var cs *Signal
	for i := range cen.Signals {
		if cen.Signals[i].Code == CodeUnreviewable {
			cs = &cen.Signals[i]
		}
	}
	if cs == nil || cs.Weight != weightWeigh {
		t.Errorf("census dominance: want weigh at adoption, got %+v", cs)
	}
}
