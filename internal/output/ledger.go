package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/stats"
)

// SignalKind is a signal's trust tier, the distinction the whole tool rests on:
// a FACT is verified truth (trust and act), a HEURISTIC is evadable
// pattern-matching (navigate and inspect), a DEGRADATION is coverage lost (a
// check did not complete, so silence here is emphatically not safety), a NOTE
// is informational (a check that does not APPLY here, which is not a gap).
type SignalKind int

const (
	KindFact SignalKind = iota
	KindHeuristic
	KindDegradation
	KindNote
)

// Lens is the value dimension a signal speaks to: adversarial security, or
// non-adversarial compat/impact, or the coverage boundary itself.
type Lens int

const (
	LensSecurity Lens = iota
	LensCompat
	LensCoverage
)

// signal weights drive the headline tier and the collapse threshold. A
// renderer may shorten a low-weight signal into a count, but never drop one at
// or above the fact floor (weightWeigh).
const (
	weightPositive = 0 // a merge argument (fixes); never trips the headline
	weightWeigh    = 1
	weightLook     = 2
)

// Code is a signal's stable identifier: the anchor the parity tests and the
// report JSON key on. It is typed so a typo or rename is a compile error rather
// than a red test, and it marshals to its string value so the JSON stays
// readable. Typing prevents typos; it does NOT give exhaustiveness (Go has no
// exhaustive switch), so the parity test is still what catches omissions.
type Code string

const (
	CodeOSVIntroduced     Code = "osv.introduced"
	CodeOSVStill          Code = "osv.still"
	CodeOSVFixed          Code = "osv.fixed"
	CodeOSVDisabled       Code = "coverage.osv.disabled"
	CodeOSVUnsupported    Code = "coverage.osv.unsupported"
	CodeOSVFailed         Code = "coverage.osv.failed"
	CodeExecIntroduced    Code = "exec.introduced"
	CodeExecPresent       Code = "exec.present"
	CodeCompatChange      Code = "compat.change"
	CodeGeneratedDelta    Code = "generated.delta"
	CodeGHACaps           Code = "gha.capsIntroduced"
	CodeGHAUsing          Code = "gha.using"
	CodeGHARefMoved       Code = "gha.refMoved"    // mutable ref resolves to a different commit than last fetch
	CodeGHAPinWeakened    Code = "gha.pinWeakened" // pin grade dropped (sha->tag/branch, tag->branch): the re-point enabling move
	CodeGHAPinRaised      Code = "gha.pinRaised"   // pin grade rose toward sha
	CodeGHAPinGrade       Code = "gha.pinGrade"    // the standing grade: same-grade context in a diff, adoption fact in a census
	CodeBinaryAdded       Code = "binary.added"
	CodeBinaryChanged     Code = "binary.changed"
	CodeRedirect          Code = "redirect"
	CodeCensusNew         Code = "census.new"
	CodeCensusCVE         Code = "census.cve"
	CodeCensusExec        Code = "census.exec"
	CodeCensusBig         Code = "census.bigExcluded"
	CodeAnalysisFailed    Code = "analysis.failed"
	CodeArtifactAbsent    Code = "artifact.absent"          // the artifact URL is not retrievable (404/410)
	CodeArtifactDenied    Code = "artifact.denied"          // access denied (401/403)
	CodeArtifactFetch     Code = "artifact.fetchFail"       // transient acquisition failure
	CodeHostileEntry      Code = "artifact.hostile"         // hostile archive member skipped at extraction
	CodeSkippedLink       Code = "artifact.skippedLink"     // symlink/hardlink not materialized (uninspected)
	CodeIntegrityWeak     Code = "integrity.tlsOnly"        // TLS-trust-only, no registry integrity/checksum-DB
	CodeExportsUnresolved Code = "compat.exportsUnresolved" // exports/resolution delta could not be computed
	CodeBinDelta          Code = "bin.delta"                // installed executable (bin) entries changed
	CodeProvenanceAnomaly Code = "provenance.anomaly"       // publisher/attestation/repo/yank account-takeover shape
	CodeProvenanceGap     Code = "coverage.provenance"      // a provenance source failed; that coverage was lost, not clean
)

// allCodes is the single source of the code set. AllSignalCodes returns it, and
// the parity/reachability tests require a fixture and a marker for each, so a
// code cannot be added to the model without proving it reaches every output.
var allCodes = []Code{
	CodeOSVIntroduced, CodeOSVStill, CodeOSVFixed,
	CodeOSVDisabled, CodeOSVUnsupported, CodeOSVFailed,
	CodeExecIntroduced, CodeExecPresent,
	CodeCompatChange, CodeGeneratedDelta,
	CodeGHACaps, CodeGHAUsing, CodeGHARefMoved,
	CodeGHAPinWeakened, CodeGHAPinRaised, CodeGHAPinGrade,
	CodeBinaryAdded, CodeBinaryChanged,
	CodeRedirect,
	CodeCensusNew, CodeCensusCVE, CodeCensusExec, CodeCensusBig,
	CodeAnalysisFailed,
	CodeArtifactAbsent, CodeArtifactDenied, CodeArtifactFetch,
	CodeHostileEntry, CodeSkippedLink, CodeIntegrityWeak, CodeExportsUnresolved,
	CodeBinDelta, CodeProvenanceAnomaly, CodeProvenanceGap,
}

func AllSignalCodes() []Code { return allCodes }

// Signal is one derived finding. Code is the stable identifier the parity tests
// anchor on: wording (Title/Detail) may change freely, the Code may not.
// Title/Detail are RAW; each renderer escapes them for its own medium.
type Signal struct {
	Code   Code
	Kind   SignalKind
	Lens   Lens
	Weight int
	Title  string
	Detail string
}

// Ledger is the single derived signal set for one dependency change. Inclusion
// is decided HERE and nowhere else; renderers loop over Signals and choose only
// presentation, never what to show.
type Ledger struct {
	Ref     string
	Signals []Signal
}

// addOSVGap classifies a not-queried OSV scan into its signal, shared by the
// diff and census paths so both read a missing scan identically: unsupported (a
// NOTE, no gap: the ecosystem has no OSV index), failed (a degradation carrying
// the reason), or disabled (a degradation: OSV was turned off for this run).
func addOSVGap(add func(Code, SignalKind, Lens, int, string, string), eco, note string) {
	switch {
	case !osvSupported(eco):
		add(CodeOSVUnsupported, KindNote, LensCoverage, weightPositive,
			"known-CVE scan not applicable", "OSV has no advisory index for the "+eco+" ecosystem")
	case note != "":
		add(CodeOSVFailed, KindDegradation, LensCoverage, weightWeigh,
			"known-CVE scan failed", note)
	default:
		add(CodeOSVDisabled, KindDegradation, LensCoverage, weightWeigh,
			"known-CVE scan not run", "OSV was disabled for this dependency")
	}
}

func osvSupported(eco string) bool { _, ok := osv.Ecosystem(eco); return ok }

// Derive turns a diff's Stats into its signal ledger. This is the ONE place
// that decides what counts; every renderer consumes the result.
func Derive(ref string, s *stats.Stats) Ledger {
	l := Ledger{Ref: ref}
	add := func(code Code, k SignalKind, lens Lens, w int, title, detail string) {
		l.Signals = append(l.Signals, Signal{Code: code, Kind: k, Lens: lens, Weight: w, Title: title, Detail: detail})
	}

	// OSV status is derived from what actually ran, never assumed. A scan that
	// did not APPLY (no OSV index for the ecosystem, e.g. gha) is a NOTE, not a
	// gap; a scan that was disabled or FAILED on a covered ecosystem is a
	// degradation that must not read as clean.
	switch {
	case !s.Security.Queried:
		addOSVGap(add, s.Package.Ecosystem, s.Security.Note)
	default:
		if n := len(s.Security.Introduced); n > 0 {
			add(CodeOSVIntroduced, KindFact, LensSecurity, weightLook,
				fmt.Sprintf("introduces %d known CVE(s)", n), joinVulnIDs(s.Security.Introduced, 5))
		}
		if n := len(s.Security.StillPresent); n > 0 {
			add(CodeOSVStill, KindFact, LensSecurity, weightWeigh,
				fmt.Sprintf("%d known CVE(s) still present after the bump", n), joinVulnIDs(s.Security.StillPresent, 5))
		}
		if n := len(s.Security.FixedByUpgrade); n > 0 {
			add(CodeOSVFixed, KindFact, LensSecurity, weightPositive,
				fmt.Sprintf("fixes %d advisory(ies)", n), "")
		}
	}

	// execution surface, generated delta, compat: reuse the existing digest so
	// the ledger agrees with today's renderers on what fired.
	d := digestOf(s)
	if d.exec {
		what := strings.Join(humanExec(d.execWhat), ", ")
		if execIntroduced(d.execWhat) {
			add(CodeExecIntroduced, KindFact, LensSecurity, weightLook, "new execution surface", what)
		} else {
			add(CodeExecPresent, KindFact, LensSecurity, weightWeigh, "execution surface present", what)
		}
	}
	if d.genDelta > 0 {
		add(CodeGeneratedDelta, KindHeuristic, LensCompat, weightWeigh,
			"generated/bundled code changed", fmt.Sprintf("%s, +/-%s lines", d.genFile, commas(d.genDelta)))
	}
	if d.compat {
		add(CodeCompatChange, KindFact, LensCompat, weightWeigh, "compatibility changed", rawCompat(s))
	}
	// a bin delta changes what a command on PATH (npx/the .bin shim) runs: a
	// FACT worth weighing, so a bump that only re-points an executable is not
	// invisible.
	if n := len(s.Runnable.Bin); n > 0 {
		names := make([]string, 0, n)
		for _, c := range s.Runnable.Bin {
			names = append(names, c.Key)
		}
		add(CodeBinDelta, KindFact, LensCompat, weightWeigh,
			fmt.Sprintf("installed executable(s) changed: %d bin entry(ies)", n), firstN(names, 5))
	}

	// GitHub Actions execution model (gha only). CapsIntroduced is the delta
	// that matters, but it comes from an evadable marker grep, so it is a
	// HEURISTIC to navigate, never a fact; the runtime move (using) is a real
	// compat fact.
	if a := s.Action; a != nil {
		if len(a.CapsIntroduced) > 0 {
			add(CodeGHACaps, KindHeuristic, LensSecurity, weightWeigh,
				"new runner capability referenced (grep of the executed code, evadable)", strings.Join(a.CapsIntroduced, ", "))
		}
		if a.UsingFrom != a.UsingTo && a.UsingFrom != "" && a.UsingTo != "" {
			add(CodeGHAUsing, KindFact, LensCompat, weightWeigh,
				"action runtime changed", a.UsingFrom+" -> "+a.UsingTo)
		}
		derivePinDelta(add, a.Pins)
	}

	// a mutable gha ref observed re-pointing between runs. Re-pointing an
	// exact-release tag is the tj-actions vector (look now); a floating major
	// tag (v4) re-points on every release (weigh, still worth knowing what
	// the new commit is).
	for _, m := range s.MovedRefs {
		w := weightWeigh
		title := "floating ref re-pointed since last fetch"
		if looksExactRelease(m.Ref) {
			w = weightLook
			title = "release tag re-pointed since last fetch (the tj-actions vector)"
		}
		add(CodeGHARefMoved, KindFact, LensSecurity, w, title,
			fmt.Sprintf("%s %q now %.12s, was %.12s; re-analysed at the new commit", m.Side, m.Ref, m.SHA, m.Prev))
	}

	// binaries carry a ZERO line delta (git -/-), so line-based ranking hides
	// them; rank by BYTES and name every one. A newly-added opaque file is
	// fact-grade regardless of size (an ideal payload channel); a changed one
	// weighs (dist/native rebuild, or drift).
	var addedBin, changedBin []stats.FileEntry
	for _, e := range s.Files.Entries {
		if !e.Binary {
			continue
		}
		switch e.Status {
		case "A":
			addedBin = append(addedBin, e)
		case "M", "R":
			changedBin = append(changedBin, e)
		}
	}
	if len(addedBin) > 0 {
		add(CodeBinaryAdded, KindFact, LensSecurity, weightLook,
			fmt.Sprintf("%d binary/opaque file(s) added", len(addedBin)), binaryList(addedBin, false))
	}
	if len(changedBin) > 0 {
		add(CodeBinaryChanged, KindHeuristic, LensCompat, weightWeigh,
			fmt.Sprintf("%d binary/opaque file(s) changed", len(changedBin)), binaryList(changedBin, true))
	}

	// Artifact-hardening facts and integrity/coverage degradations that otherwise
	// live only in Stats.Notes. Without these a change whose ONLY effect is one of
	// them (a skipped traversal member, a TLS-only fetch, an unresolved exports
	// delta) would reach Clean(): the false-clean the ledger exists to prevent.
	if n := len(s.Artifact.HostileEntries); n > 0 {
		add(CodeHostileEntry, KindFact, LensSecurity, weightLook,
			fmt.Sprintf("%d hostile archive member(s) skipped at extraction", n), firstN(s.Artifact.HostileEntries, 5))
	}
	if n := len(s.Artifact.SkippedLinks); n > 0 {
		add(CodeSkippedLink, KindDegradation, LensCoverage, weightPositive,
			fmt.Sprintf("%d symlink/hardlink(s) not materialized; their contents were not inspected", n), firstN(s.Artifact.SkippedLinks, 5))
	}
	if integrityTLSOnly(s) {
		add(CodeIntegrityWeak, KindDegradation, LensCoverage, weightPositive,
			"artifact verified by TLS trust only (no registry integrity or checksum-DB record)", "")
	}
	if s.Compat.ExportsError != "" {
		add(CodeExportsUnresolved, KindDegradation, LensCoverage, weightWeigh,
			"exports/resolution compatibility could not be computed", s.Compat.ExportsError)
	}

	// provenance anomaly (npm/crates): the account-takeover shape, a hard prior-
	// version delta (publisher change, dropped/mismatched attestation, repo
	// mismatch, yank), so no per-package baseline is needed. Install-script and
	// bin deltas are excluded here: they already surface as exec + bin.delta.
	if p := s.Provenance; p != nil && p.Queried {
		var shapes []string
		if p.MaintainerChanged {
			shapes = append(shapes, "publisher changed")
		}
		if p.AttestationDropped {
			shapes = append(shapes, "build attestation dropped")
		}
		if p.AttestedMismatch {
			shapes = append(shapes, "attested from a different repo")
		}
		if p.RepoMismatch {
			shapes = append(shapes, "claimed repo != source repo")
		}
		if p.Yanked {
			shapes = append(shapes, "version yanked")
		}
		if len(shapes) > 0 {
			add(CodeProvenanceAnomaly, KindFact, LensSecurity, weightLook,
				"provenance anomaly (account-takeover shape)", strings.Join(shapes, ", "))
		}
	}
	// a provenance source that failed is lost coverage, exactly like a failed
	// OSV scan: the fields it carries are silently absent, so their absence
	// must not read as "no anomalies"
	if p := s.Provenance; p != nil {
		if failed := p.FailedSources(); len(failed) > 0 {
			add(CodeProvenanceGap, KindDegradation, LensCoverage, weightWeigh,
				"publish provenance incomplete", "lookup failed: "+strings.Join(failed, "; "))
		}
	}

	sortSignals(l.Signals)
	return l
}

// firstN joins up to n of xs with a "+K more" tail, so a long hostile/skipped
// list points at examples without becoming a wall.
func firstN(xs []string, n int) string {
	if len(xs) <= n {
		return strings.Join(xs, ", ")
	}
	return strings.Join(xs[:n], ", ") + fmt.Sprintf(", +%d more", len(xs)-n)
}

// pinGrade orders gha pin kinds: sha (immutable) > tag (mutable, re-pointable)
// > branch (unpinned, moves on every push). Unknown reads as tag (the pinOf
// fallback for pre-RefKind sidecars).
func pinGrade(kind string) int {
	switch kind {
	case "sha":
		return 2
	case "branch":
		return 0
	}
	return 1
}

// derivePinDelta applies the delta doctrine to the pin grade of a gha bump: a
// DOWNGRADE is the re-point-enabling move (look now); an upgrade is worth a
// positive note; the same mutable grade on both sides is standing context (a
// tag bump every Dependabot cycle must not trip the headline), except a
// branch pin, which weighs every time (there is no stable thing under review).
func derivePinDelta(add func(Code, SignalKind, Lens, int, string, string), pins []stats.ActionPin) {
	var pf, pt *stats.ActionPin
	for i := range pins {
		switch pins[i].Side {
		case "from":
			pf = &pins[i]
		case "to":
			pt = &pins[i]
		}
	}
	if pf == nil || pt == nil {
		return
	}
	refs := fmt.Sprintf("%q -> %q", pf.Ref, pt.Ref)
	switch gf, gt := pinGrade(pf.Kind), pinGrade(pt.Kind); {
	case gt < gf:
		add(CodeGHAPinWeakened, KindFact, LensSecurity, weightLook,
			"pin weakened: "+pf.Kind+" -> "+pt.Kind,
			refs+"; the move that enables a later re-point, verify it is intentional")
	case gt > gf:
		add(CodeGHAPinRaised, KindFact, LensSecurity, weightPositive,
			"pin strengthened: "+pf.Kind+" -> "+pt.Kind, refs)
	case pt.Kind == "branch":
		add(CodeGHAPinGrade, KindFact, LensSecurity, weightWeigh,
			"branch-pinned on both sides (unpinned; you run whatever is there)",
			refs+"; pin a tag or, better, a sha")
	case pt.Kind == "tag":
		add(CodeGHAPinGrade, KindFact, LensSecurity, weightPositive,
			"tag-pinned on both sides (mutable, re-pointable)",
			refs+"; resolved shas recorded, prefer a sha pin")
	}
}

// looksExactRelease reports whether a gha ref is shaped like an exact release
// tag (vX.Y.Z), which convention treats as pointing at one release forever, as
// opposed to a floating major/minor tag (v4, v4.2) or a branch, which move
// routinely. Shape is the only distinction available: a tag carries no
// declared mutability policy.
func looksExactRelease(ref string) bool {
	parts := strings.Split(strings.TrimPrefix(ref, "v"), ".")
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return len(parts) >= 3
}

// integrityTLSOnly reports whether either side was verified by TLS trust alone
// (no registry integrity or checksum-DB record). gha pins are git refs, not
// registry artifacts, so the concept does not apply there (matching the note
// the stats builder already suppresses for gha).
func integrityTLSOnly(s *stats.Stats) bool {
	if s.Package.Ecosystem == "gha" {
		return false
	}
	for _, src := range []*stats.Source{s.Artifact.SourceFrom, s.Artifact.SourceTo} {
		if src != nil && strings.HasPrefix(src.Verification, "tls-only") {
			return true
		}
	}
	return false
}

// DeriveCensus turns a newly-adopted version's footprint into its ledger. A new
// dependency is unreviewed surface by definition, so it always carries a signal.
func DeriveCensus(ref string, c *Census) Ledger {
	l := Ledger{Ref: ref}
	add := func(code Code, k SignalKind, lens Lens, w int, title, detail string) {
		l.Signals = append(l.Signals, Signal{Code: code, Kind: k, Lens: lens, Weight: w, Title: title, Detail: detail})
	}
	add(CodeCensusNew, KindFact, LensCompat, weightWeigh,
		fmt.Sprintf("new dependency, %s file(s) unreviewed", commas(c.Files)), "")
	// OSV status honestly: a scan that ran reports its CVEs (or nothing); a scan
	// that did NOT run is a coverage gap, never a silent clean-on-security.
	if !c.OSVQueried {
		addOSVGap(add, c.Ecosystem, c.OSVNote)
	} else if len(c.Vulns) > 0 {
		add(CodeCensusCVE, KindFact, LensSecurity, weightLook,
			fmt.Sprintf("%d known CVE(s) at this version", len(c.Vulns)), joinVulnIDs(c.Vulns, 5))
	}
	if c.hasExec() {
		add(CodeCensusExec, KindFact, LensSecurity, weightLook,
			"runs code on install/build", strings.Join(censusExecWhat(c), ", "))
	}
	// adoption is the moment the pin is chosen, so the grade weighs here even
	// though the same grade is quiet context in a diff (delta doctrine): the
	// agent can still choose the resolved sha instead.
	switch c.GHAPinKind {
	case "tag":
		add(CodeGHAPinGrade, KindFact, LensSecurity, weightWeigh,
			"adopting at a mutable tag pin (re-pointable)", "pin the resolved sha instead")
	case "branch":
		add(CodeGHAPinGrade, KindFact, LensSecurity, weightLook,
			"adopting at an unpinned branch (moves on every push)", "pin a sha")
	case "sha":
		add(CodeGHAPinGrade, KindFact, LensSecurity, weightPositive,
			"adopting at an immutable sha pin", "")
	}
	if len(c.GHACaps) > 0 {
		add(CodeGHACaps, KindHeuristic, LensSecurity, weightPositive,
			"runner capability references present (grep of the executed code, evadable)", strings.Join(c.GHACaps, ", "))
	}
	// extraction evidence carries the same weight as in a diff: an adoption
	// whose artifact needed hostile-member skips is the one to read closest
	if n := len(c.HostileEntries); n > 0 {
		add(CodeHostileEntry, KindFact, LensSecurity, weightLook,
			fmt.Sprintf("%d hostile archive member(s) skipped at extraction", n), firstN(c.HostileEntries, 5))
	}
	if n := len(c.SkippedLinks); n > 0 {
		add(CodeSkippedLink, KindDegradation, LensCoverage, weightPositive,
			fmt.Sprintf("%d symlink/hardlink(s) not materialized; their contents were not inspected", n), firstN(c.SkippedLinks, 5))
	}
	if c.BigExcluded != "" {
		add(CodeCensusBig, KindHeuristic, LensCompat, weightPositive,
			"largest unreviewed file", c.BigExcluded)
	}
	sortSignals(l.Signals)
	return l
}

// DeriveRedirect is the FACT-grade flag that a dependency is served from a
// non-registry source; it needs no fetch, so it carries no other analysis.
func DeriveRedirect(ref, target string) Ledger {
	return Ledger{Ref: ref, Signals: []Signal{{
		Code: CodeRedirect, Kind: KindFact, Lens: LensSecurity, Weight: weightLook,
		Title: "redirected off the registry", Detail: target,
	}}}
}

// DeriveFailure records a dependency that could not be analysed as a
// DEGRADATION, so a failed analysis reads as a coverage gap worth a look, never
// as silence that a clean headline would swallow.
func DeriveFailure(ref, errMsg string) Ledger {
	return Ledger{Ref: ref, Signals: []Signal{{
		Code: CodeAnalysisFailed, Kind: KindDegradation, Lens: LensCoverage, Weight: weightLook,
		Title: "could not be analysed", Detail: errMsg,
	}}}
}

// Unavailable is a classified acquisition failure from the fetch layer: Kind is
// "absent" (404/410, the URL is not retrievable now), "denied" (401/403), or
// "transient".
type Unavailable struct {
	Kind   string
	Status int
	URL    string
	Hint   string
}

// DeriveUnavailable turns an acquisition failure into a signal. Absent is a
// FACT (the URL is not retrievable and the contents were not inspected, worth a
// look); it does NOT establish prior publication, so it never asserts a takedown
// as fact. Denied and transient are degradations.
func DeriveUnavailable(ref string, u *Unavailable) Ledger {
	detail := u.URL
	if u.Hint != "" {
		detail += " (" + u.Hint + ")"
	}
	sig := Signal{Lens: LensCoverage, Detail: detail}
	switch u.Kind {
	case "absent":
		sig.Code, sig.Kind, sig.Lens, sig.Weight = CodeArtifactAbsent, KindFact, LensSecurity, weightLook
		sig.Title = fmt.Sprintf("artifact unavailable (HTTP %d): the URL is not retrievable now and its contents were not inspected; whether it was ever published is not established", u.Status)
	case "denied":
		sig.Code, sig.Kind, sig.Weight = CodeArtifactDenied, KindDegradation, weightWeigh
		sig.Title = fmt.Sprintf("artifact access denied (HTTP %d): authentication or policy", u.Status)
	default:
		sig.Code, sig.Kind, sig.Weight = CodeArtifactFetch, KindDegradation, weightLook
		sig.Title = fmt.Sprintf("artifact fetch failed (HTTP %d, transient)", u.Status)
	}
	return Ledger{Ref: ref, Signals: []Signal{sig}}
}

// Verdict is the headline state, computed purely from the ledger so no renderer
// can reach a rosier conclusion than the signals justify.
type Verdict struct {
	Tier             int
	CoverageComplete bool
}

func Assess(ledgers ...Ledger) Verdict {
	v := Verdict{CoverageComplete: true}
	for _, l := range ledgers {
		for _, s := range l.Signals {
			if s.Kind == KindDegradation {
				v.CoverageComplete = false
			}
			if s.Weight > v.Tier {
				v.Tier = s.Weight
			}
		}
	}
	return v
}

// Clean is the honest headline condition: nothing tripped AND coverage intact.
// A degradation can never read as clean, which is what stops "no signals" from
// meaning "safe" when a check did not run.
func (v Verdict) Clean() bool { return v.Tier == 0 && v.CoverageComplete }

// rawCompat is the unescaped compat summary for a signal's Detail; renderers
// escape it. Mirrors compatPhrase's selection (format flip first, else the
// first structural constraint) without the Markdown escaping baked in.
func rawCompat(s *stats.Stats) string {
	c := s.Compat
	if c.TypeFrom != c.TypeTo && c.TypeFrom != "" && c.TypeTo != "" {
		return "module format " + c.TypeFrom + " -> " + c.TypeTo
	}
	for _, x := range c.Constraints {
		if !strings.HasPrefix(x.Key, "feature.") {
			return x.Key + " " + x.From + " -> " + x.To
		}
	}
	return "exports/resolution changed"
}

// binaryList ranks binary files by bytes (added by new size, changed by the
// absolute byte delta) and names them, capped, so an opaque payload is always
// visible and the biggest leads. Paths are raw; renderers escape them.
func binaryList(files []stats.FileEntry, delta bool) string {
	weight := func(e stats.FileEntry) int64 {
		if delta {
			if d := e.BytesTo - e.BytesFrom; d < 0 {
				return -d
			} else {
				return d
			}
		}
		return e.BytesTo
	}
	sorted := append([]stats.FileEntry(nil), files...)
	sort.SliceStable(sorted, func(i, j int) bool { return weight(sorted[i]) > weight(sorted[j]) })
	const max = 3
	var parts []string
	for i, e := range sorted {
		if i >= max {
			parts = append(parts, fmt.Sprintf("+%d more", len(sorted)-max))
			break
		}
		if delta {
			parts = append(parts, e.Path+" ("+signedBytes(e.BytesTo-e.BytesFrom)+")")
		} else {
			parts = append(parts, e.Path+" ("+humanBytes(e.BytesTo)+")")
		}
	}
	return strings.Join(parts, ", ")
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func signedBytes(n int64) string {
	if n >= 0 {
		return "+" + humanBytes(n)
	}
	return "-" + humanBytes(-n)
}

func sortSignals(ss []Signal) {
	sort.SliceStable(ss, func(i, j int) bool {
		if ss[i].Weight != ss[j].Weight {
			return ss[i].Weight > ss[j].Weight
		}
		return ss[i].Code < ss[j].Code
	})
}
