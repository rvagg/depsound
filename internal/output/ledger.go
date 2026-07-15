package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/stats"
)

// SignalKind is a signal's trust tier, the distinction the whole tool rests on:
// a FACT is ground truth (trust and act), a HEURISTIC is evadable
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
// exhaustive switch), so the parity test remains load-bearing for omissions.
type Code string

const (
	CodeOSVIntroduced  Code = "osv.introduced"
	CodeOSVStill       Code = "osv.still"
	CodeOSVFixed       Code = "osv.fixed"
	CodeOSVDisabled    Code = "coverage.osv.disabled"
	CodeOSVUnsupported Code = "coverage.osv.unsupported"
	CodeOSVFailed      Code = "coverage.osv.failed"
	CodeExecIntroduced Code = "exec.introduced"
	CodeExecPresent    Code = "exec.present"
	CodeCompatChange   Code = "compat.change"
	CodeGeneratedDelta Code = "generated.delta"
	CodeGHACaps        Code = "gha.capsIntroduced"
	CodeGHAUsing       Code = "gha.using"
	CodeBinaryAdded    Code = "binary.added"
	CodeBinaryChanged  Code = "binary.changed"
	CodeRedirect       Code = "redirect"
	CodeCensusNew      Code = "census.new"
	CodeCensusCVE      Code = "census.cve"
	CodeCensusExec     Code = "census.exec"
	CodeCensusBig      Code = "census.bigExcluded"
	CodeAnalysisFailed Code = "analysis.failed"
	CodeArtifactAbsent Code = "artifact.absent"    // the published bytes are gone (404/410)
	CodeArtifactDenied Code = "artifact.denied"    // access denied (401/403)
	CodeArtifactFetch  Code = "artifact.fetchFail" // transient acquisition failure
)

// allCodes is the single source of the code set. AllSignalCodes returns it, and
// the parity/reachability tests require a fixture and a marker for each, so a
// code cannot be added to the model without proving it reaches every output.
var allCodes = []Code{
	CodeOSVIntroduced, CodeOSVStill, CodeOSVFixed,
	CodeOSVDisabled, CodeOSVUnsupported, CodeOSVFailed,
	CodeExecIntroduced, CodeExecPresent,
	CodeCompatChange, CodeGeneratedDelta,
	CodeGHACaps, CodeGHAUsing,
	CodeBinaryAdded, CodeBinaryChanged,
	CodeRedirect,
	CodeCensusNew, CodeCensusCVE, CodeCensusExec, CodeCensusBig,
	CodeAnalysisFailed,
	CodeArtifactAbsent, CodeArtifactDenied, CodeArtifactFetch,
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
		if _, ok := osv.Ecosystem(s.Package.Ecosystem); !ok {
			add(CodeOSVUnsupported, KindNote, LensCoverage, weightPositive,
				"known-CVE scan not applicable", "OSV has no advisory index for the "+s.Package.Ecosystem+" ecosystem")
		} else if s.Security.Note != "" {
			add(CodeOSVFailed, KindDegradation, LensCoverage, weightWeigh,
				"known-CVE scan failed", s.Security.Note)
		} else {
			add(CodeOSVDisabled, KindDegradation, LensCoverage, weightWeigh,
				"known-CVE scan not run", "OSV was disabled for this dependency")
		}
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
			"generated/bundled code changed", fmt.Sprintf("%s, +/-%d lines", d.genFile, d.genDelta))
	}
	if d.compat {
		add(CodeCompatChange, KindFact, LensCompat, weightWeigh, "compatibility changed", rawCompat(s))
	}

	// GitHub Actions execution model (gha only). CapsIntroduced is the
	// load-bearing delta; a runtime move is a real compat fact, not maintenance.
	if a := s.Action; a != nil {
		if len(a.CapsIntroduced) > 0 {
			add(CodeGHACaps, KindFact, LensSecurity, weightLook,
				"new runner capability referenced", strings.Join(a.CapsIntroduced, ", "))
		}
		if a.UsingFrom != a.UsingTo && a.UsingFrom != "" && a.UsingTo != "" {
			add(CodeGHAUsing, KindFact, LensCompat, weightWeigh,
				"action runtime changed", a.UsingFrom+" -> "+a.UsingTo)
		}
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

	sortSignals(l.Signals)
	return l
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
	if len(c.Vulns) > 0 {
		add(CodeCensusCVE, KindFact, LensSecurity, weightLook,
			fmt.Sprintf("%d known CVE(s) at this version", len(c.Vulns)), joinVulnIDs(c.Vulns, 5))
	}
	if c.hasExec() {
		add(CodeCensusExec, KindFact, LensSecurity, weightLook,
			"runs code on install/build", strings.Join(censusExecWhat(c), ", "))
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
// "absent" (404/410, the bytes are gone), "denied" (401/403), or "transient".
type Unavailable struct {
	Kind   string
	Status int
	URL    string
	Hint   string
}

// DeriveUnavailable turns an acquisition failure into a signal. Absent is a
// FACT (the published bytes are gone, a takedown-shaped event worth a look, and
// the contents were not inspected); denied and transient are degradations.
func DeriveUnavailable(ref string, u *Unavailable) Ledger {
	detail := u.URL
	if u.Hint != "" {
		detail += " (" + u.Hint + ")"
	}
	sig := Signal{Lens: LensCoverage, Detail: detail}
	switch u.Kind {
	case "absent":
		sig.Code, sig.Kind, sig.Lens, sig.Weight = CodeArtifactAbsent, KindFact, LensSecurity, weightLook
		sig.Title = fmt.Sprintf("artifact unavailable (HTTP %d): the published bytes are gone; contents not inspected", u.Status)
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
