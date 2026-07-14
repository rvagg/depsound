package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rvagg/depsound/internal/stats"
)

// SignalKind is a signal's trust tier, the distinction the whole tool rests on:
// a FACT is ground truth (trust and act), a HEURISTIC is evadable
// pattern-matching (navigate and inspect), a DEGRADATION is coverage lost (a
// check did not complete, so silence here is emphatically not safety).
type SignalKind int

const (
	KindFact SignalKind = iota
	KindHeuristic
	KindDegradation
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

// Signal is one derived finding. Code is the STABLE identifier the parity tests
// anchor on: wording (Title/Detail) may change freely, the Code may not.
// Title/Detail are RAW; each renderer escapes them for its own medium.
type Signal struct {
	Code   string
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

// AllSignalCodes enumerates every code a derivation can emit. It is the
// enforcement anchor: a code here with no fixture, or a renderer that omits one,
// is a test failure, so a fact cannot be added to the model without proving it
// reaches every output.
func AllSignalCodes() []string {
	return []string{
		"osv.introduced", "osv.still", "osv.fixed", "coverage.osv.disabled",
		"exec.introduced", "exec.present",
		"compat.change", "generated.delta",
		"gha.capsIntroduced", "gha.using",
		"binary.added",
		"redirect",
		"census.new", "census.cve", "census.exec",
	}
}

// Derive turns a diff's Stats into its signal ledger. This is the ONE place
// that decides what counts; every renderer consumes the result.
func Derive(ref string, s *stats.Stats) Ledger {
	l := Ledger{Ref: ref}
	add := func(code string, k SignalKind, lens Lens, w int, title, detail string) {
		l.Signals = append(l.Signals, Signal{Code: code, Kind: k, Lens: lens, Weight: w, Title: title, Detail: detail})
	}

	// OSV status is derived from whether the scan ran, never assumed: a
	// disabled/failed scan is a degradation, not silence that reads as clean.
	if !s.Security.Queried {
		add("coverage.osv.disabled", KindDegradation, LensCoverage, weightWeigh,
			"known-CVE scan not run", "OSV was disabled or did not complete for this dependency")
	} else {
		if n := len(s.Security.Introduced); n > 0 {
			add("osv.introduced", KindFact, LensSecurity, weightLook,
				fmt.Sprintf("introduces %d known CVE(s)", n), joinVulnIDs(s.Security.Introduced, 5))
		}
		if n := len(s.Security.StillPresent); n > 0 {
			add("osv.still", KindFact, LensSecurity, weightWeigh,
				fmt.Sprintf("%d known CVE(s) still present after the bump", n), joinVulnIDs(s.Security.StillPresent, 5))
		}
		if n := len(s.Security.FixedByUpgrade); n > 0 {
			add("osv.fixed", KindFact, LensSecurity, weightPositive,
				fmt.Sprintf("fixes %d advisory(ies)", n), "")
		}
	}

	// execution surface, generated delta, compat: reuse the existing digest so
	// the ledger agrees with today's renderers on what fired.
	d := digestOf(s)
	if d.exec {
		what := strings.Join(humanExec(d.execWhat), ", ")
		if execIntroduced(d.execWhat) {
			add("exec.introduced", KindFact, LensSecurity, weightLook, "new execution surface", what)
		} else {
			add("exec.present", KindFact, LensSecurity, weightWeigh, "execution surface present", what)
		}
	}
	if d.genDelta > 0 {
		add("generated.delta", KindHeuristic, LensCompat, weightWeigh,
			"generated/bundled code changed", fmt.Sprintf("%s, +/-%d lines", d.genFile, d.genDelta))
	}
	if d.compat {
		add("compat.change", KindFact, LensCompat, weightWeigh, "compatibility changed", rawCompat(s))
	}

	// GitHub Actions execution model (gha only). CapsIntroduced is the
	// load-bearing delta; a runtime move is a real compat fact, not maintenance.
	if a := s.Action; a != nil {
		if len(a.CapsIntroduced) > 0 {
			add("gha.capsIntroduced", KindFact, LensSecurity, weightLook,
				"new runner capability referenced", strings.Join(a.CapsIntroduced, ", "))
		}
		if a.UsingFrom != a.UsingTo && a.UsingFrom != "" && a.UsingTo != "" {
			add("gha.using", KindFact, LensCompat, weightWeigh,
				"action runtime changed", a.UsingFrom+" -> "+a.UsingTo)
		}
	}

	// an added binary/excluded file carries a ZERO line delta, so line-based
	// ranking hides it; surface the addition as a fact from status + class.
	for _, e := range s.Files.Entries {
		if e.Excluded && e.Status == "A" {
			add("binary.added", KindFact, LensSecurity, weightLook, "binary/opaque file added", e.Path)
			break
		}
	}

	sortSignals(l.Signals)
	return l
}

// DeriveCensus turns a newly-adopted version's footprint into its ledger. A new
// dependency is unreviewed surface by definition, so it always carries a signal.
func DeriveCensus(ref string, c *Census) Ledger {
	l := Ledger{Ref: ref}
	add := func(code string, k SignalKind, lens Lens, w int, title, detail string) {
		l.Signals = append(l.Signals, Signal{Code: code, Kind: k, Lens: lens, Weight: w, Title: title, Detail: detail})
	}
	add("census.new", KindFact, LensCompat, weightWeigh,
		fmt.Sprintf("new dependency, %s file(s) unreviewed", commas(c.Files)), "")
	if len(c.Vulns) > 0 {
		add("census.cve", KindFact, LensSecurity, weightLook,
			fmt.Sprintf("%d known CVE(s) at this version", len(c.Vulns)), joinVulnIDs(c.Vulns, 5))
	}
	if c.hasExec() {
		add("census.exec", KindFact, LensSecurity, weightLook,
			"runs code on install/build", strings.Join(censusExecWhat(c), ", "))
	}
	sortSignals(l.Signals)
	return l
}

// DeriveRedirect is the FACT-grade flag that a dependency is served from a
// non-registry source; it needs no fetch, so it carries no other analysis.
func DeriveRedirect(ref, target string) Ledger {
	return Ledger{Ref: ref, Signals: []Signal{{
		Code: "redirect", Kind: KindFact, Lens: LensSecurity, Weight: weightLook,
		Title: "redirected off the registry", Detail: target,
	}}}
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

func sortSignals(ss []Signal) {
	sort.SliceStable(ss, func(i, j int) bool {
		if ss[i].Weight != ss[j].Weight {
			return ss[i].Weight > ss[j].Weight
		}
		return ss[i].Code < ss[j].Code
	})
}
