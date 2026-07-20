package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/stats"
)

// rowKind selects a bullet's framing; the ledger decides inclusion and tier,
// this only picks how the dependency is introduced.
type rowKind int

const (
	rowStats rowKind = iota
	rowCensus
	rowRedirect
	rowFailed
)

// ledgerRow pairs a dependency's derived ledger with the source it renders
// richly from (Stats/Census) and its framing.
type ledgerRow struct {
	l    Ledger
	s    *stats.Stats
	c    *Census
	ref  string
	kind rowKind
}

func (r ledgerRow) tier() int { return Assess(r.l).Tier }

func (r ledgerRow) phrases() string {
	out := make([]string, 0, len(r.l.Signals))
	for _, sig := range r.l.Signals {
		out = append(out, mdSignal(sig, r.s, r.c))
	}
	return strings.Join(out, "; ")
}

// bullet frames the row by kind; redirect and failure carry their evidence in
// the framing itself (the target / the error), the rest render their signals.
func (r ledgerRow) bullet() string {
	detail := ""
	if len(r.l.Signals) > 0 {
		detail = r.l.Signals[0].Detail
	}
	switch r.kind {
	case rowRedirect:
		return fmt.Sprintf("- **%s → %s** (redirect): served from a non-registry source (fork/git/local); a trusted name pointed elsewhere is the trust-laundering vector, verify the source", mdTaint(r.ref), mdTaint(detail))
	case rowFailed:
		return fmt.Sprintf("- **%s** could not be analysed: %s", refArrow(r.ref), mdTaint(detail))
	case rowCensus:
		return fmt.Sprintf("- **new dependency %s**: %s", refArrow(r.ref), r.phrases())
	default:
		return fmt.Sprintf("- **%s**: %s", refArrow(r.ref), r.phrases())
	}
}

// ledgerRows derives one ledger per result; inclusion and verdict come from the
// ledger, never from this renderer.
func ledgerRows(results []BulkResult) []ledgerRow {
	rows := make([]ledgerRow, 0, len(results))
	for _, r := range results {
		switch {
		case r.Unavailable != nil:
			rows = append(rows, ledgerRow{l: DeriveUnavailable(r.Ref, r.Unavailable), ref: r.Ref, kind: rowStats})
		case r.Redirect != "":
			rows = append(rows, ledgerRow{l: DeriveRedirect(r.Ref, r.Redirect), ref: r.Ref, kind: rowRedirect})
		case r.Census != nil:
			rows = append(rows, ledgerRow{l: DeriveCensus(r.Ref, r.Census), c: r.Census, ref: r.Ref, kind: rowCensus})
		case r.Stats != nil:
			rows = append(rows, ledgerRow{l: Derive(r.Ref, r.Stats), s: r.Stats, ref: r.Ref, kind: rowStats})
		default:
			rows = append(rows, ledgerRow{l: DeriveFailure(r.Ref, r.Err), ref: r.Ref, kind: rowFailed})
		}
	}
	return rows
}

// Markdown renders bulk results as a GitHub-Flavored Markdown PR comment: a
// plain-language headline, the deps that tripped a signal (worst first), and the
// coverage boundary in small print. Every rendered signal comes from the shared
// ledger, so no fact bulk knows can silently vanish here; the headline is the
// ledger's Verdict, so "no signals tripped" cannot appear unless coverage was
// actually complete. depsound owns the wording; the posting action appends
// run-specific links. Attacker-influenced values are escaped for the Markdown/
// HTML medium at the point they enter the document.
func Markdown(results []BulkResult) string {
	rows := ledgerRows(results)
	ledgers := make([]Ledger, len(rows))
	for i, r := range rows {
		ledgers[i] = r.l
	}
	v := Assess(ledgers...)

	// worst first; clean rows (an empty ledger) collapse to a count
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].tier() > rows[j].tier() })

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	total := len(results)
	w("<!-- depsound-title: depsound: %s -->", checkTitle(v, total))
	w("**depsound** · %d dependency change%s · %s", total, plural(total), triage(v))

	var bullets []string
	nClean := 0
	for _, r := range rows {
		if len(r.l.Signals) == 0 {
			nClean++
			continue
		}
		bullets = append(bullets, r.bullet())
	}
	// The bullets section lists only what tripped; the "N others" line is its
	// footer accounting for the clean deps NOT listed. With nothing tripped
	// there are no bullets, so the headline already carries "no signals
	// tripped" and the line would just repeat it: skip the whole section.
	if len(bullets) > 0 {
		w("")
		for _, bl := range bullets {
			w("%s", bl)
		}
		if nClean > 0 {
			w("- %d other%s: no signals tripped.", nClean, plural(nClean))
		}
	}
	w("")
	notChecked := "reachability, runtime behaviour, your tests"
	if !anyProvenanceQueried(results) {
		notChecked += ", publish provenance" // provenance ran in bulk; only listed when it did not
	}
	w("<i>Not checked: %s.</i>", notChecked)
	w("<!-- depsound -->")
	return b.String()
}

// mdSignal renders one ledger signal as a comment phrase. It dispatches on the
// stable Code to reuse rich formatting (linked advisories, compat phrasing) from
// the source Stats/Census, and falls back to the raw Title/Detail for any code
// without a specific case, so a new signal renders plainly, never drops.
func mdSignal(sig Signal, s *stats.Stats, c *Census) string {
	switch sig.Code {
	case CodeOSVIntroduced:
		return fmt.Sprintf("introduces %d known CVE(s): %s", len(s.Security.Introduced), linkedVulnIDs(s.Security.Introduced, 5))
	case CodeOSVStill:
		return fmt.Sprintf("%d known CVE(s) still present after the bump: %s", len(s.Security.StillPresent), linkedVulnIDs(s.Security.StillPresent, 5))
	case CodeOSVFixed:
		return fmt.Sprintf("fixes %d advisory(ies)", len(s.Security.FixedByUpgrade))
	case CodeOSVDisabled:
		return "known-CVE scan not run (coverage gap, not a clean result)"
	case CodeOSVFailed:
		return "known-CVE scan failed (coverage gap, not a clean result): " + mdTaint(sig.Detail)
	case CodeOSVUnsupported:
		return "known-CVE scan not applicable (this ecosystem has no OSV index)"
	case CodeExecIntroduced:
		return "new execution surface: " + mdTaint(sig.Detail)
	case CodeExecPresent:
		return "execution surface present (" + mdTaint(sig.Detail) + "), its build code may have changed"
	case CodeGeneratedDelta:
		return "generated code changed (" + mdTaint(sig.Detail) + "): outside the review surface, worth a look"
	case CodeCompatChange:
		return compatPhrase(s)
	case CodeGHACaps:
		return "new runner capability referenced (grep of the executed code, evadable): " + mdTaint(sig.Detail)
	case CodeGHAUsing:
		return "action runtime changed: " + mdTaint(sig.Detail)
	case CodeGHARefMoved:
		return sig.Title + ": " + mdTaint(sig.Detail)
	case CodeBinaryAdded, CodeBinaryChanged:
		return sig.Title + " (ranked by size): " + mdTaint(sig.Detail)
	case CodeCensusNew:
		return fmt.Sprintf("adopting %s file%s, whole footprint unreviewed", commas(c.Files), plural(c.Files))
	case CodeCensusCVE:
		return fmt.Sprintf("%d known CVE(s) at this version: %s", len(c.Vulns), linkedVulnIDs(c.Vulns, 5))
	case CodeCensusExec:
		return "runs code on install/build: " + mdTaint(sig.Detail)
	case CodeCensusBig:
		return "largest unreviewed file " + mdTaint(sig.Detail)
	case CodeArtifactDenied:
		return "artifact access denied (auth/policy): " + mdTaint(sig.Detail)
	case CodeArtifactFetch:
		return "artifact fetch failed (transient): " + mdTaint(sig.Detail)
	default:
		if sig.Detail != "" {
			return mdTaint(sig.Title) + ": " + mdTaint(sig.Detail)
		}
		return mdTaint(sig.Title)
	}
}

// refArrow renders a dependency ref for a bullet: the tool's " -> " separator
// as a unicode arrow, then escaped for the Markdown/HTML medium.
func refArrow(ref string) string {
	return mdTaint(strings.ReplaceAll(ref, " -> ", " → "))
}

// commas formats a count with thousands separators: 49532 -> "49,532".
func commas(n int) string {
	sign := ""
	if n < 0 {
		sign, n = "-", -n
	}
	s := fmt.Sprintf("%d", n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return sign + s
}

// compatPhrase names the most consumer-relevant compatibility change: the
// module-format flip (CJS<->ESM) first, else the first changed constraint.
func compatPhrase(s *stats.Stats) string {
	c := s.Compat
	if c.TypeFrom != c.TypeTo && c.TypeFrom != "" && c.TypeTo != "" {
		return fmt.Sprintf("module format changed: %s → %s", mdTaint(c.TypeFrom), mdTaint(c.TypeTo))
	}
	// structural constraints (edition, MSRV, engines, go directive) are few and
	// important, so name them; feature-set changes are churny, so count them
	var structural []string
	features := 0
	for _, x := range c.Constraints {
		if strings.HasPrefix(x.Key, "feature.") {
			features++
			continue
		}
		structural = append(structural, fmt.Sprintf("%s %s → %s", mdTaint(x.Key), mdTaint(x.From), mdTaint(x.To)))
	}
	const maxShown = 2
	var parts []string
	if len(structural) > maxShown {
		parts = append(structural[:maxShown:maxShown], fmt.Sprintf("+%d more constraint%s", len(structural)-maxShown, plural(len(structural)-maxShown)))
	} else {
		parts = structural
	}
	if features > 0 {
		parts = append(parts, fmt.Sprintf("%d feature change%s", features, plural(features)))
	}
	if len(parts) == 0 {
		return "exports/resolution changed"
	}
	return strings.Join(parts, ", ")
}

func execIntroduced(what []string) bool {
	for _, w := range what {
		if strings.Contains(w, "INTRODUCED") || strings.Contains(w, " added") {
			return true
		}
	}
	return false
}

// humanExec strips the router's terminal decorations ("INTRODUCED", the
// present-note, the "lifecycle " prefix) so surfaces read as plain names in a
// comment bullet instead of shouting.
func humanExec(what []string) []string {
	out := make([]string, 0, len(what))
	for _, w := range what {
		w = strings.TrimPrefix(w, "lifecycle ")
		w = strings.ReplaceAll(w, " INTRODUCED", "")
		w = strings.ReplaceAll(w, " present (build code may have changed)", "")
		out = append(out, w)
	}
	return out
}

// linkedVulnIDs renders up to max advisory ids as clickable links, then a
// "+N more" tail so a heavy dep does not become a wall.
func linkedVulnIDs(vulns []osv.Vuln, max int) string {
	parts := make([]string, 0, len(vulns))
	for i, v := range vulns {
		if i >= max {
			parts = append(parts, fmt.Sprintf("+%d more", len(vulns)-max))
			break
		}
		parts = append(parts, vulnLink(preferredID(v)))
	}
	return strings.Join(parts, ", ")
}

// preferredID picks the most recognizable id to show: the CVE alias when
// present (as the router does), else the primary OSV id.
func preferredID(v osv.Vuln) string {
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return v.ID
}

// vulnLink renders a clickable advisory id. The charset check IS the
// sanitization: advisory ids are [A-Za-z0-9-], safe as both a Markdown label
// and a URL path, so a validated id needs no further escaping. A malformed id
// (a hostile feed) degrades to plain escaped text, no link.
func vulnLink(id string) string {
	if !safeVulnID(id) {
		return mdTaint(id)
	}
	return "[" + id + "](" + vulnURL(id) + ")"
}

// vulnURL routes an advisory id to its authoritative page.
func vulnURL(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "https://www.cve.org/CVERecord?id=" + id
	case strings.HasPrefix(id, "GHSA-"):
		return "https://github.com/advisories/" + id
	case strings.HasPrefix(id, "RUSTSEC-"):
		return "https://rustsec.org/advisories/" + id + ".html"
	case strings.HasPrefix(id, "GO-"):
		return "https://pkg.go.dev/vuln/" + id
	default:
		return "https://osv.dev/vulnerability/" + id
	}
}

func safeVulnID(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}

// triage is the headline verb, derived from the ledger verdict: a degradation
// (coverage lost) can never read "no signals tripped".
func triage(v Verdict) string {
	switch {
	case v.Clean():
		return "no signals tripped"
	case v.Tier >= weightLook:
		return "flags to look at now"
	default:
		return "review the changes"
	}
}

func checkTitle(v Verdict, total int) string {
	if v.Clean() {
		return fmt.Sprintf("%d change(s), no signals tripped", total)
	}
	return fmt.Sprintf("%d change(s), flagged for review", total)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// mdTaint makes an attacker-influenced value safe as inline GitHub-Flavored
// Markdown: taint() strips control/bidi bytes and newlines (so it stays on one
// line, no block injection), then GFM metacharacters are entity-encoded (tags/
// images, emphasis, links, code, table pipes, @mention/#issue autolinks).
// Entities still display as the character (&#64; -> @), so @scope/pkg reads
// right but stays inert. Residual: bare-URL autolinks, a link not an
// auto-loading image, so no zero-click channel.
func mdTaint(s string) string {
	s = taint(s)
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"`", "&#96;",
		"*", "&#42;",
		"_", "&#95;",
		"~", "&#126;",
		"[", "&#91;",
		"]", "&#93;",
		"|", "&#124;",
		"\\", "&#92;",
		"@", "&#64;",
		"#", "&#35;",
	).Replace(s)
}
