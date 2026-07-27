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

// coverageNotes name what we could scan, not what we found: properties of the
// ecosystem, identical on every row and every PR, so they belong in the
// boundary once. A per-dep coverage gap (a scan that failed or was disabled)
// is news about that dep and stays on its row.
var coverageNotes = map[Code]bool{CodeOSVUnsupported: true}

// findings are the signals that say something about this dependency.
func (r ledgerRow) findings() []Signal {
	out := make([]Signal, 0, len(r.l.Signals))
	for _, sig := range r.l.Signals {
		if !coverageNotes[sig.Code] {
			out = append(out, sig)
		}
	}
	return out
}

func (r ledgerRow) phrases() string {
	f := r.findings()
	out := make([]string, 0, len(f))
	for _, sig := range f {
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
		// a row whose signals are all calm context still has room for what the
		// change is; a row carrying something to weigh gets to keep the floor
		phrases := r.phrases()
		if r.tier() == 0 {
			if d := digestLine(r.s); d != "" {
				phrases += " · " + d
			}
		}
		return fmt.Sprintf("- **%s**: %s", refArrow(r.ref), phrases)
	}
}

// digest is the row for a change that tripped nothing: what it is, in
// per-invocation facts. Deltas and counts only, so every clause is checkable:
// "no new runner capability" is, "capabilities fine" would be a verdict.
func (r ledgerRow) digest() string {
	d := digestLine(r.s)
	if d == "" {
		return ""
	}
	return fmt.Sprintf("- **%s**: %s", refArrow(r.ref), d)
}

func digestLine(s *stats.Stats) string {
	if s == nil {
		return ""
	}
	var parts []string
	if a := s.Action; a != nil {
		if p := pinPhrase(a.Pins); p != "" {
			parts = append(parts, p)
		}
		if a.UsingTo != "" && a.UsingFrom == a.UsingTo {
			parts = append(parts, mdTaint(a.UsingTo)+" unchanged")
		}
		parts = appendNonEmpty(parts, filesPhrase(s))
		if len(a.Caps) > 0 { // referenced in both versions, none new in this bump
			parts = append(parts, "no new runner capability")
		}
		if n := len(a.Nested); n > 0 {
			parts = append(parts, fmt.Sprintf("%d nested action%s", n, plural(n)))
		}
		return strings.Join(parts, " · ")
	}
	parts = appendNonEmpty(parts, filesPhrase(s))
	if s.Compat.TypeTo != "" && s.Compat.TypeFrom == s.Compat.TypeTo {
		parts = append(parts, "still "+mdTaint(s.Compat.TypeTo))
	}
	if !execSurfacePresent(s.Runnable) {
		parts = append(parts, "no install/build execution surface")
	}
	return strings.Join(parts, " · ")
}

func appendNonEmpty(parts []string, s string) []string {
	if s == "" {
		return parts
	}
	return append(parts, s)
}

// filesPhrase sizes the change; nothing changed is left to the
// no-content-change signal.
func filesPhrase(s *stats.Stats) string {
	if s.Files.Changed == 0 {
		return ""
	}
	return fmt.Sprintf("%d file%s +%s/-%s", s.Files.Changed, plural(s.Files.Changed),
		commas(s.Files.Added), commas(s.Files.Removed))
}

// pinPhrase grades both sides of an action pin in one clause.
func pinPhrase(pins []stats.ActionPin) string {
	from, to := pinOf(pins, "from"), pinOf(pins, "to")
	if from == nil || to == nil {
		return ""
	}
	if from.Kind == to.Kind {
		return from.Kind + " pin both sides"
	}
	return from.Kind + " → " + to.Kind + " pin"
}

func execSurfacePresent(r stats.Runnable) bool {
	return len(r.Lifecycle) > 0 || r.GypFrom || r.GypTo || r.CgoFrom || r.CgoTo ||
		r.BuildRSFrom || r.BuildRSTo || r.ProcMacroFrom || r.ProcMacroTo
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
		case r.Note != "":
			rows = append(rows, ledgerRow{l: DeriveBenign(r.Ref, r.Note), ref: r.Ref, kind: rowStats})
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

	// findings first, then a digest for each quiet change, so a row that tripped
	// nothing still says what it is. Digests are capped so a wide PR cannot
	// become a wall; the remainder collapses to a stated count.
	var bullets, digests []string
	nQuiet := 0
	for _, r := range rows {
		if len(r.findings()) > 0 {
			bullets = append(bullets, r.bullet())
			continue
		}
		nQuiet++
		if len(digests) < maxDigestRows {
			if d := r.digest(); d != "" {
				digests = append(digests, d)
			}
		}
	}
	if len(bullets)+len(digests) > 0 {
		w("")
		for _, bl := range append(bullets, digests...) {
			w("%s", bl)
		}
		if rest := nQuiet - len(digests); rest > 0 {
			w("- %d other%s: nothing tripped.", rest, plural(rest))
		}
	}
	w("")
	w("<i>%s</i>", coverageLine(results, rows))
	w("<!-- depsound -->")
	return b.String()
}

// maxDigestRows caps the quiet-change detail so the comment's length tracks
// what moved, never the size of the dependency list.
const maxDigestRows = 10

// coverageLine is the boundary in one small-print block: what was checked
// across this set, what cannot be, and the ecosystem coverage notes hoisted
// out of the rows. It is scoped by what is actually in the set, so a GitHub
// Actions PR is not told about import reachability.
func coverageLine(results []BulkResult, rows []ledgerRow) string {
	gha, pkg := false, false
	for _, r := range results {
		switch {
		case r.Stats != nil && r.Stats.Action != nil:
			gha = true
		case r.Stats != nil || r.Census != nil:
			pkg = true
		}
	}
	checked := []string{"the published artifact diff"}
	notChecked := []string{"runtime behaviour", "intent (an obfuscated payload reads as ordinary code)"}
	if gha {
		checked = append(checked, "pin grade", "execution model", "runner capability references (grep, evadable)")
		notChecked = append(notChecked, "the permissions, secrets and trigger at each callsite", "self-hosted runner reach")
	}
	if pkg {
		checked = append(checked, "manifest compatibility", "install/build execution surface")
		notChecked = append(notChecked, "whether your code reaches the change", "your test coverage")
	}
	if g := provenanceGap(results); g != "" {
		notChecked = append(notChecked, g)
	}
	var out strings.Builder
	fmt.Fprintf(&out, "Checked: %s. Not checked: %s.", strings.Join(checked, ", "), strings.Join(notChecked, ", "))
	// the hoisted coverage notes, once each, with the count they apply to
	byCode := map[Code]int{}
	var order []Code
	for _, r := range rows {
		for _, sig := range r.l.Signals {
			if coverageNotes[sig.Code] {
				if byCode[sig.Code] == 0 {
					order = append(order, sig.Code)
				}
				byCode[sig.Code]++
			}
		}
	}
	for _, code := range order {
		if code == CodeOSVUnsupported {
			fmt.Fprintf(&out, " No known-CVE scan for %d of these: OSV indexes no advisories for that ecosystem.", byCode[code])
		}
	}
	return out.String()
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
	// a commit-pinned action carries two 40-char shas; the short form is what a
	// human matches against the diff, and the full pair stays in the report
	fields := strings.Fields(ref)
	for i, f := range fields {
		if isHexSHA(f) {
			fields[i] = f[:12]
		}
	}
	return mdTaint(strings.ReplaceAll(strings.Join(fields, " "), " -> ", " → "))
}

// isHexSHA reports whether s is a full 40-char git object name.
func isHexSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
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
