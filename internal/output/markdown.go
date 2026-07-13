package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/stats"
)

// tier ranks a dep's worst signal, driving the comment headline.
type tier int

const (
	tierClean tier = iota
	tierWeigh
	tierLook
)

// commentRow is one dependency's rendered signals.
type commentRow struct {
	ref      string
	tier     tier
	phrases  []string
	isNew    bool   // a newly-added dependency (census), not a bump
	redirect string // non-empty: this dep is redirected to this target
	failed   bool
	errMsg   string
}

// Markdown renders bulk results as a GitHub-Flavored Markdown report shaped
// for a PR sticky comment: a plain-language headline, the deps that tripped a
// signal (worst first), and the coverage boundary in small print. The full
// firehose report is left to the run artifact, not embedded, so the comment
// carries no terminal-style shout. depsound owns the wording; the
// action that posts this is thin plumbing (and appends run-specific links like
// the artifact URL, which depsound cannot know). A leading HTML comment carries
// the one-line check title; a trailing one is the per-PR upsert anchor, both
// invisible when rendered. Attacker-influenced values are escaped for the
// Markdown/HTML medium here, at the point they enter a document GitHub renders.
func Markdown(results []BulkResult) string {
	var shown []commentRow
	var nClean int
	worst := tierClean
	for _, r := range results {
		if r.Redirect != "" {
			// a trusted name served from a non-registry source is FACT-grade
			// security, the loudest signal; no fetch, so no phrases to compute
			worst = tierLook
			shown = append(shown, commentRow{ref: r.Ref, tier: tierLook, redirect: r.Redirect})
			continue
		}
		if r.Census != nil {
			t, phrases := censusSignals(r.Census)
			if t > worst {
				worst = t
			}
			// a new dependency is unreviewed surface by definition, so it
			// always shows (never folds into the clean count)
			shown = append(shown, commentRow{ref: r.Ref, tier: t, phrases: phrases, isNew: true})
			continue
		}
		if r.Stats == nil {
			shown = append(shown, commentRow{ref: r.Ref, failed: true, errMsg: r.Err})
			worst = tierLook // an un-analysed dep is a gap worth a look
			continue
		}
		t, phrases := commentSignals(r.Stats)
		if t > worst {
			worst = t
		}
		if len(phrases) == 0 {
			nClean++
			continue
		}
		shown = append(shown, commentRow{ref: r.Ref, tier: t, phrases: phrases})
	}
	// worst first; failed rows sort as look-tier
	sort.SliceStable(shown, func(i, j int) bool {
		ti, tj := shown[i].tier, shown[j].tier
		if shown[i].failed {
			ti = tierLook
		}
		if shown[j].failed {
			tj = tierLook
		}
		return ti > tj
	})

	total := len(results)
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("<!-- depsound-title: depsound: %s -->", checkTitle(worst, total))
	w("**depsound** · %d dependency change%s · %s", total, plural(total), triage(worst))
	if len(shown) > 0 {
		w("")
		for _, r := range shown {
			if r.failed {
				w("- **%s** could not be analysed: %s", refArrow(r.ref), mdTaint(r.errMsg))
				continue
			}
			if r.redirect != "" {
				w("- **%s → %s** (redirect) — served from a non-registry source (fork/git/local); a trusted name pointed elsewhere is the trust-laundering vector, verify the source", mdTaint(r.ref), mdTaint(r.redirect))
				continue
			}
			if r.isNew {
				w("- **new dependency %s** — %s", refArrow(r.ref), strings.Join(r.phrases, "; "))
				continue
			}
			w("- **%s** — %s", refArrow(r.ref), strings.Join(r.phrases, "; "))
		}
		if nClean > 0 {
			w("- %d other%s: no signals tripped.", nClean, plural(nClean))
		}
	}
	w("")
	w("<sub>Not checked: reachability, runtime behaviour, your tests, " +
		"transitive depth, publish provenance. Silence is not safety.</sub>")

	w("<!-- depsound -->")
	return b.String()
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

// commentSignals turns one dep's stats into its worst tier and plain-language
// signal phrases. Reuses the bulk digest so the router and the comment agree
// on what fired. Values that originate in package/advisory data are escaped
// for Markdown as they are composed.
func commentSignals(s *stats.Stats) (tier, []string) {
	d := digestOf(s)
	t := tierClean
	var phrases []string
	add := func(nt tier, p string) {
		if nt > t {
			t = nt
		}
		phrases = append(phrases, p)
	}

	if d.osvIntro > 0 {
		add(tierLook, fmt.Sprintf("introduces %d known CVE(s): %s", d.osvIntro, linkedVulnIDs(s.Security.Introduced, 5)))
	}
	if d.exec {
		surfaces := mdTaint(strings.Join(humanExec(d.execWhat), ", "))
		if execIntroduced(d.execWhat) {
			add(tierLook, "new execution surface: "+surfaces)
		} else {
			add(tierWeigh, "execution surface present ("+surfaces+"), its build code may have changed")
		}
	}
	if d.genDelta > 0 {
		// a generated/bundled change (an npm dist/, a vendored blob) is
		// review-worthy but not new-risk-introduced, so it weighs rather than
		// taking the loud tier; otherwise every routine dist bump dominates
		// the headline. Introduced CVEs and new execution surface stay loud.
		add(tierWeigh, fmt.Sprintf("generated code changed (%s, ±%s lines): outside the review surface, worth a look", mdTaint(d.genFile), commas(d.genDelta)))
	}
	if d.osvStill > 0 {
		add(tierWeigh, fmt.Sprintf("%d known CVE(s) still present after the bump: %s", d.osvStill, linkedVulnIDs(s.Security.StillPresent, 5)))
	}
	if d.compat {
		add(tierWeigh, compatPhrase(s))
	}
	if d.osvFixed > 0 {
		// the merge argument; positive, does not raise the tier
		phrases = append(phrases, fmt.Sprintf("fixes %d advisory(ies)", d.osvFixed))
	}
	return t, phrases
}

// censusSignals turns a newly-added dependency's footprint into the comment
// tier and phrases. A new dep is never "clean": you are adopting unreviewed
// code, so the floor is the weigh tier, rising to look when it ships known
// CVEs or runs code on install/build (the sneaked-in-malware shape).
func censusSignals(c *Census) (tier, []string) {
	t := tierWeigh
	phrases := []string{fmt.Sprintf("adopting %s file%s, whole footprint unreviewed", commas(c.Files), plural(c.Files))}
	if len(c.Vulns) > 0 {
		t = tierLook
		phrases = append(phrases, fmt.Sprintf("%d known CVE(s) at this version: %s", len(c.Vulns), linkedVulnIDs(c.Vulns, 5)))
	}
	if c.hasExec() {
		t = tierLook
		phrases = append(phrases, "runs code on install/build: "+mdTaint(strings.Join(censusExecWhat(c), ", ")))
	}
	if c.BigExcluded != "" {
		phrases = append(phrases, "largest unreviewed file "+mdTaint(c.BigExcluded))
	}
	return t, phrases
}

// compatPhrase names the most consumer-relevant compatibility change: the
// module-format flip (CJS<->ESM) first, else the first changed constraint.
func compatPhrase(s *stats.Stats) string {
	c := s.Compat
	if c.TypeFrom != c.TypeTo && c.TypeFrom != "" && c.TypeTo != "" {
		return fmt.Sprintf("module format changed: %s → %s", mdTaint(c.TypeFrom), mdTaint(c.TypeTo))
	}
	// structural constraints (edition, MSRV, engines, go directive) are few and
	// load-bearing, so name them; feature-set changes are churny, so count them
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

func triage(worst tier) string {
	switch worst {
	case tierLook:
		return "flags to look at now"
	case tierWeigh:
		return "review the changes"
	default:
		return "no signals tripped"
	}
}

func checkTitle(worst tier, total int) string {
	if worst >= tierWeigh {
		return fmt.Sprintf("%d change(s), flagged for review", total)
	}
	return fmt.Sprintf("%d change(s), no signals tripped", total)
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
