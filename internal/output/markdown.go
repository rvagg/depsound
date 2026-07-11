package output

import (
	"fmt"
	"sort"
	"strings"

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
	ref     string
	tier    tier
	phrases []string
	failed  bool
	errMsg  string
}

// Markdown renders bulk results as a GitHub-Flavored Markdown report shaped
// for a PR sticky comment: a plain-language headline, the deps that tripped a
// signal (worst first), the coverage boundary in small print, and the full
// router report folded into a <details> block. depsound owns the wording; the
// action that posts this is thin plumbing (and appends run-specific links like
// the artifact URL, which depsound cannot know). A leading HTML comment carries
// the one-line check title; a trailing one is the per-PR upsert anchor, both
// invisible when rendered. Attacker-influenced values are escaped for the
// Markdown/HTML medium here, at the point they enter a document GitHub renders.
func Markdown(results []BulkResult) string {
	var shown []commentRow
	var nClean, attention int
	worst := tierClean
	for _, r := range results {
		if r.Stats == nil {
			shown = append(shown, commentRow{ref: r.Ref, failed: true, errMsg: r.Err})
			attention++
			worst = tierLook // an un-analysed dep is a gap worth a look
			continue
		}
		t, phrases := commentSignals(r.Stats)
		if t > worst {
			worst = t
		}
		if t >= tierWeigh {
			attention++
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

	w("<!-- depsound-title: depsound: %s -->", checkTitle(worst, total, attention))
	w("**depsound** · %d dependency update%s · %s", total, plural(total), triage(worst, attention))
	if len(shown) > 0 {
		w("")
		for _, r := range shown {
			if r.failed {
				w("- **%s** could not be analysed: %s", mdTaint(r.ref), mdTaint(r.errMsg))
				continue
			}
			w("- **%s** — %s", mdTaint(r.ref), strings.Join(r.phrases, "; "))
		}
		if nClean > 0 {
			w("- %d other%s: no signals tripped.", nClean, plural(nClean))
		}
	}
	w("")
	w("<sub>Not a verdict. Not checked: reachability, runtime behaviour, your tests, " +
		"transitive depth, publish provenance. Silence is not safety. " +
		"Drill any dep: <code>depsound &lt;eco&gt;:&lt;name&gt; &lt;from&gt; &lt;to&gt;</code>.</sub>")

	report := Bulk(results)
	f := fence(report)
	w("")
	w("<details><summary>depsound report</summary>")
	w("")
	w("%s", f)
	b.WriteString(report)
	if !strings.HasSuffix(report, "\n") {
		w("")
	}
	w("%s", f)
	w("</details>")
	w("")
	w("<sub>depsound %s · gateway, not verdict</sub>", mdTaint(toolVersion(results)))
	w("<!-- depsound -->")
	return b.String()
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
		add(tierLook, fmt.Sprintf("introduces %d known CVE(s): %s", d.osvIntro, mdTaint(d.introIDs)))
	}
	if d.exec {
		if execIntroduced(d.execWhat) {
			add(tierLook, "new execution surface ("+mdTaint(strings.Join(d.execWhat, "; "))+")")
		} else {
			add(tierWeigh, "execution surface present, its build code may have changed")
		}
	}
	if d.genDelta > 0 {
		add(tierLook, fmt.Sprintf("large unreviewed change in %s (±%d lines, a payload can hide here)", mdTaint(d.genFile), d.genDelta))
	}
	if d.osvStill > 0 {
		add(tierWeigh, fmt.Sprintf("%d known CVE(s) still present after the bump: %s", d.osvStill, mdTaint(d.stillIDs)))
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

// compatPhrase names the most consumer-relevant compatibility change: the
// module-format flip (CJS<->ESM) first, else the first changed constraint.
func compatPhrase(s *stats.Stats) string {
	c := s.Compat
	if c.TypeFrom != c.TypeTo && c.TypeFrom != "" && c.TypeTo != "" {
		return fmt.Sprintf("module format changed: %s -> %s", mdTaint(c.TypeFrom), mdTaint(c.TypeTo))
	}
	if len(c.Constraints) > 0 {
		x := c.Constraints[0]
		more := ""
		if len(c.Constraints) > 1 {
			more = fmt.Sprintf(" (+%d more)", len(c.Constraints)-1)
		}
		return fmt.Sprintf("%s %s -> %s%s", mdTaint(x.Key), mdTaint(x.From), mdTaint(x.To), more)
	}
	return "exports/resolution changed"
}

func execIntroduced(what []string) bool {
	for _, w := range what {
		if strings.Contains(w, "INTRODUCED") || strings.Contains(w, " added") {
			return true
		}
	}
	return false
}

func triage(worst tier, attention int) string {
	switch worst {
	case tierLook:
		return "flags to look at now"
	case tierWeigh:
		if attention == 1 {
			return "1 to weigh"
		}
		return fmt.Sprintf("%d to weigh", attention)
	default:
		return "no signals tripped"
	}
}

func checkTitle(worst tier, total, attention int) string {
	if worst >= tierWeigh {
		return fmt.Sprintf("%d update(s), %d to review", total, attention)
	}
	return fmt.Sprintf("%d update(s), no signals tripped", total)
}

func toolVersion(results []BulkResult) string {
	for _, r := range results {
		if r.Stats != nil {
			return r.Stats.Tool.Version
		}
	}
	return ""
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

// fence returns a Markdown code fence of backticks one longer than the longest
// backtick run in content, so tainted content inside cannot break out of the
// fence (a package name may carry backticks). Minimum three.
func fence(content string) string {
	longest, cur := 0, 0
	for _, c := range content {
		if c == '`' {
			cur++
			if cur > longest {
				longest = cur
			}
		} else {
			cur = 0
		}
	}
	return strings.Repeat("`", max(longest+1, 3))
}
