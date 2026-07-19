package output

import (
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/provenance"
	"github.com/rvagg/depsound/internal/stats"
)

// cleanStats is an actually-clean result: the OSV scan RAN (Queried) and found
// nothing, and nothing else changed. Queried matters, an unqueried scan is now
// a degradation, not a clean result.
func cleanStats() *stats.Stats {
	return &stats.Stats{
		Tool:     stats.Tool{Name: "depsound", Version: "0.0.0"},
		Package:  stats.PkgRef{Ecosystem: "npm", Name: "ms", From: "2.1.2", To: "2.1.3"},
		Compat:   stats.Compat{TypeFrom: "commonjs", TypeTo: "commonjs"},
		Security: stats.Security{Queried: true},
	}
}

// TestMarkdownGeneratedDeltaGrouped: a large generated/bundled line delta (the
// dist/index.js case) is comma-grouped like the other counts, not a raw run of
// digits.
func TestMarkdownGeneratedDeltaGrouped(t *testing.T) {
	s := &stats.Stats{
		Package:  stats.PkgRef{Ecosystem: "gha", Name: "actions/checkout"},
		Security: stats.Security{Queried: true},
		Files: stats.FilesSection{Entries: []stats.FileEntry{
			{Path: "dist/index.js", Status: "M", Class: "generated", Added: 74909},
		}},
	}
	out := Markdown([]BulkResult{{Ref: "gha:actions/checkout a b", Stats: s}})
	if !strings.Contains(out, "74,909") {
		t.Errorf("generated-delta line count should be comma-grouped:\n%s", out)
	}
	if strings.Contains(out, "74909") {
		t.Errorf("ungrouped line count leaked:\n%s", out)
	}
}

// TestMarkdownProvenanceCoverageFlip: the coverage footer stops listing "publish
// provenance" as not-checked once provenance actually ran for a dep, and keeps
// listing it when nothing ran.
func TestMarkdownProvenanceCoverageFlip(t *testing.T) {
	ran := Markdown([]BulkResult{{Ref: "npm:x 1 -> 2", Stats: &stats.Stats{
		Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: true},
		Provenance: &provenance.Result{Queried: true},
	}}})
	if strings.Contains(ran, "publish provenance") {
		t.Errorf("provenance ran; footer must not call it not-checked:\n%s", ran)
	}
	none := Markdown([]BulkResult{{Ref: "gha:x v1 -> v2", Stats: &stats.Stats{
		Package: stats.PkgRef{Ecosystem: "gha"}, Security: stats.Security{Queried: false},
	}}})
	if !strings.Contains(none, "publish provenance") {
		t.Errorf("no provenance run; footer must still list it:\n%s", none)
	}
}

func TestMarkdownHeadlineTiers(t *testing.T) {
	out := Markdown([]BulkResult{{Ref: "npm:ms 2.1.2 -> 2.1.3", Stats: cleanStats()}})
	if !strings.Contains(out, "no signals tripped") {
		t.Errorf("clean set should read 'no signals tripped':\n%s", out)
	}
	// the headline already says "no signals tripped"; an all-clean set must not
	// also append a redundant "N others: no signals tripped." line
	if strings.Contains(out, "other") {
		t.Errorf("all-clean set must not append the redundant 'others' line:\n%s", out)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "<!-- depsound -->") {
		t.Error("missing trailing upsert marker")
	}
	if !strings.HasPrefix(out, "<!-- depsound-title:") {
		t.Error("missing leading check-title marker")
	}

	// module-format flip is a compatibility signal to weigh
	s := cleanStats()
	s.Compat = stats.Compat{TypeFrom: "commonjs", TypeTo: "module"}
	out = Markdown([]BulkResult{{Ref: "npm:commander 14 -> 15", Stats: s}})
	if !strings.Contains(out, "review the changes") {
		t.Errorf("compat flip should read 'review the changes':\n%s", out)
	}
	if !strings.Contains(out, "module format changed: commonjs → module") {
		t.Errorf("missing module-format phrase:\n%s", out)
	}
	if !strings.Contains(out, "npm:commander 14 → 15") {
		t.Errorf("ref should render with a unicode arrow:\n%s", out)
	}

	// an introduced advisory is the loud tier
	s = cleanStats()
	s.Security = stats.Security{Queried: true, Introduced: []osv.Vuln{{ID: "GHSA-xxxx-yyyy-zzzz"}}}
	out = Markdown([]BulkResult{{Ref: "npm:x 1 -> 2", Stats: s}})
	if !strings.Contains(out, "look at now") {
		t.Errorf("introduced CVE should read 'look at now':\n%s", out)
	}
	if !strings.Contains(out, "GHSA-xxxx-yyyy-zzzz") {
		t.Errorf("missing advisory id:\n%s", out)
	}
}

// A large generated/bundled delta (the npm dist/ case) is review-worthy but
// must NOT dominate the headline the way an introduced CVE does.
func TestMarkdownGeneratedDeltaWeighs(t *testing.T) {
	s := cleanStats()
	s.Files.Entries = []stats.FileEntry{
		{Path: "dist/bundle.js", Status: "M", Class: "generated", Added: 150, Removed: 60},
	}
	out := Markdown([]BulkResult{{Ref: "npm:pkg 1.0.0 -> 1.1.0", Stats: s}})
	if strings.Contains(out, "look at now") {
		t.Errorf("generated-delta alone must not read 'look at now':\n%s", out)
	}
	if !strings.Contains(out, "review the changes") {
		t.Errorf("generated-delta should read 'review the changes':\n%s", out)
	}
	if !strings.Contains(out, "dist/bundle.js") {
		t.Errorf("should name the generated file:\n%s", out)
	}
}

// A newly-added dependency has no prior version to diff, so it rides the
// stream as a census: it must appear (never silently absent), floor at the
// weigh tier (unreviewed surface), and go loud on a shipped CVE or install code.
func TestMarkdownNewDependency(t *testing.T) {
	c := &Census{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Files: 3}
	out := Markdown([]BulkResult{{Ref: "npm:left-pad 1.3.0", Census: c}})
	if !strings.Contains(out, "new dependency") {
		t.Errorf("a new dep should be labelled:\n%s", out)
	}
	if !strings.Contains(out, "adopting 3 files") {
		t.Errorf("should state the footprint:\n%s", out)
	}
	if !strings.Contains(out, "review the changes") || strings.Contains(out, "no signals tripped") {
		t.Errorf("a new dep floors at weigh and is never clean:\n%s", out)
	}

	c = &Census{
		Ecosystem: "npm", Name: "evil", Version: "9.9.9", Files: 12,
		OSVQueried: true,
		Vulns:      []osv.Vuln{{ID: "GHSA-aaaa-bbbb-cccc"}},
		Lifecycle:  []manifest.Change{{Key: "postinstall", Status: "present"}},
	}
	out = Markdown([]BulkResult{{Ref: "npm:evil 9.9.9", Census: c}})
	if !strings.Contains(out, "look at now") {
		t.Errorf("CVE + install script is the loud tier:\n%s", out)
	}
	if !strings.Contains(out, "runs code on install/build: postinstall") {
		t.Errorf("should surface the install execution surface:\n%s", out)
	}
	if !strings.Contains(out, "GHSA-aaaa-bbbb-cccc") {
		t.Errorf("should link the advisory:\n%s", out)
	}
}

// A redirect (a trusted name served off the registry) is the loud tier, names
// its target, and escapes an attacker-controlled target.
func TestMarkdownRedirect(t *testing.T) {
	out := Markdown([]BulkResult{{Ref: "go:github.com/trusted/x", Redirect: "github.com/attacker/x@v1.2.0"}})
	if !strings.Contains(out, "look at now") {
		t.Errorf("a redirect is the loud tier:\n%s", out)
	}
	if !strings.Contains(out, "redirect") || !strings.Contains(out, "github.com/attacker/x") {
		t.Errorf("should label the redirect and name the target:\n%s", out)
	}
	if strings.Contains(out, "no signals tripped") {
		t.Errorf("a redirect must never read as clean:\n%s", out)
	}
	out = Markdown([]BulkResult{{Ref: "go:x", Redirect: "evil <img src=x>"}})
	if strings.Contains(out, "<img") {
		t.Errorf("redirect target not escaped:\n%s", out)
	}
}

// A hostile package name or error must not inject HTML or Markdown. The whole
// comment is active Markdown now (no embedded report), so check all of it.
func TestMarkdownEscapesHostileValues(t *testing.T) {
	hostile := "npm:evil <img src=x onerror=alert(1)> `code` *bold* [l](u)"
	out := Markdown([]BulkResult{{Ref: hostile, Stats: nil, Err: "boom <script>"}})

	for _, raw := range []string{"<img", "<script"} {
		if strings.Contains(out, raw) {
			t.Errorf("raw %q reached the comment (injection):\n%s", raw, out)
		}
	}
	if !strings.Contains(out, "&lt;img") {
		t.Errorf("hostile ref not HTML-escaped:\n%s", out)
	}
}

// The router shouts "INTRODUCED" (caps) in its terminal output; that must not
// leak into a comment bullet.
func TestMarkdownExecDeshout(t *testing.T) {
	s := cleanStats()
	s.Runnable = stats.Runnable{CgoTo: true} // cgo newly introduced (was absent)
	out := Markdown([]BulkResult{{Ref: "go:example.com/x v1 -> v2", Stats: s}})
	if strings.Contains(out, "INTRODUCED") {
		t.Errorf("terminal shout leaked into comment:\n%s", out)
	}
	if !strings.Contains(out, "new execution surface: cgo") {
		t.Errorf("expected clean exec phrase:\n%s", out)
	}
	if !strings.Contains(out, "look at now") {
		t.Errorf("new execution surface should be the loud tier:\n%s", out)
	}
}

// A rich compat change must name the constraints that matter (MSRV must not
// hide) and count feature churn, never a dangling "+N more".
func TestMarkdownCompatNamesConstraints(t *testing.T) {
	s := cleanStats()
	s.Compat = stats.Compat{Constraints: []manifest.Change{
		{Key: "edition", Status: "changed", From: "2021", To: "2024"},
		{Key: "rust-version (MSRV)", Status: "changed", From: "1.63", To: "1.85"},
		{Key: "feature.foo", Status: "added", To: "dep:x"},
		{Key: "feature.bar", Status: "changed", From: "a", To: "b"},
	}}
	out := Markdown([]BulkResult{{Ref: "crates:x 1 -> 2", Stats: s}})
	if strings.Contains(out, "more)") {
		t.Errorf("no bare '(+N more)' should survive:\n%s", out)
	}
	if !strings.Contains(out, "rust-version (MSRV) 1.63 → 1.85") {
		t.Errorf("MSRV must be surfaced, not hidden in a count:\n%s", out)
	}
	if !strings.Contains(out, "2 feature changes") {
		t.Errorf("feature churn should be named and counted:\n%s", out)
	}
}

// Advisory ids render as clickable links to their authoritative pages, with
// the charset check as the sanitizer (a malformed id gets no link).
func TestMarkdownLinksAdvisories(t *testing.T) {
	s := cleanStats()
	s.Security = stats.Security{
		Queried:      true,
		Introduced:   []osv.Vuln{{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2026-1111"}}},
		StillPresent: []osv.Vuln{{ID: "RUSTSEC-2026-0097"}},
	}
	out := Markdown([]BulkResult{{Ref: "npm:x 1 -> 2", Stats: s}})
	if !strings.Contains(out, "[CVE-2026-1111](https://www.cve.org/CVERecord?id=CVE-2026-1111)") {
		t.Errorf("CVE not linked to cve.org (alias preferred as label):\n%s", out)
	}
	if !strings.Contains(out, "[RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097.html)") {
		t.Errorf("RUSTSEC not linked:\n%s", out)
	}
	if got := vulnLink("evil id](http://x)"); strings.Contains(got, "](http") {
		t.Errorf("malformed id must not become a link: %q", got)
	}
}

func TestCommas(t *testing.T) {
	for in, want := range map[int]string{
		0: "0", 42: "42", 999: "999", 1000: "1,000",
		49532: "49,532", 1234567: "1,234,567",
		-123: "-123", -49532: "-49,532",
	} {
		if got := commas(in); got != want {
			t.Errorf("commas(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestMdTaint(t *testing.T) {
	// each metacharacter checked in isolation: entity encodings contain '#'
	// and digits, so a combined input would collide (&#124; holds "#12").
	cases := map[string]string{
		"<b>":    "<b>",
		"*x*":    "*x*",
		"`y`":    "`y`",
		"[a](b)": "](b)",
		"~~z~~":  "~~z~~",
		"@user":  "@user",
		"#12":    "#12",
		"|c|":    "|c|",
	}
	for in, active := range cases {
		if got := mdTaint(in); strings.Contains(got, active) {
			t.Errorf("mdTaint(%q) left active %q: %q", in, active, got)
		}
	}
	// newlines cannot survive taint(), so a value cannot inject a block
	if strings.ContainsAny(mdTaint("a\nb\r\n## heading"), "\n\r") {
		t.Errorf("newline survived mdTaint (block-injection risk): %q", mdTaint("a\nb\r\n## heading"))
	}
	// taint() runs first and emits its own metacharacters (\ in \xNN, [] in
	// its truncation marker); mdTaint must encode those ONCE, no double-escape
	if got := mdTaint("\x1b[x]"); got != "&#92;x1b&#91;x&#93;" {
		t.Errorf("taint+encode composition = %q, want single-encoded", got)
	}
	if strings.Contains(mdTaint("a&b"), "&amp;amp;") {
		t.Error("ampersand double-encoded")
	}
	// the character still displays: @ suppressed as a mention but shown
	if !strings.Contains(mdTaint("@scope/pkg"), "&#64;scope/pkg") {
		t.Errorf("scoped name should display but not mention: %q", mdTaint("@scope/pkg"))
	}
}
