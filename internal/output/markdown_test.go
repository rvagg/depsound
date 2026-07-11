package output

import (
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/stats"
)

func cleanStats() *stats.Stats {
	return &stats.Stats{
		Tool:    stats.Tool{Name: "depsound", Version: "0.0.0"},
		Package: stats.PkgRef{Ecosystem: "npm", Name: "ms", From: "2.1.2", To: "2.1.3"},
		Compat:  stats.Compat{TypeFrom: "commonjs", TypeTo: "commonjs"},
	}
}

func TestMarkdownHeadlineTiers(t *testing.T) {
	out := Markdown([]BulkResult{{Ref: "npm:ms 2.1.2 -> 2.1.3", Stats: cleanStats()}})
	if !strings.Contains(out, "no signals tripped") {
		t.Errorf("clean set should read 'no signals tripped':\n%s", out)
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
	if !strings.Contains(out, "1 to weigh") {
		t.Errorf("compat flip should be '1 to weigh':\n%s", out)
	}
	if !strings.Contains(out, "module format changed: commonjs -> module") {
		t.Errorf("missing module-format phrase:\n%s", out)
	}

	// an introduced advisory is the loud tier
	s = cleanStats()
	s.Security = stats.Security{Introduced: []osv.Vuln{{ID: "GHSA-xxxx-yyyy-zzzz"}}}
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
	if !strings.Contains(out, "to weigh") {
		t.Errorf("generated-delta should weigh:\n%s", out)
	}
	if !strings.Contains(out, "dist/bundle.js") {
		t.Errorf("should name the generated file:\n%s", out)
	}
}

// A hostile package name or error must not inject HTML or Markdown into the
// ACTIVE region of the comment (headline + bullets + coverage). The full
// report is embedded inside a code fence, where such bytes are inert, so this
// checks only the region GitHub renders as Markdown.
func TestMarkdownEscapesHostileValues(t *testing.T) {
	hostile := "npm:evil <img src=x onerror=alert(1)> `code` *bold* [l](u)"
	out := Markdown([]BulkResult{{Ref: hostile, Stats: nil, Err: "boom <script>"}})

	active, _, _ := strings.Cut(out, "<details>")
	for _, raw := range []string{"<img", "<script"} {
		if strings.Contains(active, raw) {
			t.Errorf("raw %q reached active Markdown (injection):\n%s", raw, active)
		}
	}
	if !strings.Contains(active, "&lt;img") {
		t.Errorf("hostile ref not HTML-escaped in active region:\n%s", active)
	}
}

func TestFenceOutgrowsBackticks(t *testing.T) {
	if f := fence("no ticks"); f != "```" {
		t.Errorf("plain content fence = %q, want three", f)
	}
	if f := fence("a ``` b"); len(f) < 4 {
		t.Errorf("content with ``` needs a longer fence, got %q", f)
	}
	if f := fence("````"); f != "`````" {
		t.Errorf("fence must exceed the longest run, got %q", f)
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
