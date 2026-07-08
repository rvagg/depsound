package provenance

import "testing"

func TestTrimRepo(t *testing.T) {
	cases := map[string]string{
		"git+https://github.com/expressjs/express.git": "github.com/expressjs/express",
		"https://github.com/serde-rs/serde":            "github.com/serde-rs/serde",
		"git@github.com:foo/bar.git":                   "github.com/foo/bar",
		"github.com/gin-gonic/gin":                     "github.com/gin-gonic/gin",
	}
	for in, want := range cases {
		if got := trimRepo(in); got != want {
			t.Errorf("trimRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRepoMismatch(t *testing.T) {
	// same repo through different URL forms is NOT a mismatch
	if repoMismatch("git+https://github.com/a/b.git", "https://github.com/a/b") {
		t.Error("URL-form differences must not read as mismatch")
	}
	// a genuinely different host/path IS
	if !repoMismatch("https://github.com/a/b", "https://github.com/evil/b") {
		t.Error("different owner must read as mismatch")
	}
	// unknown either side: no mismatch (cannot compare)
	if repoMismatch("", "github.com/a/b") {
		t.Error("missing claim must not read as mismatch")
	}
}

func TestPrevPublished(t *testing.T) {
	times := map[string]string{
		"created":  "2020-01-01T00:00:00Z",
		"modified": "2025-01-01T00:00:00Z",
		"1.0.0":    "2021-01-01T00:00:00Z",
		"1.1.0":    "2022-01-01T00:00:00Z",
		"1.2.0":    "2023-01-01T00:00:00Z",
	}
	// prior to 1.2.0 by publish time is 1.1.0 (created/modified excluded)
	if got := prevPublished(times, "1.2.0"); got != "1.1.0" {
		t.Errorf("prevPublished = %q, want 1.1.0", got)
	}
	// the earliest version has no predecessor
	if got := prevPublished(times, "1.0.0"); got != "" {
		t.Errorf("earliest version should have no predecessor, got %q", got)
	}
}

func TestGapDays(t *testing.T) {
	if d := gapDays("2022-01-01T00:00:00Z", "2022-01-31T00:00:00Z"); d != 30 {
		t.Errorf("gapDays = %d, want 30", d)
	}
}

func TestFreshnessTier(t *testing.T) {
	cases := []struct {
		age     int
		hasDate bool
		want    string
	}{
		{0, true, "under-day"},
		{1, true, "fresh"},
		{2, true, "fresh"},
		{3, true, ""},
		{400, true, ""},
		{0, false, ""}, // unknown date must not read as fresh
	}
	for _, c := range cases {
		if got := freshnessTier(c.age, c.hasDate); got != c.want {
			t.Errorf("freshnessTier(%d,%v) = %q, want %q", c.age, c.hasDate, got, c.want)
		}
	}
}

func TestInstallScriptDelta(t *testing.T) {
	// a postinstall appearing is the high-signal case
	added, changed := installScriptDelta(
		map[string]string{"test": "jest"},
		map[string]string{"test": "jest", "postinstall": "node evil.js"})
	if len(added) != 1 || added[0] != "postinstall" || len(changed) != 0 {
		t.Errorf("added=%v changed=%v, want added=[postinstall]", added, changed)
	}
	// a changed install command
	_, changed = installScriptDelta(
		map[string]string{"preinstall": "echo hi"},
		map[string]string{"preinstall": "curl x | sh"})
	if len(changed) != 1 || changed[0] != "preinstall" {
		t.Errorf("changed=%v, want [preinstall]", changed)
	}
	// unchanged install script: no delta (a build script isn't an install hook)
	added, changed = installScriptDelta(
		map[string]string{"postinstall": "x", "build": "old"},
		map[string]string{"postinstall": "x", "build": "new"})
	if len(added) != 0 || len(changed) != 0 {
		t.Errorf("stable install hooks should not fire: added=%v changed=%v", added, changed)
	}
}
