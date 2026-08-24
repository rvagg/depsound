package provenance

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
	// a different host/path is
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

func TestBinNamesAndDelta(t *testing.T) {
	// object bin -> command names
	got := binNames([]byte(`{"foo":"./f.js","bar":"./b.js"}`), "pkg")
	if len(got) != 2 || got[0] != "bar" || got[1] != "foo" {
		t.Errorf("object bin names = %v", got)
	}
	// string bin -> one command named after the package, scope stripped
	if got := binNames([]byte(`"./cli.js"`), "@scope/tool"); len(got) != 1 || got[0] != "tool" {
		t.Errorf("string bin name = %v", got)
	}
	// delta: only the newly-appearing command
	if got := addedBins([]string{"foo"}, []string{"foo", "bar"}); len(got) != 1 || got[0] != "bar" {
		t.Errorf("addedBins = %v", got)
	}
}

func TestNPMDeprecationRequiresNonEmptyString(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{`"use replacement"`, "use replacement"},
		{`""`, ""},
		{`"   "`, ""},
		{`null`, ""},
		{`{"message":"not the npm contract"}`, ""},
	}
	for _, test := range cases {
		if got := npmDeprecation([]byte(test.raw)); got != test.want {
			t.Errorf("npmDeprecation(%s) = %q, want %q", test.raw, got, test.want)
		}
	}
}

func TestAssessNPMPreservesDeprecationMessageAndObservation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"repository":{"url":"https://github.com/request/request"},
			"time":{"2.88.2":"2020-02-11T15:00:00Z"},
			"versions":{"2.88.2":{"deprecated":"request has been deprecated; use another client"}}
		}`))
	}))
	defer srv.Close()
	old := npmRegistry
	npmRegistry = srv.URL
	defer func() { npmRegistry = old }()

	r := &Result{}
	if !assessNPM(t.Context(), srv.Client(), "request", "2.88.2", "", r) {
		t.Fatal("npm metadata should be collected")
	}
	if !r.Deprecated || r.DeprecationReason != "request has been deprecated; use another client" {
		t.Fatalf("deprecation = %+v", r)
	}
	if r.DeprecationScope != "npm-version" || r.DeprecationSource != srv.URL+"/request" || r.DeprecationObservedAt == "" {
		t.Fatalf("deprecation provenance = %+v", r)
	}
}

func TestAssessGoUsesLatestModForDeprecationAndRetractions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = w.Write([]byte("v1.0.0\nv1.2.0\nv1.3.0-rc.1\n"))
		case strings.HasSuffix(r.URL.Path, "/@v/v1.2.0.mod"):
			_, _ = w.Write([]byte(`// Deprecated: use example.com/mod/v2 instead.
module example.com/mod

retract v0.9.0 // published accidentally

// data corruption
retract [v1.0.0, v1.0.5]
`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := goProxy
	goProxy = srv.URL
	defer func() { goProxy = old }()

	r := &Result{}
	if !assessGo(t.Context(), srv.Client(), "example.com/mod", "v1.0.3", r) {
		t.Fatal("latest go.mod should be collected")
	}
	if !r.Deprecated || r.DeprecationReason != "use example.com/mod/v2 instead." || r.DeprecationScope != "go-module" {
		t.Fatalf("deprecation = %+v", r)
	}
	if r.DeprecationObservedAt == "" || r.DeprecationSource != srv.URL+"/example.com/mod/@v/v1.2.0.mod" {
		t.Fatalf("deprecation provenance = %+v", r)
	}
	if r.RetractionsVersion != "v1.2.0" || r.RetractionsObservedAt == "" || len(r.Retractions) != 2 {
		t.Fatalf("retractions = %+v", r)
	}
	if r.Retractions[0].MatchesReviewed || !r.Retractions[1].MatchesReviewed ||
		r.Retractions[1].Low != "v1.0.0" || r.Retractions[1].High != "v1.0.5" ||
		r.Retractions[1].Rationale != "data corruption" {
		t.Fatalf("retraction matching = %+v", r.Retractions)
	}
}

// Complete is the bar for a coverage claim: any failed source breaks it,
// unsupported sources do not (they are not lost coverage), and FailedSources
// names what each failure cost.
func TestSourceStates(t *testing.T) {
	full := &Result{Queried: true, Sources: map[string]string{"depsdev": "complete", "registry": "complete"}}
	if !full.Complete() || full.FailedSources() != nil {
		t.Errorf("all-complete should be Complete with no failures: %+v", full)
	}
	partial := &Result{Queried: true, Sources: map[string]string{"depsdev": "complete", "registry": "failed"}}
	if partial.Complete() {
		t.Error("a failed source must break Complete")
	}
	if f := partial.FailedSources(); len(f) != 1 || !strings.Contains(f[0], "registry") || !strings.Contains(f[0], "attestation") {
		t.Errorf("failure should name the source and its scope: %v", f)
	}
	goStyle := &Result{Queried: true, Sources: map[string]string{"depsdev": "complete", "registry": "unsupported"}}
	if !goStyle.Complete() || goStyle.FailedSources() != nil {
		t.Errorf("unsupported is not lost coverage: %+v", goStyle)
	}
	goFailed := &Result{Queried: true, Sources: map[string]string{"depsdev": "complete", "registry": "unsupported", "gomod": "failed"}}
	if goFailed.Complete() {
		t.Error("a failed current go.mod lookup must break Complete")
	}
	if f := goFailed.FailedSources(); len(f) != 1 || !strings.Contains(f[0], "gomod") || !strings.Contains(f[0], "retraction") {
		t.Errorf("failure should name current Go declaration coverage: %v", f)
	}
	if (&Result{Queried: false}).Complete() {
		t.Error("not-queried is never Complete")
	}
}

func TestAssessCratesPreservesRegistryActions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"crate":{"repository":"https://github.com/droundy/arrayref"},
			"versions":[
				{"num":"0.3.10","created_at":"2026-08-20T07:15:00Z","yanked":false,"crate_size":10,
				 "published_by":{"login":"droundy"},
				 "audit_actions":[{"action":"publish","time":"2026-08-20T07:15:00Z","user":{"login":"droundy"}}]},
				{"num":"0.3.9","created_at":"2024-01-01T00:00:00Z","yanked":false,"crate_size":9,
				 "published_by":{"login":"droundy"},
				 "audit_actions":[{"action":"yank","time":"2026-08-20T07:15:00.100Z","user":{"login":"droundy"}}]},
				{"num":"0.3.8","created_at":"2023-01-01T00:00:00Z","yanked":true,"crate_size":8,
				 "published_by":{"login":"droundy"},
				 "audit_actions":[{"action":"unyank","time":"2026-08-20T07:16:00Z","user":{"login":"admin"}}]}
			]
		}`))
	}))
	defer srv.Close()
	orig := cratesAPI
	cratesAPI = srv.URL
	defer func() { cratesAPI = orig }()

	r := &Result{}
	if !assessCrates(t.Context(), srv.Client(), "arrayref", "0.3.10", "0.3.9", r) {
		t.Fatal("crates.io response should be collected")
	}
	if r.RegistryActionsSource != srv.URL+"/arrayref" || r.RegistryActionsObservedAt == "" {
		t.Errorf("registry source/observation missing: %+v", r)
	}
	if r.RegistryActionsSinceVersion != "0.3.9" || r.RegistryActionsSince != "2024-01-01T00:00:00Z" {
		t.Errorf("projection baseline = %q at %q", r.RegistryActionsSinceVersion, r.RegistryActionsSince)
	}
	if len(r.RegistryActions) != 3 {
		t.Fatalf("registry actions = %+v", r.RegistryActions)
	}
	for i, want := range []string{"publish", "yank", "unyank"} {
		if r.RegistryActions[i].Action != want {
			t.Errorf("action[%d] = %+v, want %s", i, r.RegistryActions[i], want)
		}
	}
}
