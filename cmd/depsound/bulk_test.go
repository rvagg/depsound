package main

import (
	"reflect"
	"testing"

	"github.com/rvagg/depsound/internal/fetch"
)

func TestParseBulkLines(t *testing.T) {
	in := `
# a dependabot PR's worth of bumps
npm:hono 4.12.20 4.12.27

go:github.com/x/y v1.0.0 v1.1.0
`
	got, err := parseBulkLines(in)
	if err != nil {
		t.Fatal(err)
	}
	want := []bulkItem{
		{spec: "npm:hono", from: "4.12.20", to: "4.12.27"},
		{spec: "go:github.com/x/y", from: "v1.0.0", to: "v1.1.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

// a two-field line is a new dependency (census); a `redirect` line flags a
// non-registry source. Both ride the same stream as bumps.
func TestParseBulkLinesCensusAndRedirect(t *testing.T) {
	got, err := parseBulkLines("npm:left-pad 1.3.0\ngo:github.com/x/y v1.0.0 v1.1.0\nredirect go:github.com/a/b github.com/fork/b@v1.0.0\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []bulkItem{
		{spec: "npm:left-pad", to: "1.3.0"}, // census: empty from
		{spec: "go:github.com/x/y", from: "v1.0.0", to: "v1.1.0"},
		{spec: "go:github.com/a/b", redirect: "github.com/fork/b@v1.0.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

// TestParseBulkLinesUnresolved: an `unresolved<TAB>path<TAB>reason` line from
// detect becomes a failed row (spec is the path, failure the reason), so a
// manifest that could not be parsed rides the stream instead of vanishing.
func TestParseBulkLinesUnresolved(t *testing.T) {
	got, err := parseBulkLines("unresolved\tsub/package-lock.json\tparse new package-lock.json: invalid character 't'\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []bulkItem{{spec: "sub/package-lock.json", failure: "parse new package-lock.json: invalid character 't'"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestParseBulkLinesRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"npm:hono",          // bare spec, no version
		"hono 1 2",          // no ecosystem colon -> spec.Parse fails
		"pypi:requests 1 2", // unsupported ecosystem
		"npm:hono 1 2 3",    // too many fields
	} {
		if _, err := parseBulkLines(bad); err == nil {
			t.Errorf("parseBulkLines(%q): want error", bad)
		}
	}
}

func TestParseBulkJSON(t *testing.T) {
	got, err := parseBulkJSON([]byte(`[
		{"ecosystem":"npm","name":"hono","from":"4.12.20","to":"4.12.27"},
		{"ecosystem":"crates","name":"rand","from":"0.9.2","to":"0.10.0"}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	want := []bulkItem{
		{spec: "npm:hono", from: "4.12.20", to: "4.12.27"},
		{spec: "crates:rand", from: "0.9.2", to: "0.10.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
	if _, err := parseBulkJSON([]byte(`[{"ecosystem":"npm","name":"x"}]`)); err == nil {
		t.Error("incomplete JSON entry should error")
	}
}

func TestPositionalCount(t *testing.T) {
	if positionalCount([]string{"npm:x", "1", "2", "--no-osv"}) != 3 {
		t.Error("diff form should have 3 positionals")
	}
	if positionalCount([]string{"npm:x", "1", "--format=json"}) != 2 {
		t.Error("census form should have 2 positionals")
	}
}

func TestParseCooldown(t *testing.T) {
	for in, wantHours := range map[string]float64{"5": 120, "5d": 120, "12h": 12, "": 0} {
		d, err := parseCooldown(in)
		if err != nil {
			t.Errorf("parseCooldown(%q): %v", in, err)
		}
		if d.Hours() != wantHours {
			t.Errorf("parseCooldown(%q) = %v, want %v hours", in, d, wantHours)
		}
	}
	if _, err := parseCooldown("nonsense"); err == nil {
		t.Error("nonsense cooldown should error")
	}
}

func TestBuildResolution(t *testing.T) {
	// exact args -> no resolution noise on an ordinary diff
	if r := buildResolution("1.2.3", fetch.Resolved{Version: "1.2.3"}, "1.3.0", fetch.Resolved{Version: "1.3.0"}); r != nil {
		t.Errorf("exact args should yield nil resolution, got %+v", r)
	}
	// range to side, with an ambiguity set
	r := buildResolution("1.2.3", fetch.Resolved{Version: "1.2.3"},
		"^2.0.0", fetch.Resolved{Version: "2.1.0", Range: "^2.0.0", Newer: []string{"2.1.1", "2.2.0"}})
	if r == nil || r.FromSpec != "" || r.ToSpec != "^2.0.0" || len(r.ToNewer) != 2 {
		t.Errorf("range-to resolution = %+v", r)
	}
}
