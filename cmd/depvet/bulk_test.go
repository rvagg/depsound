package main

import (
	"reflect"
	"testing"
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
		{"npm:hono", "4.12.20", "4.12.27"},
		{"go:github.com/x/y", "v1.0.0", "v1.1.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestParseBulkLinesRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"npm:hono 4.12.20",  // missing to
		"hono 1 2",          // no ecosystem colon -> spec.Parse fails
		"pypi:requests 1 2", // unsupported ecosystem
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
		{"npm:hono", "4.12.20", "4.12.27"},
		{"crates:rand", "0.9.2", "0.10.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
	if _, err := parseBulkJSON([]byte(`[{"ecosystem":"npm","name":"x"}]`)); err == nil {
		t.Error("incomplete JSON entry should error")
	}
}
