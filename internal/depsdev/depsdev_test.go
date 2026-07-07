package depsdev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSystem(t *testing.T) {
	if s, ok := System("npm"); !ok || s != "npm" {
		t.Errorf("npm -> %q %v", s, ok)
	}
	if s, ok := System("crates"); !ok || s != "cargo" {
		t.Errorf("crates -> %q %v", s, ok)
	}
	if _, ok := System("go"); ok {
		t.Error("go should be unsupported (go.mod is the resolved set)")
	}
}

func TestDependencies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodes":[
			{"versionKey":{"system":"NPM","name":"express","version":"4.18.2"},"relation":"SELF"},
			{"versionKey":{"name":"accepts","version":"1.3.8"},"relation":"DIRECT"},
			{"versionKey":{"name":"mime","version":"1.6.0"},"relation":"INDIRECT"}
		]}`))
	}))
	defer srv.Close()
	old := base
	base = srv.URL
	defer func() { base = old }()

	nodes, err := Dependencies(context.Background(), srv.Client(), "npm", "express", "4.18.2")
	if err != nil {
		t.Fatal(err)
	}
	// SELF excluded; DIRECT/INDIRECT kept with their relation
	if len(nodes) != 2 || nodes[0].Name != "accepts" || nodes[0].Relation != "DIRECT" || nodes[1].Relation != "INDIRECT" {
		t.Errorf("nodes = %+v", nodes)
	}
}

func TestDependenciesNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "dependencies not found", http.StatusNotFound)
	}))
	defer srv.Close()
	old := base
	base = srv.URL
	defer func() { base = old }()
	if _, err := Dependencies(context.Background(), srv.Client(), "cargo", "ripgrep", "14.1.1"); err == nil {
		t.Error("404 should error (binary-only crate / unpublished)")
	}
}
