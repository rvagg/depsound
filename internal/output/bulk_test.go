package output

import (
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/stats"
)

// Regression: a build-execution surface present in BOTH versions (cgo
// true->true) must be flagged, not swept into "NO FLAGS RAISED". Before,
// bulk fired only on INTRODUCED exec surface, so the dep that compiles C at
// build time was the quietest in the batch.
func TestBulkFlagsPresentExecSurface(t *testing.T) {
	s := &stats.Stats{Package: stats.PkgRef{Ecosystem: "go", Name: "x", From: "1", To: "2"}}
	s.Runnable.CgoFrom = true
	s.Runnable.CgoTo = true

	out := Bulk([]BulkResult{{Ref: "go:x 1 2", Stats: s}})
	if strings.Contains(out, "no flags raised") {
		t.Error("cgo-present dep must not be reported as no-flags")
	}
	if !strings.Contains(out, "execution surface") || !strings.Contains(out, "build code may have changed") {
		t.Errorf("present exec surface not flagged:\n%s", out)
	}
}

// A large generated/binary delta (npm dist/, vendored C) is unreviewed
// surface where a payload can hide; it must flag even with no exec surface.
func TestBulkFlagsLargeGeneratedDelta(t *testing.T) {
	s := &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm", Name: "y", From: "1", To: "2"}}
	s.Files.Entries = []stats.FileEntry{
		{Path: "dist/bundle.js", Class: "generated", Added: 300, Removed: 20},
		{Path: "index.js", Class: "source", Added: 3, Removed: 1},
	}
	out := Bulk([]BulkResult{{Ref: "npm:y 1 2", Stats: s}})
	if strings.Contains(out, "no flags raised") {
		t.Error("large generated delta must not be no-flags")
	}
	if !strings.Contains(out, "dist/bundle.js") || !strings.Contains(out, "payload can hide") {
		t.Errorf("large generated delta not flagged:\n%s", out)
	}
}
