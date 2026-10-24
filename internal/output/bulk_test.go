package output

import (
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/manifest"
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

func TestBulkRendersLockSourceMetadataWithoutArtifactClaims(t *testing.T) {
	change := &manifest.LockChange{
		Ecosystem: "npm", Name: "mirror", Version: "1.2.3",
		From: []manifest.LockSource{{Location: "lock/a", Resolved: "https://old.example/mirror.tgz", Host: "old.example", Integrity: "sha512-old"}},
		To:   []manifest.LockSource{{Location: "lock/b", Resolved: "https://new.example/mirror.tgz", Host: "new.example", Integrity: "sha512-new"}},
	}
	out := Bulk([]BulkResult{{Ref: "npm:mirror 1.2.3", LockChange: change}})
	for _, value := range []string{"https://old.example/mirror.tgz", "https://new.example/mirror.tgz", "old.example", "new.example", "sha512-old", "sha512-new", "no artifacts inspected", "inspect both declared lockfile"} {
		if !strings.Contains(out, value) {
			t.Errorf("lock source report lost %q:\n%s", value, out)
		}
	}
	if strings.Contains(out, "known-advisory scan") {
		t.Errorf("metadata-only report must not imply advisory coverage:\n%s", out)
	}
}

func TestBulkRendersUnknownLockSourceFields(t *testing.T) {
	change := &manifest.LockChange{
		Ecosystem: "npm", Name: "mirror", Version: "1.2.3",
		From: []manifest.LockSource{{Location: "old"}},
		To:   []manifest.LockSource{{Location: "new"}},
	}
	out := Bulk([]BulkResult{{Ref: "npm:mirror 1.2.3", LockChange: change}})
	if strings.Count(out, "unknown") < 6 {
		t.Errorf("empty declared fields must render as unknown:\n%s", out)
	}
}
