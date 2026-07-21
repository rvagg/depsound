package main

import (
	"os"
	"testing"

	"github.com/rvagg/depsound/internal/extract"
	"github.com/rvagg/depsound/internal/stats"
)

// ghaMovedRefs is the moved-tag detector: a cached workspace whose recorded
// source commit differs from a fresh resolution of the same mutable ref is
// stale bytes wearing a current label, and the move itself is a signal.
func TestGHAMovedRefs(t *testing.T) {
	shaA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	st := func(fromKind, fromSHA, toKind, toSHA string) *stats.Stats {
		return &stats.Stats{Artifact: stats.Artifact{
			SourceFrom: &stats.Source{Digest: "git-" + fromSHA, RefKind: fromKind},
			SourceTo:   &stats.Source{Digest: "git-" + toSHA, RefKind: toKind},
		}}
	}

	t.Run("tag moved on the to side", func(t *testing.T) {
		pins := map[string]ghaPin{"v1": {shaA, "tag"}, "v2": {shaB, "tag"}}
		moved := ghaMovedRefs(st("tag", shaA, "tag", shaA), "v1", "v2", pins)
		if len(moved) != 1 {
			t.Fatalf("want 1 moved ref, got %d", len(moved))
		}
		m := moved[0]
		if m.Side != "to" || m.Ref != "v2" || m.Prev != shaA || m.SHA != shaB {
			t.Errorf("unexpected moved ref: %+v", m)
		}
	})

	t.Run("unmoved tags are quiet", func(t *testing.T) {
		pins := map[string]ghaPin{"v1": {shaA, "tag"}, "v2": {shaB, "tag"}}
		if moved := ghaMovedRefs(st("tag", shaA, "tag", shaB), "v1", "v2", pins); len(moved) != 0 {
			t.Errorf("want no moved refs, got %+v", moved)
		}
	})

	t.Run("sha pins never report movement", func(t *testing.T) {
		// a sha pin is immutable by definition; a digest mismatch there would
		// be a cache defect, not a re-point, and must not claim one
		pins := map[string]ghaPin{shaA: {shaB, "sha"}}
		if moved := ghaMovedRefs(st("sha", shaA, "sha", shaA), shaA, shaA, pins); len(moved) != 0 {
			t.Errorf("want no moved refs for sha pins, got %+v", moved)
		}
	})

	t.Run("legacy sidecar without sources is quiet", func(t *testing.T) {
		pins := map[string]ghaPin{"v1": {shaA, "tag"}, "v2": {shaB, "tag"}}
		if moved := ghaMovedRefs(&stats.Stats{}, "v1", "v2", pins); len(moved) != 0 {
			t.Errorf("want no moved refs without recorded sources, got %+v", moved)
		}
	})
}

// The census evidence sidecar: what the extractor refused must survive tree
// reuse, and a missing/corrupt sidecar reads as nil (regenerate), never as
// no-evidence.
func TestExtractReportSidecar(t *testing.T) {
	p := t.TempDir() + "/tree.extract.json"
	if rep := readExtractReport(p); rep != nil {
		t.Errorf("missing sidecar should read nil, got %+v", rep)
	}
	want := &extract.Report{Files: 2, HostileEntries: []string{"../evil"}, SkippedLinks: []string{"l"}}
	if err := writeExtractReport(p, want); err != nil {
		t.Fatal(err)
	}
	got := readExtractReport(p)
	if got == nil || got.Files != 2 || len(got.HostileEntries) != 1 || len(got.SkippedLinks) != 1 {
		t.Errorf("round trip lost evidence: %+v", got)
	}
	if err := os.WriteFile(p, []byte("{corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rep := readExtractReport(p); rep != nil {
		t.Errorf("corrupt sidecar should read nil, got %+v", rep)
	}
}
