package fetch

import (
	"context"
	"testing"
	"time"
)

func TestResolvePassthrough(t *testing.T) {
	// a concrete version needs no network and returns unchanged
	r, err := ResolveVersion(context.Background(), nil, "npm", "x", "1.2.3", 0)
	if err != nil || r.Version != "1.2.3" {
		t.Errorf("passthrough = %+v, %v", r, err)
	}
}

func TestPickCooldown(t *testing.T) {
	now := time.Now()
	cand := []candidate{
		{"1.0.0", now.Add(-30 * 24 * time.Hour)},
		{"1.1.0", now.Add(-10 * 24 * time.Hour)}, // old enough
		{"1.2.0", now.Add(-2 * 24 * time.Hour)},  // too fresh
		{"1.3.0", now.Add(-1 * time.Hour)},       // too fresh
	}
	r, err := pickCooldown(cand, 5*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "1.1.0" {
		t.Errorf("cooldown pick = %q, want 1.1.0", r.Version)
	}
	// two newer versions were withheld
	if r.Note == "" {
		t.Errorf("expected a withheld note, got none")
	}
}

func TestPickCooldownNoneOldEnough(t *testing.T) {
	now := time.Now()
	cand := []candidate{{"1.0.0", now.Add(-1 * time.Hour)}}
	if _, err := pickCooldown(cand, 5*24*time.Hour); err == nil {
		t.Error("all-too-fresh should error")
	}
}

func TestSemverGreater(t *testing.T) {
	if !semverGreater("2.0.0", "1.9.9") {
		t.Error("2.0.0 > 1.9.9")
	}
	if !semverGreater("v1.0.0", "") {
		t.Error("anything > empty")
	}
	if semverGreater("1.0.0", "1.0.1") {
		t.Error("1.0.0 !> 1.0.1")
	}
}
