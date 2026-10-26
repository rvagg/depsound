package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/output"
	"github.com/rvagg/depsound/internal/version"
)

func TestReviewPacketRejectsIncompatibleOrNonReplayableInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		packet manifest.ReviewPacket
	}{
		{"schema", manifest.ReviewPacket{Schema: 2, ToolVersion: version.Version, Mode: "bulk"}},
		{"version", manifest.ReviewPacket{Schema: 1, ToolVersion: "other-version", Mode: "bulk"}},
		{"evidence", manifest.ReviewPacket{Schema: 1, ToolVersion: version.Version, Mode: "evidence"}},
		{"mode", manifest.ReviewPacket{Schema: 1, ToolVersion: version.Version, Mode: "shell"}},
		{"empty", manifest.ReviewPacket{Schema: 1, ToolVersion: version.Version, Mode: "bulk"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.packet)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseReviewPacket(raw); err == nil {
				t.Fatal("unusable review input accepted")
			}
		})
	}
}

func TestMetadataReviewPacketDoesNotAcquireCanonicalReplacement(t *testing.T) {
	packet := manifest.ReviewPacket{Schema: 1, ToolVersion: version.Version, Mode: "bulk", Items: []manifest.ReviewItem{{LockChange: &manifest.LockChange{
		Ecosystem: "npm", Name: "x$(id)", Kind: "added", ToVersion: "1.0.0", To: []manifest.LockSource{{Resolved: "https://mirror.example/x.tgz"}},
	}}}}
	raw, err := json.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	items, err := parseReviewPacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
		t.Errorf("metadata replay acquired %s", req.URL)
		return nil, http.ErrNotSupported
	})
	results := runBulk(t.TempDir(), items, false, provenanceFull, 0)
	if len(results) != 1 || results[0].LockChange == nil || results[0].Stats != nil || results[0].Census != nil || results[0].Err != "" {
		t.Fatalf("metadata replay became an artifact query: %+v", results)
	}
	if !strings.Contains(results[0].Ref, "x$(id)") {
		t.Fatalf("package data lost: %q", results[0].Ref)
	}
}

func TestBulkReplayRetainsReplayableItemsBesideEvidenceOnlyRows(t *testing.T) {
	items := []bulkItem{
		{spec: "npm:good", to: "1.0.0"},
		{spec: "npm:bad", to: "2.0.0"},
	}
	packet := bulkReplay(items, []output.BulkResult{
		{Ref: "npm:good 1.0.0", Census: &output.Census{Ecosystem: "npm", Name: "good", Version: "1.0.0"}},
		{Ref: "npm:bad 2.0.0\nignored", Err: "artifact unavailable"},
	})
	if packet.Mode != "bulk" || len(packet.Items) != 1 || len(packet.Omitted) != 1 || strings.Contains(packet.Omitted[0].Ref, "\n") {
		t.Fatalf("mixed replay packet = %+v", packet)
	}
	replayed, err := parseReviewPacket(mustMarshalReviewPacket(t, packet))
	if err != nil {
		t.Fatal(err)
	}
	if len(replayed) != 2 || replayed[0].to != "1.0.0" || replayed[1].failure == "" {
		t.Fatalf("mixed replay rows = %+v", replayed)
	}
}

func mustMarshalReviewPacket(t *testing.T, packet *manifest.ReviewPacket) []byte {
	t.Helper()
	raw, err := json.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
