package evidence

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/stats"
)

func TestExportRetainsEvidenceAndDeduplicates(t *testing.T) {
	cache := t.TempDir()
	workspace := filepath.Join(cache, "workspace")
	tree := filepath.Join(cache, "tree")
	mustMkdir(t, workspace)
	mustMkdir(t, tree)
	mustWrite(t, filepath.Join(workspace, "stats.json"), `{}`)
	mustWrite(t, filepath.Join(workspace, "diff.patch"), "patch")
	mustWrite(t, filepath.Join(workspace, "surface.json"), "surface")
	mustWrite(t, filepath.Join(cache, "package.crate"), "archive bytes")
	mustWrite(t, filepath.Join(cache, "sidecar.json"), `{"url":"https://registry.example/pkg","digest":"sha256-test"}`)
	mustWrite(t, filepath.Join(tree, "nested", "payload.js"), "payload")

	destination := filepath.Join(t.TempDir(), "evidence")
	input := Input{Kind: "diff", Report: map[string]any{"advisories": []string{"OSV-1"}}, Items: []Item{
		{Ref: "crates:one 1 -> 2", Workspace: workspace, Sources: []Source{{
			Side: "to", Archive: filepath.Join(cache, "package.crate"), Extension: ".crate",
			MetaFile: filepath.Join(cache, "sidecar.json"), Tree: tree,
			Metadata: &stats.Source{URL: "https://registry.example/pkg", Digest: "sha256-test"},
		}}},
		{Ref: "duplicate", Sources: []Source{{Side: "to", Archive: filepath.Join(cache, "package.crate"), Extension: ".crate"}}},
	}}
	manifest, err := Export(cache, destination, input, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ReportFile.SHA256 == "" || manifest.ReportFile.Bytes == 0 {
		t.Fatal("report hash missing")
	}
	if err := os.RemoveAll(cache); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 6 {
		t.Fatalf("copied files = %d, want 6", len(manifest.Files))
	}
	seenArchive := 0
	for _, file := range manifest.Files {
		if !strings.HasPrefix(file.Path, "data/") {
			t.Fatalf("unsafe data path %q", file.Path)
		}
		bytes := mustRead(t, filepath.Join(destination, filepath.FromSlash(file.Path)))
		digest := sha256.Sum256(bytes)
		if file.Bytes != int64(len(bytes)) || file.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("bad digest for %+v", file)
		}
		if file.Role == "archive" {
			seenArchive++
		}
	}
	if seenArchive != 1 {
		t.Fatalf("archives copied = %d", seenArchive)
	}
	owners := 0
	for _, owner := range manifest.Sources {
		if owner.Role == "archive" {
			owners++
		}
	}
	if owners != 2 {
		t.Fatalf("archive ownership entries = %d", owners)
	}
	var disk Manifest
	if err := json.Unmarshal(mustRead(t, filepath.Join(destination, "manifest.json")), &disk); err != nil {
		t.Fatal(err)
	}
	if len(disk.Sources) != len(manifest.Sources) {
		t.Fatal("manifest was not retained")
	}
}

func TestExportRetainsReviewInput(t *testing.T) {
	cache := t.TempDir()
	destination := filepath.Join(t.TempDir(), "evidence")
	packet := &manifest.ReviewPacket{
		Schema: 1, ToolVersion: "v1.2.3", Mode: "bulk", Reason: "lockfile input",
		Items: []manifest.ReviewItem{{
			Ecosystem: "npm", Name: "example", From: "1.0.0", To: "2.0.0",
			LockChange: &manifest.LockChange{
				Ecosystem: "npm", Name: "example", FromVersion: "1.0.0", ToVersion: "2.0.0",
			},
		}},
	}
	want, err := json.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Export(cache, destination, Input{Report: map[string]bool{}, Replay: packet}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReplayFile == nil {
		t.Fatal("review input record missing")
	}
	if got.ReplayFile.Path != "review-input.json" || got.ReplayFile.Role != "review-input" {
		t.Fatalf("unsafe review input record: %+v", got.ReplayFile)
	}
	digest := sha256.Sum256(want)
	if got.ReplayFile.Bytes != int64(len(want)) || got.ReplayFile.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("review input hash mismatch: %+v", got.ReplayFile)
	}
	if retained := mustRead(t, filepath.Join(destination, got.ReplayFile.Path)); string(retained) != string(want) {
		t.Fatalf("review input bytes changed: %q", retained)
	}
	var disk Manifest
	if err := json.Unmarshal(mustRead(t, filepath.Join(destination, manifestName)), &disk); err != nil {
		t.Fatal(err)
	}
	if disk.ReplayFile == nil || *disk.ReplayFile != *got.ReplayFile {
		t.Fatalf("review input record was not retained: %+v", disk.ReplayFile)
	}
}

func TestExportOmitsReviewInputWithoutReplay(t *testing.T) {
	cache := t.TempDir()
	destination := filepath.Join(t.TempDir(), "evidence")
	got, err := Export(cache, destination, Input{Report: map[string]bool{}}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReplayFile != nil {
		t.Fatalf("unexpected review input record: %+v", got.ReplayFile)
	}
	if _, err := os.Stat(filepath.Join(destination, "review-input.json")); !os.IsNotExist(err) {
		t.Fatalf("unexpected review input file: %v", err)
	}
}

func TestExportCountsReviewInputAgainstMetadataLimit(t *testing.T) {
	cache := t.TempDir()
	destination := filepath.Join(t.TempDir(), "evidence")
	report := map[string]string{"report": "retained"}
	packet := &manifest.ReviewPacket{Schema: 1, ToolVersion: "v1.2.3", Mode: "bulk", Reason: strings.Repeat("x", 128)}
	reportBytes, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	replayBytes, err := json.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	limit := int64(len(reportBytes) + len(replayBytes) - 1)
	_, err = Export(cache, destination, Input{Report: report, Replay: packet}, Limits{
		MaxFiles: 1, MaxFileBytes: 1, MaxTotalBytes: limit, MaxMetadataBytes: limit,
	})
	if err == nil || !strings.Contains(err.Error(), "review input exceed metadata limit") {
		t.Fatalf("review input did not consume metadata budget: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(destination, manifestName)); !os.IsNotExist(statErr) {
		t.Fatalf("failed export retained a manifest: %v", statErr)
	}
}

func TestExportCountsCombinedReviewMetadata(t *testing.T) {
	cache := t.TempDir()
	packet := &manifest.ReviewPacket{Schema: 1, ToolVersion: "v1.2.3", Mode: "bulk"}
	report := map[string]string{"report": "retained"}
	reportBytes, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	replayBytes, err := json.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	limit := int64(len(reportBytes) + len(replayBytes) + 1)
	destination := filepath.Join(t.TempDir(), "evidence")
	_, err = Export(cache, destination, Input{Report: report, Replay: packet}, Limits{
		MaxFiles: 1, MaxFileBytes: 1, MaxTotalBytes: limit, MaxMetadataBytes: limit,
	})
	if err == nil || !strings.Contains(err.Error(), "manifest exceed metadata limit") {
		t.Fatalf("combined metadata budget accepted report, review input, and manifest: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(destination, manifestName)); !os.IsNotExist(statErr) {
		t.Fatalf("metadata failure retained a manifest: %v", statErr)
	}
}

func TestExportTotalIncludesReviewInput(t *testing.T) {
	cache := t.TempDir()
	packet := &manifest.ReviewPacket{Schema: 1, ToolVersion: "v1.2.3", Mode: "bulk", Reason: strings.Repeat("x", 64)}
	report := map[string]string{"report": "retained"}
	limits := Limits{MaxFiles: 1, MaxFileBytes: 1, MaxTotalBytes: 10000, MaxMetadataBytes: 9000}
	destination := filepath.Join(t.TempDir(), "evidence")
	if _, err := Export(cache, destination, Input{Report: report, Replay: packet}, limits); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, name := range []string{"report.json", "review-input.json", manifestName} {
		info, err := os.Stat(filepath.Join(destination, name))
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	if total > limits.MaxTotalBytes {
		t.Fatalf("metadata bytes %d exceed total limit %d", total, limits.MaxTotalBytes)
	}
}

func TestExportPrioritizesArchivesOverWorkspace(t *testing.T) {
	cache := t.TempDir()
	workspace := filepath.Join(cache, "workspace")
	mustWrite(t, filepath.Join(workspace, "stats.json"), "s")
	mustWrite(t, filepath.Join(workspace, "diff.patch"), "p")
	mustWrite(t, filepath.Join(workspace, "surface.json"), "u")
	archive := filepath.Join(cache, "archive.tgz")
	mustWrite(t, archive, "archive")
	limits := Limits{MaxFiles: 1, MaxFileBytes: 10, MaxTotalBytes: 8192, MaxMetadataBytes: 4096}
	manifest, err := Export(cache, filepath.Join(t.TempDir(), "evidence"), Input{
		Kind: "diff", Report: map[string]string{"a": "b"},
		Items: []Item{{Workspace: workspace}, {Sources: []Source{{Archive: archive, Extension: ".tgz"}}}},
	}, limits)
	if err != nil {
		t.Fatal(err)
	}
	var workspaceFiles, archives int
	for _, file := range manifest.Files {
		switch file.Role {
		case "workspace":
			workspaceFiles++
		case "archive":
			archives++
		}
	}
	if workspaceFiles != 0 || archives != 1 {
		t.Fatalf("priority failed: workspace=%d archive=%d", workspaceFiles, archives)
	}
	if len(manifest.Omissions) == 0 || manifest.Omissions[0].Reason != "file limit reached" {
		t.Fatalf("missing explicit cap omission: %+v", manifest.Omissions)
	}
}

func TestExportSanitizesCachedMetadata(t *testing.T) {
	cache := t.TempDir()
	workspace := filepath.Join(cache, "workspace")
	sidecar := filepath.Join(cache, "package.meta.json")
	mustWrite(t, sidecar, `{"url":"https://sidecar-user:sidecar-pass@registry.example/pkg","digest":"sha256-test"}`)
	mustWrite(t, filepath.Join(workspace, "stats.json"), `{
		"artifact":{
			"sourceFrom":{"url":"https://source-user:source-pass@registry.example/from","digest":"from"},
			"sourceTo":{"url":"https://to-user:to-pass@registry.example/to","digest":"to"},
			"unavailable":[{"version":"2.0.0","kind":"denied","url":"https://unavailable-user:unavailable-pass@registry.example/to","artifactUrl":"https://artifact-user:artifact-pass@registry.example/to"}]
		}
	}`)
	destination := filepath.Join(t.TempDir(), "evidence")
	manifest, err := Export(cache, destination, Input{
		Kind: "diff", Report: map[string]bool{},
		Items: []Item{{Ref: "npm:example 1 -> 2", Workspace: workspace, Sources: []Source{{
			Side: "to", MetaFile: sidecar,
			Metadata: &stats.Source{URL: "https://manifest-user:manifest-pass@registry.example/to", Digest: "to"},
			Unavailable: &stats.Unavailable{
				Version: "2.0.0", Kind: "denied",
				URL: "https://manifest-unavailable-user:manifest-unavailable-pass@registry.example/to",
			},
		}}}},
	}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{
		"sidecar-pass", "source-pass", "to-pass", "unavailable-pass", "artifact-pass",
		"manifest-pass", "manifest-unavailable-pass",
	}
	metadataFiles := 0
	for _, file := range manifest.Files {
		if file.Role != "sidecar" && file.Role != "workspace" {
			continue
		}
		metadataFiles++
		if file.Transform != "structured-url-redaction" {
			t.Fatalf("metadata transform missing: %+v", file)
		}
		retained := mustRead(t, filepath.Join(destination, filepath.FromSlash(file.Path)))
		digest := sha256.Sum256(retained)
		if file.Bytes != int64(len(retained)) || file.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("metadata digest does not describe retained bytes: %+v", file)
		}
		originalPath := sidecar
		if file.Role == "workspace" {
			originalPath = filepath.Join(workspace, "stats.json")
		}
		originalDigest := sha256.Sum256(mustRead(t, originalPath))
		if file.OriginalSHA256 != hex.EncodeToString(originalDigest[:]) {
			t.Fatalf("metadata original digest does not describe input bytes: %+v", file)
		}
		for _, secret := range secrets {
			if strings.Contains(string(retained), secret) {
				t.Fatalf("retained metadata contains URL credential %q: %s", secret, retained)
			}
		}
	}
	if metadataFiles != 2 {
		t.Fatalf("sanitized metadata files = %d, want 2", metadataFiles)
	}
	retainedManifest := string(mustRead(t, filepath.Join(destination, manifestName)))
	for _, secret := range secrets {
		if strings.Contains(retainedManifest, secret) {
			t.Fatalf("manifest contains URL credential %q", secret)
		}
	}
}

func TestExportOmitsInvalidOrOversizedMetadata(t *testing.T) {
	cache := t.TempDir()
	invalid := filepath.Join(cache, "invalid.meta.json")
	oversized := filepath.Join(cache, "oversized.meta.json")
	mustWrite(t, invalid, "not json")
	mustWrite(t, oversized, `{"url":"https://registry.example/`+strings.Repeat("x", 128)+`","digest":"sha256-test"}`)
	limits := Limits{MaxFiles: 4, MaxFileBytes: 64, MaxTotalBytes: 8192, MaxMetadataBytes: 4096}
	manifest, err := Export(cache, filepath.Join(t.TempDir(), "evidence"), Input{
		Report: map[string]bool{}, Items: []Item{{Sources: []Source{
			{MetaFile: invalid}, {MetaFile: oversized},
		}}},
	}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 0 {
		t.Fatalf("invalid metadata was retained: %+v", manifest.Files)
	}
	if len(manifest.Omissions) != 2 ||
		!strings.Contains(manifest.Omissions[0].Reason, "invalid metadata") ||
		manifest.Omissions[1].Reason != "file size limit exceeded" {
		t.Fatalf("metadata omissions = %+v", manifest.Omissions)
	}
}

func TestExportRefusesMetadataOutsideCache(t *testing.T) {
	cache := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.meta.json")
	mustWrite(t, outside, `{"url":"https://user:pass@registry.example/pkg","digest":"sha256-test"}`)
	manifest, err := Export(cache, filepath.Join(t.TempDir(), "evidence"), Input{
		Report: map[string]bool{}, Items: []Item{{Sources: []Source{{MetaFile: outside}}}},
	}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 0 || len(manifest.Omissions) != 1 ||
		!strings.Contains(manifest.Omissions[0].Reason, "outside cache root") {
		t.Fatalf("outside metadata was retained: %+v", manifest)
	}
}

func TestExportRefusesUnsafePathsAndExistingDestinations(t *testing.T) {
	cache := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	mustWrite(t, outside, "secret")
	link := filepath.Join(cache, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "evidence")
	manifest, err := Export(cache, destination, Input{Report: map[string]bool{}, Items: []Item{{Sources: []Source{{Archive: link, Extension: ".tgz"}}}}}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 0 || len(manifest.Omissions) != 1 || !strings.Contains(manifest.Omissions[0].Reason, "symlink") {
		t.Fatalf("symlink escape retained: %+v", manifest)
	}
	if _, err := Export(cache, destination, Input{}, DefaultLimits); err == nil {
		t.Fatal("existing destination accepted")
	}
	if _, err := Export(cache, filepath.Join(cache, "nested"), Input{}, DefaultLimits); err == nil {
		t.Fatal("cache-overlapping destination accepted")
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeCache, err := filepath.Rel(cwd, cache)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Export(relativeCache, filepath.Join(relativeCache, "relative-nested"), Input{}, DefaultLimits); err == nil {
		t.Fatal("relative cache-overlapping destination accepted")
	}
}

func mustMkdir(t *testing.T, name string) {
	t.Helper()
	if err := os.MkdirAll(name, 0o700); err != nil {
		t.Fatal(err)
	}
}
func mustWrite(t *testing.T, name, content string) {
	t.Helper()
	mustMkdir(t, filepath.Dir(name))
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExportReadsCacheRootAliasWithoutFollowingInteriorLinks(t *testing.T) {
	cache := t.TempDir()
	mustWrite(t, filepath.Join(cache, "nested", "package.crate"), "retained archive")
	alias := filepath.Join(t.TempDir(), "cache")
	if err := os.Symlink(cache, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	interior := filepath.Join(cache, "redirect")
	if err := os.Symlink(filepath.Join(cache, "nested"), interior); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "evidence")
	manifest, err := Export(alias, destination, Input{
		Report: map[string]bool{},
		Items: []Item{{Sources: []Source{
			{Archive: filepath.Join(alias, "nested", "package.crate"), Extension: ".crate"},
			{Archive: filepath.Join(alias, "redirect", "package.crate"), Extension: ".crate"},
		}}},
	}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 1 || string(mustRead(t, filepath.Join(destination, manifest.Files[0].Path))) != "retained archive" {
		t.Fatalf("cache alias lost nested regular bytes: %+v", manifest)
	}
	if len(manifest.Omissions) != 1 || manifest.Omissions[0].Role != "archive" {
		t.Fatalf("interior symlink was not recorded as an archive omission: %+v", manifest.Omissions)
	}
}

func TestExportStopsOversizedTreeWithoutDisplacingArchive(t *testing.T) {
	cache := t.TempDir()
	archive := filepath.Join(cache, "package.crate")
	tree := filepath.Join(cache, "tree")
	mustWrite(t, archive, "archive")
	for _, name := range []string{"a", "b", "c"} {
		mustWrite(t, filepath.Join(tree, name), "data")
	}
	limits := Limits{MaxFiles: 2, MaxFileBytes: 16, MaxTotalBytes: 8192, MaxMetadataBytes: 4096}
	destination := filepath.Join(t.TempDir(), "evidence")
	manifest, err := Export(cache, destination, Input{
		Report: map[string]bool{},
		Items:  []Item{{Sources: []Source{{Archive: archive, Extension: ".crate", Tree: tree}}}},
	}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 1 || manifest.Files[0].Role != "archive" {
		t.Fatalf("tree budget displaced the archive: %+v", manifest.Files)
	}
	if len(manifest.Omissions) != 1 || manifest.Omissions[0].Role != "tree" || manifest.Omissions[0].Original != "" {
		t.Fatalf("unvisited subtree was not reported: %+v", manifest.Omissions)
	}
}

func TestExportPreservesUnsafeTreePathBytes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows filenames use UTF-16")
	}
	cache := t.TempDir()
	tree := filepath.Join(cache, "tree")
	want := map[string]string{
		"file-\xfe":   "first",
		"file-\xff":   "second",
		"file-\x1b":   "escape",
		"file-\x7f":   "delete",
		"file-\u009b": "c1 control",
		"file-\u061c": "arabic letter mark",
		"file-\u200e": "left-to-right mark",
		"file-\u202e": "right-to-left override",
		"file-\u2066": "left-to-right isolate",
		"file-\u2069": "pop directional isolate",
	}
	for name, content := range want {
		mustWrite(t, filepath.Join(tree, name), content)
	}
	destination := filepath.Join(t.TempDir(), "evidence")
	_, err := Export(cache, destination, Input{
		Report: map[string]bool{}, Items: []Item{{Sources: []Source{{Tree: tree}}}},
	}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Sources []struct {
			Role             string `json:"role"`
			Original         string `json:"original"`
			OriginalEncoding string `json:"originalEncoding"`
			DataPath         string `json:"dataPath"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(destination, "manifest.json")), &manifest); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]string)
	for _, source := range manifest.Sources {
		if source.Role != "tree" {
			continue
		}
		if source.OriginalEncoding != "base64" {
			t.Fatalf("unsafe path was retained raw: %q", source.Original)
		}
		name := source.Original
		if source.OriginalEncoding == "base64" {
			raw, err := base64.StdEncoding.DecodeString(name)
			if err != nil {
				t.Fatal(err)
			}
			name = string(raw)
		}
		seen[name] = string(mustRead(t, filepath.Join(destination, source.DataPath)))
	}
	for name, content := range want {
		if seen[name] != content {
			t.Fatalf("tree path bytes lost or aliased: name=%q, retained=%v", name, seen)
		}
	}
}
