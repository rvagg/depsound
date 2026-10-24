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

	"github.com/rvagg/depsound/internal/stats"
)

func TestExportRetainsEvidenceAndDeduplicates(t *testing.T) {
	cache := t.TempDir()
	workspace := filepath.Join(cache, "workspace")
	tree := filepath.Join(cache, "tree")
	mustMkdir(t, workspace)
	mustMkdir(t, tree)
	mustWrite(t, filepath.Join(workspace, "stats.json"), "persisted stats")
	mustWrite(t, filepath.Join(workspace, "diff.patch"), "patch")
	mustWrite(t, filepath.Join(workspace, "surface.json"), "surface")
	mustWrite(t, filepath.Join(cache, "package.crate"), "archive bytes")
	mustWrite(t, filepath.Join(cache, "sidecar.json"), "sidecar")
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
