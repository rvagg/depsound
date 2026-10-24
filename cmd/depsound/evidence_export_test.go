package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rvagg/depsound/internal/evidence"
	"github.com/rvagg/depsound/internal/stats"
)

func TestEvidenceExportRetainsLocalCrateDiff(t *testing.T) {
	dir := t.TempDir()
	oldPath, newPath := filepath.Join(dir, "old.crate"), filepath.Join(dir, "new.crate")
	writeTestCrate(t, oldPath, "quarantine-test-1.0.0", false)
	writeTestCrate(t, newPath, "quarantine-test-1.0.1", true)
	oldArchive, newArchive := readArtifactTestFile(t, oldPath), readArtifactTestFile(t, newPath)
	index := fmt.Sprintf("{\"vers\":\"1.0.0\",\"cksum\":\"%x\"}\n{\"vers\":\"1.0.1\",\"cksum\":\"%x\"}\n", sha256.Sum256(oldArchive), sha256.Sum256(newArchive))
	var replaced atomic.Bool
	installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "index.crates.io":
			return artifactTestResponse(req, []byte(index)), nil
		case "api.osv.dev":
			if replaced.CompareAndSwap(false, true) {
				if err := os.WriteFile(oldPath, []byte("replacement before export"), 0o600); err != nil {
					return nil, err
				}
			}
			return artifactTestResponse(req, []byte(`{"vulns":[{"id":"MAL-retained-snapshot"}]}`)), nil
		default:
			return nil, fmt.Errorf("unexpected request: %s", req.URL)
		}
	})

	cacheDir, destination := filepath.Join(dir, "cache"), filepath.Join(dir, "export")
	captureEvidenceCLI(t, []string{
		"crates:quarantine-test", "1.0.0", "1.0.1",
		"--cache-dir=" + cacheDir,
		"--evidence-dir=" + destination,
		"--from-artifact=" + oldPath,
		"--to-artifact=" + newPath,
		"--format=json", "--no-provenance",
	})

	manifestBytes, err := os.ReadFile(filepath.Join(destination, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest evidence.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}

	if !replaced.Load() {
		t.Fatal("source replacement did not occur before export")
	}
	retained, err := os.ReadFile(filepath.Join(destination, manifest.Report))
	if err != nil {
		t.Fatal(err)
	}
	var report stats.Stats
	if err := json.Unmarshal(retained, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Security.StillPresent) != 1 || report.Security.StillPresent[0].ID != "MAL-retained-snapshot" {
		t.Fatalf("retained report used cached facts instead of the current advisory snapshot: %+v", report.Security)
	}
	if err := os.RemoveAll(cacheDir); err != nil {
		t.Fatal(err)
	}
	var archives [][]byte
	for _, file := range manifest.Files {
		if file.Role != "archive" {
			continue
		}
		if !strings.HasSuffix(file.Path, ".crate") {
			t.Fatalf("archive data path = %q", file.Path)
		}
		data, err := os.ReadFile(filepath.Join(destination, filepath.FromSlash(file.Path)))
		if err != nil {
			t.Fatal(err)
		}
		archives = append(archives, data)
	}
	if len(archives) != 2 || !containsBytes(archives, oldArchive) || !containsBytes(archives, newArchive) {
		t.Fatalf("exported archives lost reviewed bytes: %d", len(archives))
	}
}

func containsBytes(values [][]byte, want []byte) bool {
	for _, value := range values {
		if bytes.Equal(value, want) {
			return true
		}
	}
	return false
}

func TestEvidenceExportRetainsPartialDiffFacts(t *testing.T) {
	dir := t.TempDir()
	newPath := filepath.Join(dir, "new.crate")
	writeTestCrate(t, newPath, "quarantine-test-1.0.1", true)
	newArchive := readArtifactTestFile(t, newPath)
	index := fmt.Sprintf("{\"vers\":\"1.0.1\",\"cksum\":\"%x\"}\n", sha256.Sum256(newArchive))
	installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "index.crates.io":
			return artifactTestResponse(req, []byte(index)), nil
		case "static.crates.io":
			if strings.HasSuffix(req.URL.Path, "1.0.1.crate") {
				return artifactTestResponse(req, newArchive), nil
			}
			return nil, fmt.Errorf("unexpected archive request: %s", req.URL)
		case "api.osv.dev":
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			if bytes.Contains(body, []byte(`"version":"1.0.1"`)) {
				return artifactTestResponse(req, []byte(`{"vulns":[{"id":"MAL-test"}]}`)), nil
			}
			return artifactTestResponse(req, []byte(`{}`)), nil
		default:
			return nil, fmt.Errorf("unexpected request: %s", req.URL)
		}
	})

	cacheDir, destination := filepath.Join(dir, "cache"), filepath.Join(dir, "export")
	captureEvidenceCLI(t, []string{
		"crates:quarantine-test", "1.0.0", "1.0.1",
		"--cache-dir=" + cacheDir, "--evidence-dir=" + destination,
		"--format=json", "--no-provenance",
	})
	retained, err := os.ReadFile(filepath.Join(destination, "stats.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report stats.Stats
	if err := json.Unmarshal(retained, &report); err != nil {
		t.Fatal(err)
	}
	if report.Artifact.SourceTo == nil || len(report.Artifact.Unavailable) != 1 || len(report.Security.Introduced) != 1 || report.Security.Introduced[0].ID != "MAL-test" {
		t.Fatalf("partial facts = %+v", report)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(destination, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest evidence.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	archives := 0
	for _, file := range manifest.Files {
		if file.Role == "archive" {
			archives++
		}
	}
	if archives != 1 {
		t.Fatalf("retained archives = %d, want available endpoint only", archives)
	}
}

func TestEvidenceExportRetainsTransitiveAddedNode(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "crate.crate")
	writeTestCrate(t, archivePath, "quarantine-test-1.0.1", true)
	archive := readArtifactTestFile(t, archivePath)
	index := fmt.Sprintf("{\"vers\":\"1.0.1\",\"cksum\":\"%x\"}\n", sha256.Sum256(archive))
	installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "index.crates.io":
			return artifactTestResponse(req, []byte(index)), nil
		case "static.crates.io":
			return artifactTestResponse(req, archive), nil
		default:
			return nil, fmt.Errorf("unexpected request: %s", req.URL)
		}
	})
	oldLock, newLock := filepath.Join(dir, "old.lock"), filepath.Join(dir, "new.lock")
	if err := os.WriteFile(oldLock, []byte("version = 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newLock, []byte("version = 3\n\n[[package]]\nname = \"quarantine-test\"\nversion = \"1.0.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "export")
	captureEvidenceCLI(t, []string{
		"transitive", "crates", "--old=" + oldLock, "--new=" + newLock,
		"--cache-dir=" + filepath.Join(dir, "cache"), "--evidence-dir=" + destination,
		"--format=json", "--no-osv",
	})
	manifestBytes, err := os.ReadFile(filepath.Join(destination, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest evidence.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	var archiveFound, buildFound bool
	for _, file := range manifest.Files {
		archiveFound = archiveFound || file.Role == "archive"
	}
	for _, source := range manifest.Sources {
		buildFound = buildFound || (source.Role == "tree" && source.Original == "build.rs")
	}
	if !archiveFound || !buildFound {
		t.Fatalf("added-node evidence archive=%t build.rs=%t", archiveFound, buildFound)
	}
}
