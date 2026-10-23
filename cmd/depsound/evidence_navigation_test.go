package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/output"
	"github.com/rvagg/depsound/internal/stats"
)

func TestLocalEvidenceNavigationReopensReviewedDiff(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("POSIX shell unavailable")
	}
	for _, mode := range []string{"both local", "local from", "local to"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			evidence := filepath.Join(dir, "evidence ' $(touch injected)")
			if err := os.MkdirAll(evidence, 0o755); err != nil {
				t.Fatal(err)
			}
			oldPath, newPath := filepath.Join(evidence, "old.crate"), filepath.Join(evidence, "new.crate")
			writeTestCrate(t, oldPath, "quarantine-test-1.0.0", false)
			writeTestCrate(t, newPath, "quarantine-test-1.0.1", true)
			oldArchive, newArchive := readArtifactTestFile(t, oldPath), readArtifactTestFile(t, newPath)
			index := fmt.Sprintf("{\"vers\":\"1.0.0\",\"cksum\":\"%x\"}\n{\"vers\":\"1.0.1\",\"cksum\":\"%x\"}\n", sha256.Sum256(oldArchive), sha256.Sum256(newArchive))
			installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
				switch req.URL.Host {
				case "index.crates.io":
					return artifactTestResponse(req, []byte(index)), nil
				case "static.crates.io":
					if strings.HasSuffix(req.URL.Path, "1.0.0.crate") {
						return artifactTestResponse(req, oldArchive), nil
					}
					return artifactTestResponse(req, newArchive), nil
				default:
					return nil, fmt.Errorf("unexpected request: %s", req.URL)
				}
			})
			cacheDir := filepath.Join(dir, "cache ' $(touch injected)")
			args := []string{"crates:quarantine-test", "1.0.0", "1.0.1", "--cache-dir=" + cacheDir, "--format=json", "--no-osv", "--no-provenance"}
			if mode != "local to" {
				args = append(args, "--from-artifact="+oldPath)
			}
			if mode != "local from" {
				args = append(args, "--to-artifact="+newPath)
			}
			var reviewed stats.Stats
			if err := json.Unmarshal(captureEvidenceCLI(t, args), &reviewed); err != nil {
				t.Fatal(err)
			}
			var show, surface string
			for _, action := range reviewed.NextActions {
				if strings.HasPrefix(action.Command, "depsound show ") {
					show = action.Command
				}
				if strings.HasPrefix(action.Command, "depsound surface ") {
					surface = action.Command
				}
			}
			patch := captureEvidenceCLI(t, shellEvidenceArgs(t, dir, show))
			if !bytes.Contains(patch, []byte("+fn main() {}")) || bytes.Contains(patch, []byte("+++ b/src/lib.rs")) {
				t.Fatalf("show did not select the reviewed build script:\n%s", patch)
			}
			surface = strings.Replace(surface, "<your import paths>", "quarantine_test", 1) + " --format=json"
			var intersection struct {
				Workspace string `json:"workspace"`
			}
			if err := json.Unmarshal(captureEvidenceCLI(t, shellEvidenceArgs(t, dir, surface)), &intersection); err != nil {
				t.Fatal(err)
			}
			if intersection.Workspace != reviewed.Workspace {
				t.Fatalf("surface reviewed a different workspace: %q, want %q", intersection.Workspace, reviewed.Workspace)
			}
			if _, err := os.Stat(filepath.Join(dir, "injected")); !os.IsNotExist(err) {
				t.Fatalf("evidence path executed shell content: %v", err)
			}
			rendered := output.Text(&reviewed)
			if !strings.Contains(rendered, show) {
				t.Fatalf("human report lost its executable drill-down:\n%s", rendered)
			}
		})
	}
}

func TestLocalManifestIdentityDiagnosticEscapesEachValue(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "hostile.crate")
	name := `\u001b[31m\u202e` + strings.Repeat("x", 260)
	writeTestCrateNamed(t, archive, "quarantine-test-1.0.0", name, "pub fn value() {}\n", false)
	installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
		return artifactTestResponse(req, nil), nil
	})
	_, err := buildCensusWithArtifact(filepath.Join(dir, "cache"), "crates:quarantine-test", "1.0.0", 0, archive)
	if err == nil {
		t.Fatal("mislabeled manifest was accepted")
	}
	message := err.Error()
	if strings.ContainsAny(message, "\x1b\u202e\n") || !strings.Contains(message, "quarantine-test@1.0.0") {
		t.Fatalf("identity diagnostic lost escaping or the requested identity: %q", message)
	}
}

func TestResolutionDiagnosticPreservesAcquisitionFailure(t *testing.T) {
	name := strings.Repeat("x", 190)
	installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
		response := artifactTestResponse(req, []byte(`{}`))
		response.StatusCode = http.StatusServiceUnavailable
		return response, nil
	})
	_, err := analyze(t.TempDir(), "npm:"+name, "latest", "2.0.0", 0)
	failure := bulkFail("npm:"+name, err).Unavailable
	if failure == nil || failure.Kind != "transient" || failure.Status != http.StatusServiceUnavailable || failure.URL != "https://registry.npmjs.org/"+url.PathEscape(name) {
		t.Fatalf("diagnostic formatting erased structured acquisition evidence: %+v, %v", failure, err)
	}
}

func shellEvidenceArgs(t *testing.T, dir, command string) []string {
	t.Helper()
	if command == "" {
		t.Fatal("report omitted executable navigation")
	}
	cmd := exec.Command("sh", "-c", `depsound() { printf '%s\000' "$@"; }; `+command)
	cmd.Dir = dir
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("parse generated command: %v", err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
}

func captureEvidenceCLI(t *testing.T, args []string) []byte {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	original := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = original }()
	result := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		result <- data
	}()
	err = run(args)
	writer.Close()
	os.Stdout = original
	data := <-result
	if err != nil {
		t.Fatalf("run %q: %v", args, err)
	}
	return data
}
