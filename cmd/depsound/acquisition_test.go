package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/stats"
)

func TestAnalyzeRetainsIndependentAcquisitionOutcomes(t *testing.T) {
	cases := []struct {
		name                   string
		missingFrom, missingTo bool
		fromStatus             int
		transportFailure       bool
	}{
		{name: "old version absent", missingFrom: true},
		{name: "new version absent", missingTo: true},
		{name: "both versions absent", missingFrom: true, missingTo: true},
		{name: "old artifact denied", fromStatus: http.StatusForbidden},
		{name: "old metadata transport failure", transportFailure: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fromPath, toPath := filepath.Join(dir, "old.crate"), filepath.Join(dir, "new.crate")
			writeTestCrate(t, fromPath, "quarantine-test-1.0.0", false)
			writeTestCrate(t, toPath, "quarantine-test-1.0.1", true)
			fromBytes, toBytes := readArtifactTestFile(t, fromPath), readArtifactTestFile(t, toPath)
			fromChecksum, toChecksum := fmt.Sprintf("%x", sha256.Sum256(fromBytes)), fmt.Sprintf("%x", sha256.Sum256(toBytes))
			const indexURL = "https://index.crates.io/qu/ar/quarantine-test"
			const fromURL = "https://static.crates.io/crates/quarantine-test/quarantine-test-1.0.0.crate"
			const toURL = "https://static.crates.io/crates/quarantine-test/quarantine-test-1.0.1.crate"
			indexRequests, recovered := 0, false
			installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
				switch req.URL.String() {
				case indexURL:
					indexRequests++
					if tc.transportFailure && indexRequests == 1 {
						return nil, errors.New("fixture connection failure")
					}
					var body strings.Builder
					if recovered || !tc.missingFrom {
						fmt.Fprintf(&body, "{\"vers\":\"1.0.0\",\"cksum\":%q}\n", fromChecksum)
					}
					if recovered || !tc.missingTo {
						fmt.Fprintf(&body, "{\"vers\":\"1.0.1\",\"cksum\":%q}\n", toChecksum)
					}
					return artifactTestResponse(req, []byte(body.String())), nil
				case fromURL:
					response := artifactTestResponse(req, fromBytes)
					if tc.fromStatus != 0 {
						response.StatusCode = tc.fromStatus
					}
					return response, nil
				case toURL:
					return artifactTestResponse(req, toBytes), nil
				default:
					return nil, fmt.Errorf("unexpected request: %s", req.URL)
				}
			})
			cacheDir := filepath.Join(dir, "cache")
			r, err := analyze(cacheDir, "crates:quarantine-test", "1.0.0", "1.0.1", 0)
			if err != nil {
				t.Fatal(err)
			}
			wantFromUnavailable := tc.missingFrom || tc.fromStatus != 0 || tc.transportFailure
			wantFailures := 1
			if wantFromUnavailable && tc.missingTo {
				wantFailures = 2
			}
			if len(r.st.Artifact.Unavailable) != wantFailures {
				t.Fatalf("failures = %+v, want %d", r.st.Artifact.Unavailable, wantFailures)
			}
			if r.ws != "" || r.idx != nil {
				t.Fatal("partial acquisition exposed a complete diff workspace")
			}
			if wantFromUnavailable {
				if r.st.Artifact.SourceFrom != nil {
					t.Fatalf("unavailable old artifact has a source: %+v", r.st.Artifact.SourceFrom)
				}
			} else if source := r.st.Artifact.SourceFrom; source == nil || source.URL != fromURL || source.Digest != "sha256-"+fromChecksum {
				t.Fatalf("old acquisition evidence was lost: %+v", source)
			}
			if tc.missingTo {
				if r.st.Artifact.SourceTo != nil {
					t.Fatalf("unavailable new artifact has a source: %+v", r.st.Artifact.SourceTo)
				}
			} else if source := r.st.Artifact.SourceTo; source == nil || source.URL != toURL || source.Digest != "sha256-"+toChecksum {
				t.Fatalf("new acquisition evidence was lost after old failure: %+v", source)
			}
			for i, failure := range r.st.Artifact.Unavailable {
				wantSide, wantVersion, wantArtifact := "from", "1.0.0", fromURL
				if !wantFromUnavailable || i == 1 {
					wantSide, wantVersion, wantArtifact = "to", "1.0.1", toURL
				}
				wantStage, wantURL, wantStatus, wantKind := "registry-index", indexURL, http.StatusOK, "absent"
				if wantSide == "from" && tc.fromStatus != 0 {
					wantStage, wantURL, wantStatus, wantKind = "artifact", fromURL, tc.fromStatus, "denied"
				}
				if wantSide == "from" && tc.transportFailure {
					wantStatus, wantKind = 0, "transient"
				}
				if failure.Side != wantSide || failure.Version != wantVersion || failure.Stage != wantStage || failure.URL != wantURL || failure.Status != wantStatus || failure.Kind != wantKind {
					t.Fatalf("acquisition fact = %+v, want %s %s %s %s %d %s", failure, wantSide, wantVersion, wantStage, wantURL, wantStatus, wantKind)
				}
				if wantStage == "registry-index" && failure.ArtifactURL != wantArtifact {
					t.Fatalf("intended artifact URL = %q, want %q", failure.ArtifactURL, wantArtifact)
				}
			}
			if tc.name == "old version absent" {
				recovered = true
				r, err = analyze(cacheDir, "crates:quarantine-test", "1.0.0", "1.0.1", 0)
				if err != nil {
					t.Fatal(err)
				}
				if len(r.st.Artifact.Unavailable) != 0 || !r.st.Runnable.BuildRSTo || r.st.Runnable.BuildRSFrom {
					t.Fatalf("recovered artifacts did not produce their build-script delta: %+v", r.st)
				}
				assertArtifactTreeSource(t, filepath.Join(r.ws, "old"), "pub fn value() -> u8 { 1 }\n")
			}
		})
	}
}

func TestLocalChecksumObservationsRefreshAcrossWorkspaceReuse(t *testing.T) {
	dir := t.TempDir()
	fromPath, toPath := filepath.Join(dir, "old.crate"), filepath.Join(dir, "new.crate")
	writeTestCrate(t, fromPath, "quarantine-test-1.0.0", false)
	writeTestCrate(t, toPath, "quarantine-test-1.0.1", true)
	fromChecksum := fmt.Sprintf("%x", sha256.Sum256(readArtifactTestFile(t, fromPath)))
	toChecksum := fmt.Sprintf("%x", sha256.Sum256(readArtifactTestFile(t, toPath)))
	mode := "matched"
	installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "index.crates.io" {
			return nil, fmt.Errorf("unexpected request: %s", req.URL)
		}
		body := fmt.Sprintf("{\"vers\":\"1.0.0\",\"cksum\":%q}\n{\"vers\":\"1.0.1\",\"cksum\":%q}\n", fromChecksum, toChecksum)
		if mode == "version-absent" {
			body = ""
		}
		response := artifactTestResponse(req, []byte(body))
		if mode == "lookup-failed" {
			response.StatusCode = http.StatusServiceUnavailable
		}
		return response, nil
	})
	cacheDir := filepath.Join(dir, "cache")
	inputs := artifactInputs{from: fromPath, to: toPath}
	r, err := analyzeWithArtifacts(cacheDir, "crates:quarantine-test", "1.0.0", "1.0.1", 0, inputs)
	if err != nil {
		t.Fatal(err)
	}
	workspace := r.ws
	var persisted stats.Stats
	if err := json.Unmarshal(readArtifactTestFile(t, filepath.Join(workspace, "stats.json")), &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Artifact.SourceFrom.RegistryChecksum != nil || persisted.Artifact.SourceTo.RegistryChecksum != nil {
		t.Fatal("live registry lookup observations were persisted as deterministic workspace evidence")
	}
	for _, source := range []*stats.Source{persisted.Artifact.SourceFrom, persisted.Artifact.SourceTo} {
		if source.Verification != "local-sha256" {
			t.Fatalf("live registry verification was persisted as deterministic workspace evidence: %+v", source)
		}
	}
	t.Setenv("PATH", t.TempDir())
	for _, state := range []string{"matched", "lookup-failed", "version-absent"} {
		mode = state
		r, err = analyzeWithArtifacts(cacheDir, "crates:quarantine-test", "1.0.0", "1.0.1", 0, inputs)
		if err != nil {
			t.Fatal(err)
		}
		if r.ws != workspace || !r.st.Runnable.BuildRSTo || r.st.Runnable.BuildRSFrom {
			t.Fatalf("lookup state %s changed the reviewed diff: %+v", state, r.st)
		}
		for _, source := range []*stats.Source{r.st.Artifact.SourceFrom, r.st.Artifact.SourceTo} {
			observation := source.RegistryChecksum
			if observation == nil || observation.State != state || observation.URL != "https://index.crates.io/qu/ar/quarantine-test" {
				t.Fatalf("lookup state %s reused stale registry evidence: %+v", state, observation)
			}
			wantStatus, wantVerification := http.StatusOK, "local-sha256"
			if state == "matched" {
				wantVerification = "local-registry-sha256"
				if observation.Expected != source.Digest {
					t.Fatalf("registry match does not bind to the reviewed bytes: %+v", source)
				}
			} else if state == "lookup-failed" {
				wantStatus = http.StatusServiceUnavailable
			}
			if observation.Status != wantStatus || source.Verification != wantVerification {
				t.Fatalf("lookup state %s has false verification/status: %+v", state, source)
			}
		}
		assertArtifactTreeSource(t, filepath.Join(r.ws, "old"), "pub fn value() -> u8 { 1 }\n")
	}
}

func TestGHAResolutionFailuresDoNotReuseCompleteWorkspace(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	const shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	oldArchive, newArchive := acquisitionActionArchive(t, shaA, "old"), acquisitionActionArchive(t, shaB, "new")
	blocked := 0
	installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.github.com" {
			switch req.URL.Path {
			case "/repos/review/action/commits/v1", "/repos/review/action/commits/v2":
				old := strings.HasSuffix(req.URL.Path, "/v1")
				if blocked == 2 || blocked == 1 && old {
					response := artifactTestResponse(req, []byte(`{"message":"Repository access blocked","block":{"reason":"tos"}}`))
					response.StatusCode = http.StatusForbidden
					return response, nil
				}
				sha := shaB
				if old {
					sha = shaA
				}
				return artifactTestResponse(req, []byte(fmt.Sprintf(`{"sha":%q}`, sha))), nil
			case "/repos/review/action/git/ref/tags/v1", "/repos/review/action/git/ref/tags/v2":
				return artifactTestResponse(req, []byte(`{}`)), nil
			}
		}
		if req.URL.Host == "codeload.github.com" {
			switch req.URL.Path {
			case "/review/action/tar.gz/" + shaA:
				return artifactTestResponse(req, oldArchive), nil
			case "/review/action/tar.gz/" + shaB:
				return artifactTestResponse(req, newArchive), nil
			}
		}
		return nil, fmt.Errorf("unexpected request: %s", req.URL)
	})
	cacheDir := filepath.Join(t.TempDir(), "cache")
	complete, err := analyze(cacheDir, "gha:review/action", "v1", "v2", 0)
	if err != nil {
		t.Fatal(err)
	}
	if complete.st.Action == nil || complete.st.Artifact.SourceFrom.Digest != "git-"+shaA || complete.st.Artifact.SourceTo.Digest != "git-"+shaB {
		t.Fatalf("fixture did not establish a reviewed action pair: %+v", complete.st)
	}
	for _, count := range []int{1, 2} {
		blocked = count
		r, err := analyze(cacheDir, "gha:review/action", "v1", "v2", 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.st.Artifact.Unavailable) != count || r.ws != "" || r.st.Action != nil || len(r.st.MovedRefs) != 0 {
			t.Fatalf("blocked refs reused complete action evidence: %+v", r.st)
		}
		for i, failure := range r.st.Artifact.Unavailable {
			ref, side := "v1", "from"
			if i == 1 {
				ref, side = "v2", "to"
			}
			if failure.Side != side || failure.Version != ref || failure.URL != "https://api.github.com/repos/review/action/commits/"+ref || failure.Stage != "ref-resolution" || failure.Kind != "denied" || failure.Status != http.StatusForbidden || failure.Reason != "policy-blocked" || failure.PolicyReason != "tos" {
				t.Fatalf("policy-block evidence was lost: %+v", failure)
			}
		}
		if count == 1 && (r.st.Artifact.SourceTo == nil || r.st.Artifact.SourceTo.Digest != "git-"+shaB) {
			t.Fatalf("available opposite endpoint was lost: %+v", r.st.Artifact)
		}
	}
	census, err := buildCensus(cacheDir, "gha:review/action/sub", "v1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if census.Name != "review/action/sub" || census.Unavailable == nil || census.Unavailable.PolicyReason != "tos" {
		t.Fatalf("blocked scoped census lost its identity/reason: %+v", census)
	}
}

func acquisitionActionArchive(t *testing.T, sha, value string) []byte {
	t.Helper()
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{
		"action.yml": "name: fixture\nruns:\n  using: node20\n  main: index.js\n",
		"index.js":   "console.log(" + fmt.Sprintf("%q", value) + ")\n",
	} {
		if err := tw.WriteHeader(&tar.Header{Name: "action-" + sha + "/" + name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}
