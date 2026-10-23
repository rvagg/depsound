package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestBulkNoProvenanceSkipsUnavailableMetadata(t *testing.T) {
	var mu sync.Mutex
	requests := map[string]int{}
	installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		requests[req.URL.Host]++
		mu.Unlock()
		if req.URL.Host != "index.crates.io" {
			return nil, fmt.Errorf("unexpected provenance request: %s", req.URL)
		}
		return artifactTestResponse(req, nil), nil
	})

	input := filepath.Join(t.TempDir(), "changes")
	if err := os.WriteFile(input, []byte("crates:changed 1.0.0 1.1.0\ncrates:added 1.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bulkCmd([]string{"--cache-dir=" + t.TempDir(), "--file=" + input, "--no-osv", "--no-provenance", "--format=json"}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if requests["index.crates.io"] != 3 {
		t.Fatalf("artifact index requests = %d, want 3", requests["index.crates.io"])
	}
	if len(requests) != 1 {
		t.Fatalf("provenance was requested despite --no-provenance: %v", requests)
	}
}

func TestTransitiveCollectsProvenanceOnlyForUnavailableContent(t *testing.T) {
	dir := t.TempDir()
	oldLock := filepath.Join(dir, "old.lock")
	newLock := filepath.Join(dir, "new.lock")
	writePolicyLock(t, oldLock, "1.0.0", "1.0.0")
	writePolicyLock(t, newLock, "1.1.0", "1.1.0")

	archives := map[string][]byte{}
	checksums := map[string]string{}
	for _, version := range []string{"1.0.0", "1.1.0"} {
		path := filepath.Join(dir, "present-"+version+".crate")
		writeTestCrateNamed(t, path, "quarantine-test-"+version, "present", "pub fn value() {}\n", false)
		archives[version] = readArtifactTestFile(t, path)
		checksums[version] = fmt.Sprintf("%x", sha256.Sum256(archives[version]))
	}

	var mu sync.Mutex
	provenance := map[string]int{}
	installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "index.crates.io":
			if strings.Contains(req.URL.Path, "missing") {
				return artifactTestResponse(req, nil), nil
			}
			return artifactTestResponse(req, []byte(fmt.Sprintf(
				"{\"vers\":%q,\"cksum\":%q}\n{\"vers\":%q,\"cksum\":%q}\n",
				"1.0.0", checksums["1.0.0"], "1.1.0", checksums["1.1.0"],
			))), nil
		case "static.crates.io":
			version := "1.0.0"
			if strings.Contains(req.URL.Path, "1.1.0") {
				version = "1.1.0"
			}
			return artifactTestResponse(req, archives[version]), nil
		case "api.deps.dev", "crates.io":
			name := "missing"
			if strings.Contains(req.URL.Path, "present") {
				name = "present"
			}
			mu.Lock()
			provenance[name]++
			mu.Unlock()
			return artifactTestResponse(req, []byte("{}")), nil
		default:
			return nil, fmt.Errorf("unexpected request: %s", req.URL)
		}
	})

	if err := transitiveCmd([]string{"crates", "--old=" + oldLock, "--new=" + newLock, "--cache-dir=" + filepath.Join(dir, "cache"), "--no-osv", "--format=json"}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if provenance["missing"] == 0 {
		t.Fatal("missing-content transitive change did not collect provenance")
	}
	if provenance["present"] != 0 {
		t.Fatalf("available-content transitive change collected provenance: %d requests", provenance["present"])
	}
}

func writePolicyLock(t *testing.T, path, missingVersion, presentVersion string) {
	t.Helper()
	body := fmt.Sprintf(`version = 4

[[package]]
name = "missing"
version = %q
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "present"
version = %q
source = "registry+https://github.com/rust-lang/crates.io-index"
`, missingVersion, presentVersion)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
