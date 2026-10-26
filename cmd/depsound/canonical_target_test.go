package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/output"
)

func TestSourceOnlyVersionChangeCensusesCanonicalTarget(t *testing.T) {
	const name = "quarantine-test"
	oldSource := manifest.NewLockSource("old", "sparse+https://mirror.example/index/", "")
	newSource := manifest.NewLockSource("new", "registry+https://github.com/rust-lang/crates.io-index", "")
	d := diffResolved(
		[]resolvedDep{{name: name, version: "1.0.0", source: &oldSource, sourceOnly: true}},
		[]resolvedDep{{name: name, version: "2.0.0", source: &newSource}},
	)
	if len(d.changed) != 1 || d.changed[0].Declared == nil || !d.changed[0].Declared.ToRegistry {
		t.Fatalf("source-only baseline did not retain a canonical target: %+v", d)
	}

	archive := filepath.Join(t.TempDir(), name+".crate")
	writeTestCrate(t, archive, name+"-2.0.0", true)
	contents := readArtifactTestFile(t, archive)
	checksum := fmt.Sprintf("%x", sha256.Sum256(contents))
	const indexURL = "https://index.crates.io/qu/ar/quarantine-test"
	const artifactURL = "https://static.crates.io/crates/quarantine-test/quarantine-test-2.0.0.crate"
	requests := map[string]int{}
	installArtifactTestTransport(t, func(req *http.Request) (*http.Response, error) {
		requests[req.URL.String()]++
		switch req.URL.String() {
		case indexURL:
			return artifactTestResponse(req, []byte(fmt.Sprintf("{\"vers\":\"2.0.0\",\"cksum\":%q}\n", checksum))), nil
		case artifactURL:
			return artifactTestResponse(req, contents), nil
		default:
			return nil, fmt.Errorf("old or non-canonical acquisition requested: %s", req.URL)
		}
	})

	item := itemForRef("crates", d.changed[0])
	if item.from != "" || item.to != "2.0.0" || item.lockChange == nil {
		t.Fatalf("canonical transition item = %+v", item)
	}
	results := runBulk(t.TempDir(), []bulkItem{item}, true, provenanceDisabled, 0)
	if len(results) != 1 || results[0].LockChange == nil || results[0].Census == nil || results[0].Err != "" || results[0].Unavailable != nil {
		t.Fatalf("canonical target census was not retained with declaration: %+v", results)
	}
	if requests[indexURL] != 1 || requests[artifactURL] != 1 || len(requests) != 2 {
		t.Fatalf("canonical census requests = %+v", requests)
	}
}

func TestDetectBulkPacketPreservesCanonicalTransition(t *testing.T) {
	old := writeDetectLock(t, "old", "[[package]]\nname = \"x\"\nversion = \"1.0.0\"\nsource = \"sparse+https://mirror.example/index/\"\n")
	niu := writeDetectLock(t, "new", "[[package]]\nname = \"x\"\nversion = \"2.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n")
	detected := detectChanges([]detectPair{{path: "Cargo.lock", old: old, new: niu}})
	if len(detected.LockChanges) != 1 || !detected.LockChanges[0].ToRegistry || len(detected.Changed) != 0 {
		t.Fatalf("detect transition = %+v", detected)
	}
	raw, err := json.Marshal(detected.LockChanges[0])
	if err != nil {
		t.Fatal(err)
	}
	items, err := parseBulkLines("lock-change " + string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].to != "2.0.0" || !items[0].lockChange.ToRegistry {
		t.Fatalf("bulk line lost canonical target: %+v", items)
	}
	packet := bulkReplay(items, []output.BulkResult{{Ref: items[0].lockChange.Ref(), LockChange: items[0].lockChange, Census: &output.Census{Ecosystem: "crates", Name: "x", Version: "2.0.0"}}})
	packetRaw, err := json.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := parseReviewPacket(packetRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(replayed) != 1 || replayed[0].to != "2.0.0" || !replayed[0].lockChange.ToRegistry {
		t.Fatalf("replay packet lost canonical target: %+v", replayed)
	}
}

func TestToRegistryValidationAndUnavailableReplay(t *testing.T) {
	change := &manifest.LockChange{Ecosystem: "npm", Name: "x", Kind: "source", Version: "1.0.0", ToRegistry: true, From: []manifest.LockSource{{}}, To: []manifest.LockSource{{}}}
	if err := validateLockChange(change); err == nil {
		t.Fatal("accepted toRegistry outside a version change")
	}
	change.Kind, change.Version, change.FromVersion, change.ToVersion = "version", "", "1.0.0", "2.0.0"
	items := []bulkItem{{spec: "npm:x", to: "2.0.0", lockChange: change}}
	packet := bulkReplay(items, []output.BulkResult{{Ref: change.Ref(), LockChange: change, Err: "registry unavailable"}})
	if packet.Mode != "evidence" {
		t.Fatalf("unavailable canonical census advertised replay: %+v", packet)
	}
}

func writeDetectLock(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
