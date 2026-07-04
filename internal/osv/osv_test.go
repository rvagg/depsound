package osv

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseEmpty(t *testing.T) {
	// OSV returns a bare {} for no vulns, not {"vulns":[]}
	if v := parse([]byte(`{}`)); len(v) != 0 {
		t.Errorf("empty response parsed to %v", v)
	}
}

func TestParseVulns(t *testing.T) {
	raw := `{"vulns":[{"id":"GHSA-x","aliases":["CVE-1"],"summary":"bad",
	  "affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]}],
	  "severity":[{"score":"CVSS:3.1/..."}]}]}`
	v := parse([]byte(raw))
	if len(v) != 1 || v[0].ID != "GHSA-x" || v[0].Summary != "bad" {
		t.Fatalf("parse = %+v", v)
	}
	if len(v[0].Fixed) != 1 || v[0].Fixed[0] != "1.2.0" {
		t.Errorf("fixed = %v", v[0].Fixed)
	}
}

func TestAssessBuckets(t *testing.T) {
	// from has {A, B}; to has {B (as its CVE alias), C}. Expect:
	// A fixed, B still present (alias-deduped), C introduced.
	byVersion := map[string]string{
		"1.0.0": `{"vulns":[{"id":"GHSA-a"},{"id":"GHSA-b","aliases":["CVE-b"]}]}`,
		"2.0.0": `{"vulns":[{"id":"CVE-b","aliases":["GHSA-b"]},{"id":"GHSA-c"}]}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var q struct {
			Version string `json:"version"`
		}
		json.Unmarshal(body, &q)
		io.WriteString(w, byVersion[q.Version])
	}))
	defer srv.Close()
	orig := apiURL
	apiURL = srv.URL
	defer func() { apiURL = orig }()

	a := Assess(context.Background(), srv.Client(), "", "npm", "pkg", "1.0.0", "2.0.0")
	if !a.Queried {
		t.Fatal("not queried")
	}
	if len(a.FixedByUpgrade) != 1 || a.FixedByUpgrade[0].ID != "GHSA-a" {
		t.Errorf("fixed = %+v", a.FixedByUpgrade)
	}
	if len(a.StillPresent) != 1 { // GHSA-b == CVE-b, one vuln
		t.Errorf("still present (alias dedup) = %+v", a.StillPresent)
	}
	if len(a.Introduced) != 1 || a.Introduced[0].ID != "GHSA-c" {
		t.Errorf("introduced = %+v", a.Introduced)
	}
}

func TestAssessUnmappedEcosystem(t *testing.T) {
	a := Assess(context.Background(), http.DefaultClient, "", "pypi", "x", "1", "2")
	if a.Queried || a.Note == "" {
		t.Errorf("unmapped ecosystem should degrade, got %+v", a)
	}
}

func TestOSVVersion(t *testing.T) {
	if osvVersion("Go", "v1.2.3") != "1.2.3" {
		t.Error("Go version should strip leading v")
	}
	if osvVersion("npm", "1.2.3") != "1.2.3" {
		t.Error("npm version unchanged")
	}
}
