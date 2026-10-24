package output

import (
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/fetch"
	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/provenance"
	"github.com/rvagg/depsound/internal/stats"
)

// parityFixture supplies varied report facts for presentation-budget checks.
func parityFixture() []BulkResult {
	return []BulkResult{
		{Ref: "npm:a 1 -> 2", Stats: &stats.Stats{
			Security: stats.Security{Queried: true,
				Introduced:     []osv.Vuln{{ID: "GHSA-a"}},
				StillPresent:   []osv.Vuln{{ID: "GHSA-b"}},
				FixedByUpgrade: []osv.Vuln{{ID: "GHSA-c"}},
			},
			Runnable: stats.Runnable{CgoTo: true, Bin: []manifest.Change{{Key: "mycli", Status: "added"}}},
			Compat:   stats.Compat{TypeFrom: "commonjs", TypeTo: "module"},
			Files: stats.FilesSection{Entries: []stats.FileEntry{
				{Path: "native.node", Status: "A", Excluded: true, Binary: true, BytesTo: 2 << 20},
				{Path: "prebuilt.wasm", Status: "M", Excluded: true, Binary: true, BytesFrom: 1 << 20, BytesTo: 3 << 20},
				{Path: "dist/b.js", Status: "M", Class: "generated", Added: 200},
			}},
			Action: &stats.ActionSection{CapsIntroduced: []string{"id-token"}, UsingFrom: "node20", UsingTo: "node24",
				Pins: []stats.ActionPin{{Side: "from", Kind: "sha", Ref: "aaaa"}, {Side: "to", Kind: "tag", Ref: "v2"}}}, // pin weakened
		}},
		{Ref: "gha:up v1 -> sha", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "gha"}, Security: stats.Security{Queried: false},
			Action: &stats.ActionSection{Pins: []stats.ActionPin{{Side: "from", Kind: "tag", Ref: "v1"}, {Side: "to", Kind: "sha", Ref: "bbbb"}}}}}, // pin strengthened
		{Ref: "go:b v1 -> v2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "go"}, Security: stats.Security{Queried: true}, Runnable: stats.Runnable{CgoFrom: true, CgoTo: true},
			Provenance: &provenance.Result{Queried: true, Deprecated: true, DeprecationScope: "go-module", DeprecationReason: "use go:b/v2", DeprecationSource: "https://proxy.example/go:b/@v/v2.mod",
				RetractionsObservedAt: "2026-08-21T00:00:00Z", RetractionsSource: "https://proxy.example/go:b/@v/v2.mod",
				Retractions: []provenance.Retraction{{Low: "v2.0.0", Rationale: "bad release", MatchesReviewed: true}},
				Sources:     map[string]string{"depsdev": "complete", "registry": "unsupported", "gomod": "complete"}}}},
		{Ref: "npm:c 1 -> 2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: false}}}, // disabled
		{Ref: "npm:f 1 -> 2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: false, Note: "OSV lookup failed"},
			Resolution: &stats.Resolution{FromSpec: "^1.0.0", ToSpec: "^2.0.0"}}}, // failed + range-resolved endpoints
		{Ref: "gha:u v1 -> v2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "gha"}, Security: stats.Security{Queried: false},
			Action:    &stats.ActionSection{Pins: []stats.ActionPin{{Side: "from", Kind: "tag", Ref: "v1"}, {Side: "to", Kind: "tag", Ref: "v2"}}},                        // pin grade: tag both sides
			MovedRefs: []stats.MovedRef{{Side: "to", Ref: "v2.0.1", Prev: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}}, // osv-unsupported + moved ref
		{Ref: "npm:hard 1 -> 2", Stats: &stats.Stats{
			Package:  stats.PkgRef{Ecosystem: "npm"},
			Security: stats.Security{Queried: true},
			Artifact: stats.Artifact{
				HostileEntries: []string{"../evil"},
				SkippedLinks:   []string{"link -> /etc/passwd"},
				SourceTo:       &stats.Source{Verification: "tls-only"},
				BytesFrom:      4 << 20, UnreviewableFrom: 0,
				BytesTo: 4 << 20, UnreviewableTo: 3 << 20, // became bundle-dominated
			},
			Compat: stats.Compat{ExportsError: "malformed exports map"},
		}},
		{Ref: "npm:gitdep 1 -> 2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: true},
			Dependencies: []manifest.DepChange{{Section: "optionalDependencies", Name: "helper", Status: "added", To: "github:o/r", Flag: "git dependency"}}}},
		{Ref: "npm:husky-ish 1 -> 2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: true},
			Runnable: stats.Runnable{LifecycleGitOnly: []manifest.Change{{Key: "prepare", Status: "added"}}}}},
		{Ref: "npm:malware 1 -> 2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"},
			Security: stats.Security{Queried: true, StillPresent: []osv.Vuln{{ID: "MAL-2022-4", Kind: osv.KindMalware}}}}},
		{Ref: "npm:hardened 1 -> 2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: true},
			Provenance: &provenance.Result{Queried: true, MaintainerChanged: true, TrustedPublisher: "github", AttestationAdded: true,
				Sources: map[string]string{"depsdev": "complete", "registry": "complete"}}}}, // onto OIDC: hardening, not a shape
		{Ref: "npm:takeover 1 -> 2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm"}, Security: stats.Security{Queried: true}, Provenance: &provenance.Result{Queried: true, MaintainerChanged: true, AttestationDropped: true, RepoMismatch: true, ClaimedRepo: "github.com/o/r", SourceRepo: "github.com/other/r",
			Sources: map[string]string{"depsdev": "complete", "registry": "failed"}}}},
		{Ref: "npm:new 1.0.0", Census: &Census{Files: 12, OSVQueried: true, Vulns: []osv.Vuln{{ID: "V"}, {ID: "MAL-2022-4", Kind: osv.KindMalware}}, Lifecycle: []manifest.Change{{Key: "postinstall"}}, BigExcluded: "blob.bin",
			HostileEntries: []string{"../evil"}, SkippedLinks: []string{"link -> /etc/passwd"}}}, // extraction evidence must survive the census path too
		{Ref: "gha:o/r/post v1 -> v2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "gha"}, Security: stats.Security{Queried: true},
			Artifact: stats.Artifact{BytesTo: 8 << 10}, // compared, and nothing differed
			Action:   &stats.ActionSection{SubPath: "post", Pins: []stats.ActionPin{{Side: "from", Kind: "sha", Ref: "aaaa"}, {Side: "to", Kind: "sha", Ref: "bbbb"}}}}},
		{Ref: "go:trusted/x", Redirect: "github.com/fork/x@v1.0.0"},
		{Ref: "npm:broke 1 -> 2", Err: "extraction failed"},
		{Ref: "npm:gone 1 -> 2", Unavailable: &Unavailable{Kind: "absent", Status: 404, URL: "https://registry.npmjs.org/gone/-/gone-2.tgz"}},
		{Ref: "npm:locked 1 -> 2", Unavailable: &Unavailable{Kind: "denied", Status: 403, URL: "https://registry.example/locked"}},
		{Ref: "npm:flaky 1 -> 2", Unavailable: &Unavailable{Kind: "transient", Status: 503, URL: "https://registry.example/flaky"}},
		{Ref: "crates:checksum 1 -> 2", Stats: &stats.Stats{Package: stats.PkgRef{Ecosystem: "crates"}, Security: stats.Security{Queried: true},
			Artifact: stats.Artifact{SourceTo: &stats.Source{RegistryChecksum: &fetch.RegistryChecksum{State: "lookup-failed", URL: "https://index.example/checksum", Error: "unavailable"}}}}},
		{Ref: "npm:source 1.0.0", LockChange: &manifest.LockChange{Ecosystem: "npm", Name: "source", Version: "1.0.0",
			From: []manifest.LockSource{{Location: "lock/old", Resolved: "https://old.example/source.tgz", Host: "old.example", Integrity: "sha512-old"}},
			To:   []manifest.LockSource{{Location: "lock/new", Resolved: "https://new.example/source.tgz", Host: "new.example", Integrity: "sha512-new"}}}},
	}
}

func TestSummaryRenderersRetainIndependentAcquisitionEvidence(t *testing.T) {
	longURL := "https://new-artifact.example/" + strings.Repeat("u", 260)
	policy := "platform-policy\x1b" + strings.Repeat("p", 260)
	hint := "lookup-failure-cause-" + strings.Repeat("h", 260)
	s := &stats.Stats{
		Package: stats.PkgRef{Ecosystem: "crates", Name: "example", From: "1.0.0", To: "2.0.0"},
		Artifact: stats.Artifact{Unavailable: []*stats.Unavailable{
			{Side: "from", Version: "1.0.0", Kind: "absent", Reason: "version-absent", URL: "https://old-index.example/pkg", ArtifactURL: "https://old-artifact.example/pkg.crate"},
			{Side: "to", Version: "2.0.0", Kind: "denied", URL: longURL, Reason: "policy-blocked", PolicyReason: policy, Hint: hint},
		}},
	}
	for name, render := range map[string]func([]BulkResult) string{"bulk": Bulk, "markdown": Markdown} {
		t.Run(name, func(t *testing.T) {
			out := render([]BulkResult{{Ref: "crates:example 1.0.0 -> 2.0.0", Stats: s}})
			for _, value := range []string{"https://old-index.example/pkg", "https://old-artifact.example/pkg.crate", longURL[:100], "platform-policy", hint[:100]} {
				if !strings.Contains(out, value) {
					t.Errorf("lost independent acquisition evidence %q:\n%s", value, out)
				}
			}
			if strings.Contains(out, "\x1b") {
				t.Fatalf("platform response injected a terminal control:\n%q", out)
			}
		})
	}
}

func TestSummaryRenderersEscapeLockSourceEvidence(t *testing.T) {
	change := &manifest.LockChange{Ecosystem: "npm", Name: "source", Version: "1.0.0",
		From: []manifest.LockSource{{Location: "old\x1b", Resolved: "https://old.example/<source>", Host: "old.example", Integrity: "sha512-old"}},
		To:   []manifest.LockSource{{Location: "new", Resolved: "https://new.example/<source>", Host: "new.example", Integrity: "sha512-new"}}}
	for name, render := range map[string]func([]BulkResult) string{"bulk": Bulk, "markdown": Markdown} {
		t.Run(name, func(t *testing.T) {
			out := render([]BulkResult{{Ref: "npm:source 1.0.0", LockChange: change}})
			for _, value := range []string{"old.example", "new.example", "sha512-old", "sha512-new"} {
				if !strings.Contains(out, value) {
					t.Errorf("lost lock source evidence %q:\n%s", value, out)
				}
			}
			if strings.Contains(out, "\x1b") {
				t.Fatalf("lock source metadata injected a control: %q", out)
			}
		})
	}
}
