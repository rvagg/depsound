package output

import (
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/stats"
)

func TestUnavailableCensusRetainsIndependentSubtreeFacts(t *testing.T) {
	c := &Census{
		Ecosystem: "npm", Name: "root", Version: "1.0.0",
		Unavailable:       &stats.Unavailable{Version: "1.0.0", Kind: "absent"},
		OSVQueried:        true,
		Vulns:             []osv.Vuln{{ID: "MAL-ROOT", Kind: osv.KindMalware}},
		Against:           true,
		SubtreeNew:        2,
		SubtreeConflict:   1,
		SubtreeHave:       3,
		SubtreeOSVQueried: true,
		Subtree: []SubtreeDep{
			{Name: "new-dep", Version: "2.0.0", Status: "new", Advisories: []string{"GHSA-subtree"}},
			{Name: "other-new", Version: "3.0.0", Status: "new"},
			{Name: "conflict-dep", Version: "4.0.0", Status: "conflict"},
			{Name: "have-a", Version: "1.0.0", Status: "have"},
			{Name: "have-b", Version: "1.0.0", Status: "have"},
			{Name: "have-c", Version: "1.0.0", Status: "have"},
		},
	}
	c.Coverage, c.NextActions = CensusGuide(c)

	out := CensusText(c)
	for _, want := range []string{"GHSA-subtree", "new-dep", "other-new", "conflict-dep", "3 already in your tree"} {
		if !strings.Contains(out, want) {
			t.Errorf("partial census omitted independently collected fact %q:\n%s", want, out)
		}
	}
	for _, unexpected := range []string{"artifact: ", "execution surface ("} {
		if strings.Contains(out, unexpected) {
			t.Errorf("partial census claimed unavailable root inspection %q:\n%s", unexpected, out)
		}
	}

	summary := censusFootprint(c)
	for _, want := range []string{"GHSA-subtree", "2 new", "1 conflict", "3 already have"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary omitted independently collected fact %q: %q", want, summary)
		}
	}
	for name, render := range map[string]func([]BulkResult) string{"bulk": Bulk, "markdown": Markdown} {
		out := render([]BulkResult{{Ref: "npm:root 1.0.0", Census: c}})
		if !strings.Contains(out, "GHSA-subtree") || !strings.Contains(out, "MAL-ROOT") {
			t.Errorf("%s summary lost independently collected advisory IDs:\n%s", name, out)
		}
	}

	checked := strings.Join(c.Coverage.Checked, "\n")
	for _, want := range []string{"artifact acquisition status", "marginal transitive footprint", "known-advisory scan across the resolved subtree"} {
		if !strings.Contains(checked, want) {
			t.Errorf("coverage omitted %q: %#v", want, c.Coverage.Checked)
		}
	}
	for _, unexpected := range []string{"published artifact (files", "execution surface (lifecycle", "declared DIRECT dependencies"} {
		if strings.Contains(checked, unexpected) {
			t.Errorf("coverage claimed unavailable root fact %q: %#v", unexpected, c.Coverage.Checked)
		}
	}
}

func TestCensusNextActionCommandPreservesLongLocalArguments(t *testing.T) {
	longPath := strings.Repeat("x", 240)
	c := &Census{
		Coverage: &stats.Coverage{Checked: []string{"artifact acquisition status"}},
		NextActions: []stats.NextAction{{
			Reason:  "inspect locally",
			Command: "depsound npm:root 1.0.0 --cache=" + longPath + "\x1b",
		}},
	}

	out := CensusText(c)
	if !strings.Contains(out, "--cache="+longPath) {
		t.Errorf("next-action command was capped: %q", out)
	}
	if strings.Contains(out, "\x1b") || !strings.Contains(out, "\\x1b") {
		t.Errorf("next-action command did not escape controls: %q", out)
	}
}
