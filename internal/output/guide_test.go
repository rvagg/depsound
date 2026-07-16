package output

import (
	"strings"
	"testing"

	"github.com/rvagg/depsound/internal/npmpkg"
	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/stats"
)

func TestGuideCoverageAlwaysPresent(t *testing.T) {
	s := &stats.Stats{Package: stats.PkgRef{Ecosystem: "npm", Name: "x", From: "1", To: "2"}}
	cov, next := Guide(s)
	if cov == nil || len(cov.Checked) == 0 || len(cov.NotChecked) == 0 {
		t.Fatal("coverage boundary must always be present")
	}
	// even a totally quiet report gets the standing surface next-step, so
	// silence never reads as an all-clear (a lockfile ecosystem also routes
	// to transitive, so surface need not be the only step, just present)
	hasSurface := false
	for _, a := range next {
		if strings.Contains(a.Command, "surface") {
			hasSurface = true
		}
	}
	if !hasSurface {
		t.Errorf("quiet report must always route to surface: %+v", next)
	}
	// reachability must be named in what we do NOT check
	joined := strings.Join(cov.NotChecked, " ")
	if !strings.Contains(joined, "reachability") {
		t.Errorf("notChecked missing reachability: %v", cov.NotChecked)
	}
}

func TestGuideDerivesSignalSteps(t *testing.T) {
	s := &stats.Stats{
		Package:  stats.PkgRef{Ecosystem: "npm", Name: "x", From: "1", To: "2"},
		Runnable: stats.Runnable{Lifecycle: []npmpkg.Change{{Key: "postinstall", Status: "added"}}},
		Security: osv.Assessment{StillPresent: []osv.Vuln{{ID: "GHSA-x"}}},
	}
	_, next := Guide(s)
	var sawExec, sawStill bool
	for _, a := range next {
		if strings.Contains(a.Reason, "install/build code") {
			sawExec = true
		}
		if strings.Contains(a.Reason, "remain") {
			sawStill = true
		}
	}
	if !sawExec || !sawStill {
		t.Errorf("expected exec + still-present next-steps, got %+v", next)
	}
}
