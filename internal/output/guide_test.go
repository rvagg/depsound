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

// a range-resolved endpoint is the no-lockfile case, so the transitive route
// must be one that can actually be followed there
func TestGuideTransitiveRouteFollowsResolution(t *testing.T) {
	pkg := stats.PkgRef{Ecosystem: "npm", Name: "x", From: "1.0.0", To: "2.0.0"}
	for _, tc := range []struct {
		name       string
		res        *stats.Resolution
		want, deny string
	}{
		{"exact endpoints", nil, "--old=<base package-lock.json>", "--package-lock-only"},
		{"range endpoints", &stats.Resolution{ToSpec: "^2.0.0"}, "depsound transitive npm:x 1.0.0 2.0.0", "--old=<base package-lock.json>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, next := Guide(&stats.Stats{Package: pkg, Resolution: tc.res})
			var joined string
			for _, a := range next {
				joined += a.Reason + "\n" + a.Command + "\n"
			}
			if !strings.Contains(joined, tc.want) {
				t.Errorf("missing %q in:\n%s", tc.want, joined)
			}
			if strings.Contains(joined, tc.deny) {
				t.Errorf("unfollowable route %q in:\n%s", tc.deny, joined)
			}
		})
	}
}

// a next-step is routing, and routing that gets cut mid-sentence routes
// nowhere: our own reason text must fit the tainted-line cap
func TestGuideReasonsFitTheLineCap(t *testing.T) {
	for _, res := range []*stats.Resolution{nil, {ToSpec: "^2.0.0"}} {
		_, next := Guide(&stats.Stats{
			Package:    stats.PkgRef{Ecosystem: "npm", Name: "x", From: "1.0.0", To: "2.0.0"},
			Runnable:   stats.Runnable{Lifecycle: []npmpkg.Change{{Key: "postinstall", Status: "added"}}},
			Security:   osv.Assessment{Introduced: []osv.Vuln{{ID: "GHSA-x"}}, StillPresent: []osv.Vuln{{ID: "GHSA-y"}}},
			Resolution: res,
		})
		for _, a := range next {
			if len(a.Reason) > maxTaintedLen {
				t.Errorf("reason is %d bytes, cap is %d, so it renders truncated: %q", len(a.Reason), maxTaintedLen, a.Reason)
			}
		}
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
