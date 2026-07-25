package output

import (
	"strings"
	"testing"
)

// A projected subtree is deps.dev's isolated resolve of the dep's own tree,
// so the render must never let it read as "your tree changed by this much".
func TestTransitiveProjectedScopesTheClaim(t *testing.T) {
	out := Transitive(TransitiveResult{
		Ecosystem: "npm",
		Projected: "typescript",
		Flat:      true,
		Added:     []ModuleRef{{Path: "@ts/linux-x64", To: "7.0.2"}},
		Removed:   []ModuleRef{{Path: "old-dep", From: "1.0.0"}},
	})
	for _, want := range []string{"(projected)", "in isolation", "upper bound", "added under typescript", "no longer pulled by typescript"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// the consumer-tree wording belongs to the lockfile modes only
	for _, deny := range []string{"added to your tree", "removed from your tree", "[direct]"} {
		if strings.Contains(out, deny) {
			t.Errorf("projected render claims %q:\n%s", deny, out)
		}
	}
}

// The lockfile modes keep their own framing: this is the tree you install.
func TestTransitiveLockfileFraming(t *testing.T) {
	out := Transitive(TransitiveResult{
		Ecosystem: "npm", Kind: "pnpm",
		Added: []ModuleRef{{Path: "left-pad", To: "1.3.0"}},
	})
	if !strings.Contains(out, "added to your tree") || strings.Contains(out, "projected") {
		t.Errorf("lockfile framing lost:\n%s", out)
	}
	// pnpm resolves npm packages; the label must not hide the argument given
	if !strings.Contains(out, "pnpm (npm packages)") {
		t.Errorf("label lost the lockfile kind:\n%s", out)
	}
}
