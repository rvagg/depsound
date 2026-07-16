package output

import (
	"strings"
	"testing"
)

// removedShouts are the decorative all-caps markers the shouty audit stripped
// from human/agent output. Caps are reserved for the two load-bearing warnings
// (attacker-writable DATA; no-flags != safe), which are deliberately NOT in this
// list. If one of these reappears in a rendered report, lowercase it, the
// section order and wording carry the weight, not the shout.
var removedShouts = []string{
	"WARNING", "INTRODUCED", "REDIRECTED", "UNAVAILABLE", "DENIED",
	"UNREVIEWED", "MUTABLE", "UNPINNED", "HEURISTIC", "GUESS",
	"MALICIOUSLY", "YANKED", "MISMATCH", "DROPPED",
	"COVERAGE GAP", "NO FLAGS RAISED", "FAILED (",
}

func assertNoShouts(t *testing.T, name, out string) {
	t.Helper()
	for _, s := range removedShouts {
		if strings.Contains(out, s) {
			t.Errorf("%s output contains removed decorative shout %q; caps are reserved for the two load-bearing warnings, lowercase it:\n%s", name, s, out)
		}
	}
}

// TestNoDecorativeShouting renders the fully-loaded fixture (every bulk and
// markdown section) and fails if any decoration the audit removed crept back.
func TestNoDecorativeShouting(t *testing.T) {
	results := parityFixture()
	assertNoShouts(t, "Bulk", Bulk(results))
	assertNoShouts(t, "Markdown", Markdown(results))
}
