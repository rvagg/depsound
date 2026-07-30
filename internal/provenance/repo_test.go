package provenance

import "testing"

// npm's repository field and deps.dev's source link spell the same repo many
// ways. A spelling difference is not a repo difference, and treating one as a
// mismatch put "account-takeover shape" on unrelated packages.
func TestTrimRepoNormalisesSpellings(t *testing.T) {
	const want = "github.com/isaacs/minimatch"
	for _, u := range []string{
		"github.com/isaacs/minimatch",
		"https://github.com/isaacs/minimatch",
		"https://github.com/isaacs/minimatch.git",
		"http://github.com/isaacs/minimatch",
		"git://github.com/isaacs/minimatch",
		"git://github.com/isaacs/minimatch.git",
		"git+https://github.com/isaacs/minimatch.git",
		"git+ssh://git@github.com/isaacs/minimatch.git",
		"ssh://git@github.com/isaacs/minimatch",
		"git@github.com:isaacs/minimatch.git",
		"github.com:isaacs/minimatch",
		"https://github.com/isaacs/minimatch/",
		"https://github.com/Isaacs/MiniMatch",
	} {
		if got := trimRepo(u); got != want {
			t.Errorf("trimRepo(%q) = %q, want %q", u, got, want)
		}
	}
}

func TestRepoMismatchOnlyOnRealDifference(t *testing.T) {
	if repoMismatch("github.com/juliangruber/brace-expansion", "git://github.com/juliangruber/brace-expansion") {
		t.Error("a scheme difference is not a repo difference")
	}
	if !repoMismatch("github.com/o/r", "github.com/attacker/r") {
		t.Error("a genuinely different repo must still mismatch")
	}
	// an unknown side is not a mismatch, it is missing data
	if repoMismatch("", "github.com/o/r") || repoMismatch("github.com/o/r", "") {
		t.Error("missing data must not read as a mismatch")
	}
}
