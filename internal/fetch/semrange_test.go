package fetch

import (
	"reflect"
	"testing"
)

func TestSatisfies(t *testing.T) {
	cases := []struct {
		v, rng string
		want   bool
	}{
		{"10.2.1", "^10.2.0", true},
		{"10.9.9", "^10.2.0", true},
		{"11.0.0", "^10.2.0", false}, // caret stops at next major
		{"10.1.9", "^10.2.0", false}, // below lower bound
		{"10.2.5", "~10.2.0", true},
		{"10.3.0", "~10.2.0", false}, // tilde stops at next minor
		{"0.2.5", "^0.2.3", true},    // pre-1.0 caret: minor-locked
		{"0.3.0", "^0.2.3", false},
		{"0.0.4", "^0.0.3", false}, // pre-1.0 caret: patch-locked
		{"1.2.3", "1.2.3", true},   // exact
		{"1.2.4", "1.2.3", false},
		{"2.0.0", ">=1.5.0", true},
		{"1.4.0", ">=1.5.0", false},
		{"1.4.0", "<1.5.0", true},
		{"1.5.0", "<1.5.0", false},
		{"1.0.0", "*", true},
		{"10.2.1-beta.1", "^10.2.0", false}, // prereleases excluded
	}
	for _, c := range cases {
		if got := satisfies(c.v, c.rng); got != c.want {
			t.Errorf("satisfies(%q, %q) = %v, want %v", c.v, c.rng, got, c.want)
		}
	}
}

func TestRangeResolvable(t *testing.T) {
	for _, s := range []string{"^1.2.3", "~1.2.3", "1.2.3", ">=1.0.0", "<2.0.0", "*"} {
		if !rangeResolvable(s) {
			t.Errorf("%q should be resolvable", s)
		}
	}
	// declined: compound / hyphen / x-range, so we punt honestly, never guess
	for _, s := range []string{"^1.0.0 || ^2.0.0", "1.2.3 - 2.0.0", ">=1.0.0 <2.0.0", "1.2.x", "1.x"} {
		if rangeResolvable(s) {
			t.Errorf("%q should be declined (punt, don't guess)", s)
		}
	}
}

func TestMaxAndNewerSatisfying(t *testing.T) {
	versions := []string{"9.3.0", "10.1.0", "10.2.0", "10.2.1", "10.2.2", "11.0.0"}
	if got := maxSatisfying(versions, "^10.2.0"); got != "10.2.2" {
		t.Errorf("maxSatisfying = %q, want 10.2.2", got)
	}
	// picked 10.2.0 (say, via cooldown): the newer satisfying set another
	// consumer could install, ascending
	got := newerSatisfying(versions, "^10.2.0", "10.2.0")
	want := []string{"10.2.1", "10.2.2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("newerSatisfying = %v, want %v", got, want)
	}
	// when the pick is already the max, the set is empty
	if got := newerSatisfying(versions, "^10.2.0", "10.2.2"); len(got) != 0 {
		t.Errorf("newerSatisfying(max) = %v, want empty", got)
	}
}
