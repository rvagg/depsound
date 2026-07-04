package fetch

import "testing"

func TestIndexPath(t *testing.T) {
	cases := map[string]string{
		"a":        "1/a",
		"bc":       "2/bc",
		"def":      "3/d/def",
		"serde":    "se/rd/serde",
		"bitflags": "bi/tf/bitflags",
	}
	for name, want := range cases {
		if got := indexPath(name); got != want {
			t.Errorf("indexPath(%q) = %q, want %q", name, got, want)
		}
	}
}
