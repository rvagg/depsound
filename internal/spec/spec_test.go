package spec

import "testing"

func TestParse(t *testing.T) {
	s, err := Parse("npm:commander")
	if err != nil {
		t.Fatal(err)
	}
	if s.Eco != NPM || s.Name != "commander" {
		t.Errorf("got %+v", s)
	}

	s, err = Parse("npm:@scope/name")
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "@scope/name" {
		t.Errorf("scoped name mangled: %q", s.Name)
	}

	for _, bad := range []string{"", "commander", "npm:", "pypi:requests"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q): want error", bad)
		}
	}
}

func TestNormalizeVersion(t *testing.T) {
	cases := map[string]string{
		"v2.5.0":       "2.5.0", // dependabot/tag form
		"V2.5.0":       "2.5.0",
		"2.5.0":        "2.5.0",
		"vader.1":      "vader.1", // v not followed by a digit: not a prefix
		"v":            "v",
		"2.5.0-beta.1": "2.5.0-beta.1",
	}
	for in, want := range cases {
		if got := NormalizeVersion(NPM, in); got != want {
			t.Errorf("NormalizeVersion(npm, %q) = %q, want %q", in, got, want)
		}
	}
}
