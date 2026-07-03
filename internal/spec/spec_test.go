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
	npmCases := map[string]string{
		"v2.5.0":       "2.5.0", // dependabot/tag form
		"V2.5.0":       "2.5.0",
		"2.5.0":        "2.5.0",
		"vader.1":      "vader.1", // v not followed by a digit: not a prefix
		"v":            "v",
		"2.5.0-beta.1": "2.5.0-beta.1",
	}
	for in, want := range npmCases {
		got, err := NormalizeVersion(NPM, in)
		if err != nil || got != want {
			t.Errorf("NormalizeVersion(npm, %q) = %q, %v, want %q", in, got, err, want)
		}
	}

	goCases := map[string]string{
		"0.20.1":                               "v0.20.1",
		"v0.20.1":                              "v0.20.1",
		"1.14.47":                              "v1.14.47",
		"v0.1.1-0.20260103110540-f8a47775ebe5": "v0.1.1-0.20260103110540-f8a47775ebe5",
		"0.1.1-0.20260103110540-f8a47775ebe5":  "v0.1.1-0.20260103110540-f8a47775ebe5",
		"v2.0.0+incompatible":                  "v2.0.0+incompatible",
	}
	for in, want := range goCases {
		got, err := NormalizeVersion(Go, in)
		if err != nil || got != want {
			t.Errorf("NormalizeVersion(go, %q) = %q, %v, want %q", in, got, err, want)
		}
	}

	// commit hashes and branch names must fail clearly, not 404 weirdly
	for _, bad := range []string{"f8a47775ebe5", "master", "0abc123def"} {
		if got, err := NormalizeVersion(Go, bad); err == nil {
			t.Errorf("NormalizeVersion(go, %q) = %q, want error", bad, got)
		}
	}
}
