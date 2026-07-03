package cache

import (
	"strings"
	"testing"
)

func TestComponent(t *testing.T) {
	for _, tc := range []struct{ raw string }{
		{"commander"},
		{"@scope/name"},
		{"../../../etc/passwd"},
		{".."},
		{"."},
		{""},
		{"CON"},
		{"-rf"},
		{strings.Repeat("a", 500)},
		{"name\x00evil"},
	} {
		got := Component(tc.raw)
		if strings.ContainsAny(got, "/\\") {
			t.Errorf("Component(%q) = %q: contains path separator", tc.raw, got)
		}
		if strings.HasPrefix(got, ".") || strings.HasPrefix(got, "-") {
			t.Errorf("Component(%q) = %q: leading %q", tc.raw, got, got[0])
		}
		if len(got) > 64+9 {
			t.Errorf("Component(%q) = %q: too long (%d)", tc.raw, got, len(got))
		}
	}
}

func TestComponentUniqueness(t *testing.T) {
	// sanitized forms collide, hashes must not
	pairs := [][2]string{
		{"Foo", "foo"},
		{"@scope/name", "@scope_name"},
		{"a/b", "a_b"},
	}
	for _, p := range pairs {
		if Component(p[0]) == Component(p[1]) {
			t.Errorf("Component(%q) == Component(%q) = %q", p[0], p[1], Component(p[0]))
		}
	}
}

func TestComponentStable(t *testing.T) {
	a := Component("commander")
	b := Component("commander")
	if a != b {
		t.Errorf("Component not deterministic: %q vs %q", a, b)
	}
	if want := "commander-"; !strings.HasPrefix(a, want) {
		t.Errorf("Component(commander) = %q, want %s prefix", a, want)
	}
}
