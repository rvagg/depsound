// Package spec parses package specifiers of the form <ecosystem>:<name>.
package spec

import (
	"fmt"
	"strings"
)

type Ecosystem string

const (
	NPM Ecosystem = "npm"
)

type Spec struct {
	Eco  Ecosystem
	Name string
}

func Parse(s string) (Spec, error) {
	eco, name, ok := strings.Cut(s, ":")
	if !ok || name == "" {
		return Spec{}, fmt.Errorf("spec %q: want <ecosystem>:<name>, e.g. npm:commander", s)
	}
	switch Ecosystem(eco) {
	case NPM:
	default:
		return Spec{}, fmt.Errorf("spec %q: unsupported ecosystem %q (supported: npm)", s, eco)
	}
	return Spec{Eco: Ecosystem(eco), Name: name}, nil
}

func (s Spec) String() string { return string(s.Eco) + ":" + s.Name }

// NormalizeVersion adapts human version forms to what the ecosystem's
// registry expects: dependabot titles and git tags say v2.5.0, but npm
// versions never carry the leading v. (Go modules are the opposite and
// will ADD it here when that ecosystem lands.)
func NormalizeVersion(eco Ecosystem, v string) string {
	switch eco {
	case NPM:
		if len(v) >= 2 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
			return v[1:]
		}
	}
	return v
}
