// Package spec parses package specifiers of the form <ecosystem>:<name>.
package spec

import (
	"fmt"
	"strings"

	"golang.org/x/mod/semver"
)

type Ecosystem string

const (
	NPM Ecosystem = "npm"
	Go  Ecosystem = "go"
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
	case NPM, Go:
	default:
		return Spec{}, fmt.Errorf("spec %q: unsupported ecosystem %q (supported: npm, go)", s, eco)
	}
	return Spec{Eco: Ecosystem(eco), Name: name}, nil
}

func (s Spec) String() string { return string(s.Eco) + ":" + s.Name }

// NormalizeVersion adapts human version forms to what the ecosystem's
// registry expects: dependabot titles and git tags say v2.5.0, but npm
// versions never carry the leading v, while Go module versions require
// it. Pseudo-versions pass through either way (they begin vX.Y.Z-).
// Go versions are validated as semver so a commit hash or branch name
// fails here with a clear message instead of a baffling proxy 404
// (worse when the hash starts with a digit and would get a v prefix).
func NormalizeVersion(eco Ecosystem, v string) (string, error) {
	switch eco {
	case NPM:
		if len(v) >= 2 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
			return v[1:], nil
		}
	case Go:
		if len(v) >= 1 && v[0] >= '0' && v[0] <= '9' {
			v = "v" + v
		}
		if !semver.IsValid(v) {
			return "", fmt.Errorf("go version %q is not semver: commit hashes and branch names are not supported, resolve to a version (or pseudo-version) first", v)
		}
	}
	return v, nil
}
