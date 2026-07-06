// Package spec parses package specifiers of the form <ecosystem>:<name>.
package spec

import (
	"fmt"
	"strings"

	"golang.org/x/mod/semver"
)

type Ecosystem string

const (
	NPM    Ecosystem = "npm"
	Go     Ecosystem = "go"
	Crates Ecosystem = "crates"
	// GHA is a GitHub Actions dependency, owner/repo pinned to a ref. Its
	// artifact is the repo tree at the resolved commit (what actually runs).
	GHA Ecosystem = "gha"
)

type Spec struct {
	Eco  Ecosystem
	Name string
	// Sub is the action sub-path within a GHA repo (owner/repo/SUB@ref):
	// Name stays owner/repo (what we fetch), Sub scopes what you adopt.
	Sub string
}

func Parse(s string) (Spec, error) {
	eco, name, ok := strings.Cut(s, ":")
	if !ok || name == "" {
		return Spec{}, fmt.Errorf("spec %q: want <ecosystem>:<name>, e.g. npm:commander", s)
	}
	switch Ecosystem(eco) {
	case NPM, Go, Crates:
	case GHA:
		// owner/repo, optionally with a sub-path action: owner/repo/dir.
		// The repo (owner/repo) is what we fetch; the sub-path scopes what
		// you adopt (action.yml lives at sub/action.yml).
		owner, rest, ok := strings.Cut(name, "/")
		if !ok || owner == "" {
			return Spec{}, fmt.Errorf("spec %q: gha name must be owner/repo[/sub-path]", s)
		}
		repo, sub, _ := strings.Cut(rest, "/")
		if repo == "" {
			return Spec{}, fmt.Errorf("spec %q: gha name must be owner/repo[/sub-path]", s)
		}
		return Spec{Eco: GHA, Name: owner + "/" + repo, Sub: sub}, nil
	default:
		return Spec{}, fmt.Errorf("spec %q: unsupported ecosystem %q (supported: npm, go, crates, gha)", s, eco)
	}
	return Spec{Eco: Ecosystem(eco), Name: name}, nil
}

func (s Spec) String() string {
	if s.Sub != "" {
		return string(s.Eco) + ":" + s.Name + "/" + s.Sub
	}
	return string(s.Eco) + ":" + s.Name
}

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
