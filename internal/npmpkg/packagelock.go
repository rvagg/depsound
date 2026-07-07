package npmpkg

import (
	"encoding/json"
	"fmt"
	"strings"
)

// LockedDep is one resolved entry from a package-lock.json `packages` map:
// an exact installed version. A name can appear at several versions (npm
// dedup keeps copies at different node_modules paths), so entries are not
// collapsed by name; the caller diffs the full set.
type LockedDep struct {
	Name    string
	Version string
	Dev     bool
}

// ParsePackageLock parses package-lock.json v2/v3 (npm 7+): the flat
// `packages` map keyed by node_modules path. v1 (npm 5-6, nested
// `dependencies` only) is intentionally unsupported, that user is not this
// tool's audience. Registry deps only; workspace members/links and git/url
// deps (not fetchable by a registry version) are excluded and counted.
func ParsePackageLock(b []byte) (deps []LockedDep, nonRegistry int, err error) {
	var lock struct {
		Packages map[string]struct {
			Name     string `json:"name"` // set only for npm aliases
			Version  string `json:"version"`
			Resolved string `json:"resolved"`
			Link     bool   `json:"link"`
			Dev      bool   `json:"dev"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, 0, fmt.Errorf("package-lock.json: %w", err)
	}
	if lock.Packages == nil {
		return nil, 0, fmt.Errorf("package-lock.json has no `packages` map: lockfileVersion 1 (npm 5-6) is unsupported; use npm 7+ (lockfileVersion 2 or 3)")
	}
	const nm = "node_modules/"
	for path, e := range lock.Packages {
		idx := strings.LastIndex(path, nm)
		if idx < 0 || e.Link || e.Version == "" {
			continue // root, a workspace member/link, or no pinned version
		}
		// a resolved URL that is not a registry tarball is a git/url/tarball
		// dep, not fetchable by a registry version; an empty resolved is a
		// bundled/edge entry we keep
		if e.Resolved != "" && !strings.Contains(e.Resolved, "registry") {
			nonRegistry++
			continue
		}
		name := e.Name // the real package for an aliased install
		if name == "" {
			name = path[idx+len(nm):]
		}
		deps = append(deps, LockedDep{Name: name, Version: e.Version, Dev: e.Dev})
	}
	return deps, nonRegistry, nil
}
