package npmpkg

import (
	"encoding/json"
	"fmt"
	"sort"
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

// PackageLockGraph reads the who-pulls-whom edges out of a package-lock v2/v3:
// node "name@version" -> children it depends on, plus the root's direct set.
// Each entry's target resolves by npm's shadowing rule: the nearest ancestor
// node_modules that holds the name. Runtime `dependencies` plus optional, and
// at the root also devDependencies (your own dev tooling does install; a
// transitive package's dev deps never do, so they carry no edge).
func PackageLockGraph(b []byte) (roots []string, edges map[string][]string, err error) {
	var lock struct {
		Packages map[string]struct {
			Name         string            `json:"name"`
			Version      string            `json:"version"`
			Dependencies map[string]string `json:"dependencies"`
			Optional     map[string]string `json:"optionalDependencies"`
			Dev          map[string]string `json:"devDependencies"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, nil, fmt.Errorf("package-lock.json: %w", err)
	}
	if lock.Packages == nil {
		return nil, nil, fmt.Errorf("package-lock.json has no `packages` map (lockfileVersion 1 unsupported)")
	}

	// resolve a dependency name from a package path by walking ancestor
	// node_modules scopes, exactly npm's lookup order
	resolve := func(from, name string) string {
		prefix := from
		for {
			cand := "node_modules/" + name
			if prefix != "" {
				cand = prefix + "/node_modules/" + name
			}
			if _, ok := lock.Packages[cand]; ok {
				return cand
			}
			if prefix == "" {
				return ""
			}
			if i := strings.LastIndex(prefix, "/node_modules/"); i >= 0 {
				prefix = prefix[:i]
			} else {
				prefix = ""
			}
		}
	}
	id := func(path string) string {
		e := lock.Packages[path]
		name := e.Name
		if name == "" {
			if i := strings.LastIndex(path, "node_modules/"); i >= 0 {
				name = path[i+len("node_modules/"):]
			}
		}
		return name + "@" + e.Version
	}

	edges = map[string][]string{}
	for path, e := range lock.Packages {
		names := make([]string, 0, len(e.Dependencies)+len(e.Optional))
		for n := range e.Dependencies {
			names = append(names, n)
		}
		for n := range e.Optional {
			names = append(names, n)
		}
		if path == "" {
			for n := range e.Dev {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		var kids []string
		for _, n := range names {
			if target := resolve(path, n); target != "" {
				kids = append(kids, id(target))
			}
		}
		if path == "" {
			roots = kids
			continue
		}
		if e.Version != "" {
			edges[id(path)] = append(edges[id(path)], kids...)
		}
	}
	return roots, edges, nil
}
