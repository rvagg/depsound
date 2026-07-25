package cratepkg

import (
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// LockedCrate is one resolved [[package]] entry from a Cargo.lock: the exact
// version pinned. Cargo.lock is a FLAT list (no direct/indirect distinction,
// that lives in Cargo.toml), so transitive analysis over a Cargo.lock pair
// is the whole resolved set changing.
type LockedCrate struct {
	Name    string
	Version string
	// Registry is true for crates.io-sourced entries. Workspace members
	// (no source) and git/path deps are not fetchable from the registry, so
	// they are excluded from the analysable set and counted separately.
	Registry bool
}

type rawLock struct {
	Package []struct {
		Name         string   `toml:"name"`
		Version      string   `toml:"version"`
		Source       string   `toml:"source"`
		Dependencies []string `toml:"dependencies"`
	} `toml:"package"`
}

// CargoLockGraph reads the who-pulls-whom graph out of a Cargo.lock: ids are
// name@version, roots are the entries with no source (the workspace members
// being built). A dependency entry is "name" or "name version"; the bare form
// is unambiguous by construction, so it resolves to the single locked version
// of that name.
func CargoLockGraph(b []byte) (roots []string, edges map[string][]string, err error) {
	var raw rawLock
	if _, err := toml.Decode(string(b), &raw); err != nil {
		return nil, nil, err
	}
	byName := map[string][]string{} // name -> versions
	for _, p := range raw.Package {
		byName[p.Name] = append(byName[p.Name], p.Version)
	}
	edges = map[string][]string{}
	for _, p := range raw.Package {
		id := p.Name + "@" + p.Version
		if p.Source == "" {
			roots = append(roots, id)
		}
		for _, d := range p.Dependencies {
			name, version, ok := strings.Cut(d, " ")
			if !ok {
				vs := byName[name]
				if len(vs) != 1 {
					continue // ambiguous without a version: the lockfile would have named one
				}
				version = vs[0]
			} else if i := strings.IndexByte(version, ' '); i >= 0 {
				version = version[:i] // an older lock trails the source in parens
			}
			edges[id] = append(edges[id], name+"@"+version)
		}
	}
	sort.Strings(roots)
	return roots, edges, nil
}

// ParseCargoLock parses Cargo.lock content into its resolved crates. A
// crate can legitimately appear at more than one version (Cargo permits
// multiple semver-major versions in one tree), so entries are NOT collapsed
// by name; the caller diffs the full set.
func ParseCargoLock(b []byte) (registry []LockedCrate, nonRegistry int, err error) {
	var raw rawLock
	if _, err := toml.Decode(string(b), &raw); err != nil {
		return nil, 0, err
	}
	for _, p := range raw.Package {
		if strings.HasPrefix(p.Source, "registry+") {
			registry = append(registry, LockedCrate{Name: p.Name, Version: p.Version, Registry: true})
		} else {
			nonRegistry++ // workspace member, git or path dep: not on the registry
		}
	}
	return registry, nonRegistry, nil
}
