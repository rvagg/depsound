package npmpkg

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParsePnpmLock parses pnpm-lock.yaml lockfileVersion 9.x (pnpm 9+) into its
// resolved packages. Only 9.x is supported: earlier formats (5.x/6.0) differ
// in key shape and structure, and a pnpm-9 user is the audience. In 9.x the
// `packages` map is keyed by a bare `name@version` (peer-resolved instances
// live in `snapshots`), so the keys ARE the flat resolved set. pnpm installs
// npm packages, so these are analysed on the npm registry.
func ParsePnpmLock(b []byte) (deps []LockedDep, nonRegistry int, err error) {
	var lock struct {
		LockfileVersion string `yaml:"lockfileVersion"`
		Packages        map[string]struct {
			Resolution struct {
				Integrity string `yaml:"integrity"`
				Tarball   string `yaml:"tarball"`
				Type      string `yaml:"type"`
			} `yaml:"resolution"`
		} `yaml:"packages"`
	}
	if err := yaml.Unmarshal(b, &lock); err != nil {
		return nil, 0, fmt.Errorf("pnpm-lock.yaml: %w", err)
	}
	if !strings.HasPrefix(lock.LockfileVersion, "9") {
		return nil, 0, fmt.Errorf("pnpm lockfileVersion %q unsupported; this build supports 9.x (pnpm 9+), upgrade pnpm or use a package-lock.json", lock.LockfileVersion)
	}
	if lock.Packages == nil {
		return nil, 0, fmt.Errorf("pnpm-lock.yaml has no `packages` map")
	}
	for key, p := range lock.Packages {
		// a peer suffix can trail the key (foo@1.2.3(react@18.0.0)); the
		// resolved version is before it
		if i := strings.IndexByte(key, '('); i >= 0 {
			key = key[:i]
		}
		at := strings.LastIndexByte(key, '@')
		if at <= 0 { // no version, or a bare @scope with no trailing version
			continue
		}
		name, version := key[:at], key[at+1:]
		// registry deps carry a semver version + integrity; git/tarball deps
		// have a url-ish version or a non-registry resolution, not fetchable
		if version == "" || version[0] < '0' || version[0] > '9' ||
			p.Resolution.Tarball != "" || p.Resolution.Type != "" {
			nonRegistry++
			continue
		}
		deps = append(deps, LockedDep{Name: name, Version: version})
	}
	return deps, nonRegistry, nil
}

// PnpmLockGraph reads the who-pulls-whom graph out of a pnpm-lock.yaml 9.x:
// `importers` gives the roots (each workspace package's own deps) and
// `snapshots` gives the edges, both keyed name@version. pnpm states edges
// explicitly, so no ancestor walk is needed; peer suffixes (`(react@18)`) are
// stripped, collapsing peer-resolved instances onto the one resolved version.
// Workspace links and non-registry entries are dropped: nothing to fetch.
func PnpmLockGraph(b []byte) (roots []string, edges map[string][]string, err error) {
	type dep struct {
		Version string `yaml:"version"`
	}
	var lock struct {
		Importers map[string]struct {
			Dependencies         map[string]dep `yaml:"dependencies"`
			DevDependencies      map[string]dep `yaml:"devDependencies"`
			OptionalDependencies map[string]dep `yaml:"optionalDependencies"`
		} `yaml:"importers"`
		Snapshots map[string]struct {
			Dependencies         map[string]string `yaml:"dependencies"`
			OptionalDependencies map[string]string `yaml:"optionalDependencies"`
		} `yaml:"snapshots"`
	}
	if err := yaml.Unmarshal(b, &lock); err != nil {
		return nil, nil, fmt.Errorf("pnpm-lock.yaml: %w", err)
	}
	seen := map[string]bool{}
	for _, imp := range lock.Importers {
		for _, table := range []map[string]dep{imp.Dependencies, imp.DevDependencies, imp.OptionalDependencies} {
			for name, d := range table {
				id, ok := pnpmID(name, d.Version)
				if ok && !seen[id] {
					seen[id] = true
					roots = append(roots, id)
				}
			}
		}
	}
	sort.Strings(roots)
	edges = map[string][]string{}
	for key, snap := range lock.Snapshots {
		from := pnpmKey(key)
		for _, table := range []map[string]string{snap.Dependencies, snap.OptionalDependencies} {
			for name, version := range table {
				if id, ok := pnpmID(name, version); ok {
					edges[from] = append(edges[from], id)
				}
			}
		}
		sort.Strings(edges[from])
	}
	return roots, edges, nil
}

// pnpmID builds a name@version id, rejecting what is not a registry version
// (link:/file:/workspace: entries, and git refs). An aliased entry names its
// real package in the value (`cbw-sdk: '@coinbase/wallet-sdk@3.9.3'`), so the
// value wins over the local name; an id keyed by the alias would orphan the
// whole subtree under it.
func pnpmID(name, version string) (string, bool) {
	version = pnpmKey(strings.TrimPrefix(version, "npm:"))
	if at := strings.LastIndexByte(version, '@'); at > 0 {
		name, version = version[:at], version[at+1:]
	}
	if version == "" || version[0] < '0' || version[0] > '9' {
		return "", false
	}
	return name + "@" + version, true
}

// pnpmKey drops the peer-resolution suffix a key or version can carry, so
// every instance of a package collapses onto its resolved version.
func pnpmKey(s string) string {
	if i := strings.IndexByte(s, '('); i >= 0 {
		return s[:i]
	}
	return s
}

// ParseWorkspaceCatalogs reads pnpm-workspace.yaml's catalog tables: the
// default `catalog:` map plus every named catalog under `catalogs:`. pnpm
// centralizes dependency ranges there (package.json entries say "catalog:"),
// so a bump can live in this file alone, touching no other manifest. Returns
// name -> range with named-catalog entries flattened in (a name colliding
// across catalogs keeps the default catalog's value).
func ParseWorkspaceCatalogs(b []byte) (map[string]string, error) {
	var ws struct {
		Catalog  map[string]string            `yaml:"catalog"`
		Catalogs map[string]map[string]string `yaml:"catalogs"`
	}
	if err := yaml.Unmarshal(b, &ws); err != nil {
		return nil, fmt.Errorf("pnpm-workspace.yaml: %w", err)
	}
	out := map[string]string{}
	for _, named := range ws.Catalogs {
		for name, rng := range named {
			out[name] = rng
		}
	}
	for name, rng := range ws.Catalog {
		out[name] = rng
	}
	return out, nil
}
