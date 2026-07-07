package npmpkg

import (
	"fmt"
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
