package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/rvagg/depsound/internal/cratepkg"
	"github.com/rvagg/depsound/internal/fetch"
	"github.com/rvagg/depsound/internal/gopkg"
	"github.com/rvagg/depsound/internal/npmpkg"
	"github.com/rvagg/depsound/internal/output"
)

// transitiveEcos maps an ecosystem to how its resolved set is read and the
// default lockfile name for a github: source. Go's resolved set is go.mod's
// require block (post-1.17 pruning); Rust's is Cargo.lock's flat package
// list. npm/pnpm (lockfile) land here too once their parser is wired.
var transitiveEcos = map[string]string{"go": "go.mod", "crates": "Cargo.lock", "npm": "package-lock.json"}

// transitiveCmd resolves the change set a bump drags into the WHOLE tree by
// diffing two resolved sets (a go.mod pair, a Cargo.lock pair). The changed
// deps run through the same bulk router as a hand-supplied list; the shared
// diff handles multiple versions of one name (npm/Cargo dedup) by pairing a
// lone removed+added as a bump.
func transitiveCmd(args []string) error {
	cacheDir, format := "", "stats"
	noOSV := false
	var oldSrc, newSrc string
	var pos []string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--cache-dir="):
			cacheDir = strings.TrimPrefix(a, "--cache-dir=")
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case strings.HasPrefix(a, "--old="):
			oldSrc = strings.TrimPrefix(a, "--old=")
		case strings.HasPrefix(a, "--new="):
			newSrc = strings.TrimPrefix(a, "--new=")
		case a == "--no-osv":
			noOSV = true
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("unknown flag %q", a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 {
		return fmt.Errorf("transitive: want `depsound transitive <go|crates> --old=<lockfile> --new=<lockfile>`")
	}
	eco := pos[0]
	lockName, ok := transitiveEcos[eco]
	if !ok {
		return fmt.Errorf("transitive: unsupported ecosystem %q (supported: go, crates, npm)", eco)
	}
	if oldSrc == "" || newSrc == "" {
		return fmt.Errorf("transitive %s needs --old and --new, each a %s (path, https URL, or github:owner/repo@ref[:path])", eco, lockName)
	}

	oldDeps, err := resolveLock(eco, oldSrc, lockName)
	if err != nil {
		return fmt.Errorf("--old: %w", err)
	}
	newDeps, err := resolveLock(eco, newSrc, lockName)
	if err != nil {
		return fmt.Errorf("--new: %w", err)
	}

	res := diffResolved(oldDeps, newDeps)
	var items []bulkItem
	for _, c := range res.changed {
		items = append(items, bulkItem{spec: eco + ":" + c.Path, from: c.From, to: c.To})
	}
	fmt.Fprintf(os.Stderr, "depsound: transitive %s: %d changed, %d added, %d removed; analysing changes\n",
		eco, len(res.changed), len(res.added), len(res.removed))
	tr := output.TransitiveResult{
		Ecosystem:       eco,
		Flat:            eco == "crates" || eco == "npm", // lockfile has no direct/indirect split
		Changed:         runBulk(cacheDir, items, noOSV),
		Added:           res.added,
		Removed:         res.removed,
		DirectChanged:   res.directChanged,
		IndirectChanged: res.indirectChanged,
	}

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(tr)
	}
	fmt.Print(output.Transitive(tr))
	return nil
}

// resolvedDep is one resolved dependency from a lockfile: name + exact
// version, and whether it is indirect/transitive (Go's // indirect; npm's
// dev/optional later). Ecosystem-neutral so one diff serves all lockfiles.
type resolvedDep struct {
	name, version string
	indirect      bool
}

// resolveLock reads a lockfile source and parses it into the resolved set.
func resolveLock(eco, src, lockName string) ([]resolvedDep, error) {
	b, err := readSource(src, lockName)
	if err != nil {
		return nil, err
	}
	switch eco {
	case "go":
		m, err := gopkg.ParseBytes(src, b)
		if err != nil {
			return nil, err
		}
		var out []resolvedDep
		for _, r := range gopkg.RequireSet(m) {
			out = append(out, resolvedDep{r.Path, r.Version, r.Indirect})
		}
		return out, nil
	case "crates":
		reg, _, err := cratepkg.ParseCargoLock(b)
		if err != nil {
			return nil, err
		}
		var out []resolvedDep
		for _, c := range reg {
			out = append(out, resolvedDep{c.Name, c.Version, false})
		}
		return out, nil
	case "npm":
		reg, _, err := npmpkg.ParsePackageLock(b)
		if err != nil {
			return nil, err
		}
		var out []resolvedDep
		for _, d := range reg {
			out = append(out, resolvedDep{d.Name, d.Version, false})
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported ecosystem %q", eco)
}

type requireSetDiff struct {
	changed                        []output.ModuleRef
	added, removed                 []output.ModuleRef
	directChanged, indirectChanged int
}

// diffResolved computes the module-level change set between two resolved
// sets. A name may carry MULTIPLE versions (Cargo/npm dedup), so it diffs
// per-name version SETS: a lone removed+added is a clean bump (analysable),
// otherwise the extra versions are listed as added/removed. Deterministic.
func diffResolved(old, niu []resolvedDep) requireSetDiff {
	oldV, newV := versionsByName(old), versionsByName(niu)
	names := map[string]bool{}
	for n := range oldV {
		names[n] = true
	}
	for n := range newV {
		names[n] = true
	}
	sortedNames := make([]string, 0, len(names))
	for n := range names {
		sortedNames = append(sortedNames, n)
	}
	sort.Strings(sortedNames)

	var d requireSetDiff
	for _, name := range sortedNames {
		added := missing(newV[name], oldV[name]) // versions in new, not old
		removed := missing(oldV[name], newV[name])
		switch {
		case len(added) == 0 && len(removed) == 0:
			// unchanged
		case len(added) == 1 && len(removed) == 1:
			dep := newV[name][added[0]]
			d.changed = append(d.changed, output.ModuleRef{Path: name, From: removed[0], To: added[0], Indirect: dep.indirect})
			if dep.indirect {
				d.indirectChanged++
			} else {
				d.directChanged++
			}
		default:
			for _, v := range added {
				d.added = append(d.added, output.ModuleRef{Path: name, To: v, Indirect: newV[name][v].indirect})
			}
			for _, v := range removed {
				d.removed = append(d.removed, output.ModuleRef{Path: name, From: v, Indirect: oldV[name][v].indirect})
			}
		}
	}
	return d
}

func versionsByName(deps []resolvedDep) map[string]map[string]resolvedDep {
	out := map[string]map[string]resolvedDep{}
	for _, d := range deps {
		if out[d.name] == nil {
			out[d.name] = map[string]resolvedDep{}
		}
		out[d.name][d.version] = d
	}
	return out
}

// missing returns the versions present in a but not b, sorted.
func missing(a, b map[string]resolvedDep) []string {
	var out []string
	for v := range a {
		if _, ok := b[v]; !ok {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func readSource(src, defaultFile string) ([]byte, error) {
	ctx := context.Background()
	client := &http.Client{}
	switch {
	case strings.HasPrefix(src, "github:"):
		name, ref, path, err := parseGitHubSpec(strings.TrimPrefix(src, "github:"))
		if err != nil {
			return nil, err
		}
		if path == "" {
			path = defaultFile
		}
		return fetch.GitHubContents(ctx, client, name, ref, path)
	case strings.HasPrefix(src, "http://"), strings.HasPrefix(src, "https://"):
		return fetch.GetURL(ctx, client, src)
	default:
		return os.ReadFile(src)
	}
}

// parseGitHubSpec parses owner/repo@ref[:path] (path defaulted by caller).
func parseGitHubSpec(s string) (name, ref, path string, err error) {
	name, rest, ok := strings.Cut(s, "@")
	if !ok || name == "" {
		return "", "", "", fmt.Errorf("github: spec %q: want owner/repo@ref[:path]", s)
	}
	ref, path, _ = strings.Cut(rest, ":")
	if ref == "" {
		return "", "", "", fmt.Errorf("github: spec %q: want owner/repo@ref[:path]", s)
	}
	return name, ref, path, nil
}
