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
	"github.com/rvagg/depsound/internal/ghapkg"
	"github.com/rvagg/depsound/internal/gopkg"
	"github.com/rvagg/depsound/internal/npmpkg"
	"github.com/rvagg/depsound/internal/output"
)

// transitiveEco maps a lockfile KIND (the CLI positional) to the ecosystem
// its packages are analysed under and the default lockfile name for a
// github: source. Kind and analysis ecosystem usually match, except pnpm,
// which resolves npm packages, so a pnpm-lock.yaml is analysed on npm.
type transitiveEco struct {
	analysis string // spec ecosystem for fetch/analysis (npm/go/crates)
	lockName string
}

var transitiveEcos = map[string]transitiveEco{
	"go":     {"go", "go.mod"},
	"crates": {"crates", "Cargo.lock"},
	"npm":    {"npm", "package-lock.json"},
	"pnpm":   {"npm", "pnpm-lock.yaml"},
}

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
		return fmt.Errorf("transitive: want `depsound transitive <go|crates|npm|pnpm> --old=<lockfile> --new=<lockfile>`")
	}
	kind := pos[0]
	te, ok := transitiveEcos[kind]
	if !ok {
		return fmt.Errorf("transitive: unsupported lockfile kind %q (supported: go, crates, npm, pnpm)", kind)
	}
	if oldSrc == "" || newSrc == "" {
		return fmt.Errorf("transitive %s needs --old and --new, each a %s (path, https URL, or github:owner/repo@ref[:path])", kind, te.lockName)
	}

	oldDeps, err := resolveLock(kind, oldSrc, te.lockName)
	if err != nil {
		return fmt.Errorf("--old: %w", err)
	}
	newDeps, err := resolveLock(kind, newSrc, te.lockName)
	if err != nil {
		return fmt.Errorf("--new: %w", err)
	}

	res := diffResolved(oldDeps, newDeps)
	var items []bulkItem
	for _, c := range res.changed {
		items = append(items, bulkItem{spec: te.analysis + ":" + c.Path, from: c.From, to: c.To})
	}
	fmt.Fprintf(os.Stderr, "depsound: transitive %s: %d changed, %d added, %d removed; analysing changes\n",
		kind, len(res.changed), len(res.added), len(res.removed))
	tr := output.TransitiveResult{
		Ecosystem:       te.analysis,
		Kind:            kind,
		Flat:            te.analysis != "go",                      // only go.mod carries direct/indirect
		Changed:         runBulk(cacheDir, items, noOSV, true, 0), // versions resolved; provenance off (subtree too large to hammer deps.dev)
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

// resolveLock reads a lockfile source and parses it into the resolved set,
// dispatching on the lockfile KIND (go|crates|npm|pnpm).
func resolveLock(kind, src, lockName string) ([]resolvedDep, error) {
	b, err := readSource(src, lockName)
	if err != nil {
		return nil, err
	}
	switch kind {
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
		return lockedToResolved(reg), nil
	case "npm":
		reg, _, err := npmpkg.ParsePackageLock(b)
		if err != nil {
			return nil, err
		}
		return npmLockedToResolved(reg), nil
	case "pnpm":
		reg, _, err := npmpkg.ParsePnpmLock(b)
		if err != nil {
			return nil, err
		}
		return npmLockedToResolved(reg), nil
	case "npm-decl":
		// the declaration fallback: values are ranges, passed through for
		// bulk to resolve at review time. Dev deps count here, a repo's own
		// devDependencies install for its CI and dev machines.
		p, err := npmpkg.Parse(b)
		if err != nil {
			return nil, err
		}
		return declToResolved(p.Dev, p.Optional, p.Peer, p.Deps), nil
	case "crates-decl":
		c, err := cratepkg.Parse(b)
		if err != nil {
			return nil, err
		}
		return declToResolved(c.DevDeps, c.BuildDeps, c.Deps), nil
	case "gha":
		// a workflow file (or composite action.yml) IS the gha manifest: its
		// pinned `uses:` refs are the resolved set, so diffResolved yields the
		// action bumps just like a lockfile diff yields package bumps. Docker
		// images and reusable workflows are kept in the set (a change must
		// surface even though depsound cannot fetch them); local `./` actions
		// are the repo's own code, reviewed in its own PR diff.
		uses, err := ghapkg.WorkflowUses(b)
		if err != nil {
			return nil, err
		}
		var out []resolvedDep
		for _, u := range uses {
			switch u.Kind {
			case "action", "docker", "reusable":
				ref := u.Ref
				if ref == "" {
					ref = "?" // untagged docker image: implicit latest
				}
				out = append(out, resolvedDep{u.Identity, ref, false})
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported lockfile kind %q", kind)
}

// ghaUnsupportedKind labels a resolved gha dependency depsound cannot fetch
// and analyse, recognized by identity shape (both shapes are disjoint from
// owner/repo action identities). Empty for analysable actions.
func ghaUnsupportedKind(name string) string {
	switch {
	case strings.HasPrefix(name, "docker://"):
		return "docker image"
	case strings.Contains(name, "/.github/workflows/"):
		return "reusable workflow"
	}
	return ""
}

// declToResolved flattens declaration dep tables (name -> range) into the
// resolved-set shape, later maps winning a name collision (pass the primary
// runtime table last).
func declToResolved(tables ...map[string]string) []resolvedDep {
	merged := map[string]string{}
	for _, t := range tables {
		for name, rng := range t {
			merged[name] = rng
		}
	}
	out := make([]resolvedDep, 0, len(merged))
	for name, rng := range merged {
		out = append(out, resolvedDep{name, rng, false})
	}
	return out
}

func lockedToResolved(crates []cratepkg.LockedCrate) []resolvedDep {
	out := make([]resolvedDep, 0, len(crates))
	for _, c := range crates {
		out = append(out, resolvedDep{c.Name, c.Version, false})
	}
	return out
}

func npmLockedToResolved(deps []npmpkg.LockedDep) []resolvedDep {
	out := make([]resolvedDep, 0, len(deps))
	for _, d := range deps {
		out = append(out, resolvedDep{d.Name, d.Version, false})
	}
	return out
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
