package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/rvagg/depsound/internal/fetch"
	"github.com/rvagg/depsound/internal/gopkg"
	"github.com/rvagg/depsound/internal/output"
)

// transitiveCmd resolves the change set a dependency bump drags into the
// whole tree by diffing two go.mod files. Post-1.17 pruning means go.mod's
// require block (incl. // indirect) IS the build-relevant resolved set, so
// no lockfile parser, solver or deps.dev is needed for Go, and the changed
// modules run through the same bulk router as a hand-supplied list.
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
	if len(pos) != 1 || pos[0] != "go" {
		return fmt.Errorf("transitive: want `depsound transitive go --old=<go.mod> --new=<go.mod>` (only go supported so far)")
	}
	if oldSrc == "" || newSrc == "" {
		return fmt.Errorf("transitive go needs --old and --new, each a go.mod path or URL")
	}

	oldMod, err := loadGoMod(oldSrc)
	if err != nil {
		return fmt.Errorf("--old: %w", err)
	}
	newMod, err := loadGoMod(newSrc)
	if err != nil {
		return fmt.Errorf("--new: %w", err)
	}

	res := diffRequireSets(gopkg.RequireSet(oldMod), gopkg.RequireSet(newMod))

	var items []bulkItem
	for _, c := range res.changed {
		items = append(items, bulkItem{spec: "go:" + c.Path, from: c.From, to: c.To})
	}
	fmt.Fprintf(os.Stderr, "depsound: transitive go: %d changed, %d added, %d removed; analysing changes\n",
		len(res.changed), len(res.added), len(res.removed))
	tr := output.TransitiveResult{
		Ecosystem:       "go",
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

type requireSetDiff struct {
	changed                        []output.ModuleRef
	added, removed                 []output.ModuleRef
	directChanged, indirectChanged int
}

// diffRequireSets computes the module-level change set between two resolved
// require sets: version-changes (analysable), additions (new to the tree)
// and removals. Output is sorted so runs are deterministic.
func diffRequireSets(old, niu map[string]gopkg.Require) requireSetDiff {
	var d requireSetDiff
	for path, n := range niu {
		o, existed := old[path]
		switch {
		case !existed:
			d.added = append(d.added, output.ModuleRef{Path: path, To: n.Version, Indirect: n.Indirect})
		case o.Version != n.Version:
			d.changed = append(d.changed, output.ModuleRef{Path: path, From: o.Version, To: n.Version, Indirect: n.Indirect})
			if n.Indirect {
				d.indirectChanged++
			} else {
				d.directChanged++
			}
		}
	}
	for path, o := range old {
		if _, ok := niu[path]; !ok {
			d.removed = append(d.removed, output.ModuleRef{Path: path, From: o.Version, Indirect: o.Indirect})
		}
	}
	byPath := func(s []output.ModuleRef) { sort.Slice(s, func(i, j int) bool { return s[i].Path < s[j].Path }) }
	byPath(d.changed)
	byPath(d.added)
	byPath(d.removed)
	return d
}

// loadGoMod reads a go.mod the agent points at, in any of three forms so it
// need not have the files locally: a local PATH, an https URL (github raw
// works; a github.com/blob URL is rewritten), or github:owner/repo@ref[:path]
// (the API contents endpoint, which also works for private repos with a
// GITHUB_TOKEN). go.mod defaults for the github: path.
func loadGoMod(src string) (*gopkg.Mod, error) {
	b, err := readSource(src)
	if err != nil {
		return nil, err
	}
	return gopkg.ParseBytes(src, b)
}

func readSource(src string) ([]byte, error) {
	ctx := context.Background()
	client := &http.Client{}
	switch {
	case strings.HasPrefix(src, "github:"):
		name, ref, path, err := parseGitHubSpec(strings.TrimPrefix(src, "github:"))
		if err != nil {
			return nil, err
		}
		return fetch.GitHubContents(ctx, client, name, ref, path)
	case strings.HasPrefix(src, "http://"), strings.HasPrefix(src, "https://"):
		return fetch.GetURL(ctx, client, src)
	default:
		return os.ReadFile(src)
	}
}

// parseGitHubSpec parses owner/repo@ref[:path] (path defaults to go.mod).
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
