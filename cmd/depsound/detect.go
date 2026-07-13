package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
)

// detectManifests maps an authoritative resolution file's base name to the
// lockfile KIND it parses as. Only files that carry the RESOLVED set belong
// here: go.mod (post-1.17 prune puts direct+indirect in it) and the lockfiles
// (package-lock.json / pnpm-lock.yaml / Cargo.lock, which carry transitive).
// Declaration files (package.json, Cargo.toml) are deliberately absent: their
// lockfile is the ground truth and diffing it is authoritative and catches
// transitive bumps a manifest diff misses. A changed file whose base name is
// not here is skipped with a note, never silently.
var detectManifests = map[string]string{
	"go.mod":            "go",
	"package-lock.json": "npm",
	"pnpm-lock.yaml":    "pnpm",
	"Cargo.lock":        "crates",
}

// detectCmd reports the dependency changes a PR makes, by parsing the two
// full versions of each changed manifest and diffing the resolved sets. It is
// transitive fanned out over the changed-manifest set: the git diff only says
// WHICH files to parse (the caller supplies it), the change set comes from the
// parse, never from diff text (a lockfile's hunks reorder and lie). Pure by
// design, depsound never touches the repo; the caller (the Action) does the
// git and hands over (path, old, new) triples.
//
// Input is one triple per line on stdin or --file=, tab-separated:
//
//	<path>\t<old-source>\t<new-source>
//
// old/new are sources readSource understands (a path, https URL, or
// github:owner/repo@ref[:path]); "-" or "" means an absent side (an added or
// removed manifest), which reads as the empty set. path names the manifest
// (its base name selects the parser and it is the provenance label).
func detectCmd(args []string) error {
	format, inputFile := "lines", ""
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case strings.HasPrefix(a, "--file="):
			inputFile = strings.TrimPrefix(a, "--file=")
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("unknown flag %q", a)
		default:
			return fmt.Errorf("detect takes no positional args; feed `path<TAB>old<TAB>new` lines on stdin or --file=")
		}
	}

	pairs, err := readDetectPairs(inputFile)
	if err != nil {
		return err
	}
	res := detectChanges(pairs)

	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	case "lines":
		// bumps as three-field lines, new deps as two-field (census) lines;
		// bulk consumes both, so a sneaked-in dependency rides the same stream
		// into the report instead of vanishing.
		for _, c := range res.Changed {
			fmt.Printf("%s:%s %s %s\n", c.Eco, c.Name, c.From, c.To)
		}
		for _, c := range res.Added {
			fmt.Printf("%s:%s %s\n", c.Eco, c.Name, c.To)
		}
		if len(res.Added) > 0 {
			fmt.Fprintf(os.Stderr, "depsound: detect: %d new dependency(ies) in the list (census-shaped)\n", len(res.Added))
		}
		for _, n := range res.Notes {
			fmt.Fprintf(os.Stderr, "depsound: detect: note: %s\n", n)
		}
		return nil
	default:
		return fmt.Errorf("detect: unknown --format %q (want lines or json)", format)
	}
}

type detectPair struct {
	path, old, new string
}

// detectChange is one dependency change aggregated across every manifest that
// carried it. Files is the provenance: which manifests moved this dep, so a
// monorepo review reads "x/y 1.2->1.4 in go.mod, cmd/go.mod".
type detectChange struct {
	Eco      string   `json:"ecosystem"`
	Name     string   `json:"name"`
	From     string   `json:"from,omitempty"`
	To       string   `json:"to"`
	Indirect bool     `json:"indirect,omitempty"`
	Files    []string `json:"files"`
}

type detectResult struct {
	Changed []detectChange `json:"changed"` // bumps (from and to)
	Added   []detectChange `json:"added"`   // new deps (census-shaped)
	Notes   []string       `json:"notes,omitempty"`
}

// detectChanges parses each pair's two versions, diffs them, and aggregates
// the deltas across all pairs deduped by the FULL (eco, name, from, to) tuple:
// the same dep at the same endpoints anywhere collapses to one change (merging
// provenance), the same dep at different endpoints stays distinct. Removals
// are dropped (a dep leaving is a compat note at most, never a review target).
func detectChanges(pairs []detectPair) detectResult {
	var res detectResult
	changedIdx, addedIdx := map[string]int{}, map[string]int{}
	skipped := map[string]bool{}
	for _, p := range pairs {
		base := path.Base(p.path)
		kind, ok := detectManifests[base]
		if !ok {
			if !skipped[base] {
				skipped[base] = true
				res.Notes = append(res.Notes, fmt.Sprintf("%s: no detector for %q, skipped", p.path, base))
			}
			continue
		}
		te := transitiveEcos[kind]
		oldDeps, err := resolveManifest(kind, p.old, te.lockName)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("%s (old): %v", p.path, err))
			continue
		}
		newDeps, err := resolveManifest(kind, p.new, te.lockName)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("%s (new): %v", p.path, err))
			continue
		}
		d := diffResolved(oldDeps, newDeps)
		for _, c := range d.changed {
			mergeDetect(&res.Changed, changedIdx, te.analysis, c.Path, c.From, c.To, c.Indirect, p.path)
		}
		for _, c := range d.added {
			mergeDetect(&res.Added, addedIdx, te.analysis, c.Path, "", c.To, c.Indirect, p.path)
		}
	}
	sortDetect(res.Changed)
	sortDetect(res.Added)
	return res
}

// resolveManifest reads and parses one side of a pair. An absent side ("-" or
// empty) is the empty set, so an added manifest yields all-added and a removed
// one yields all-removed (then dropped) with no special-casing upstream.
func resolveManifest(kind, src, lockName string) ([]resolvedDep, error) {
	if src == "" || src == "-" {
		return nil, nil
	}
	return resolveLock(kind, src, lockName)
}

func mergeDetect(dst *[]detectChange, idx map[string]int, eco, name, from, to string, indirect bool, file string) {
	key := eco + "\x00" + name + "\x00" + from + "\x00" + to
	if i, ok := idx[key]; ok {
		(*dst)[i].Files = appendUnique((*dst)[i].Files, file)
		return
	}
	idx[key] = len(*dst)
	*dst = append(*dst, detectChange{Eco: eco, Name: name, From: from, To: to, Indirect: indirect, Files: []string{file}})
}

func appendUnique(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

func sortDetect(cs []detectChange) {
	for i := range cs {
		sort.Strings(cs[i].Files)
	}
	sort.Slice(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if a.Eco != b.Eco {
			return a.Eco < b.Eco
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
}

func readDetectPairs(inputFile string) ([]detectPair, error) {
	var r io.Reader = os.Stdin
	if inputFile != "" {
		f, err := os.Open(inputFile)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	var pairs []detectPair
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			return nil, fmt.Errorf("detect line %q: want path<TAB>old<TAB>new (3 tab-separated fields)", line)
		}
		pairs = append(pairs, detectPair{path: f[0], old: f[1], new: f[2]})
	}
	return pairs, sc.Err()
}
