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

	"github.com/rvagg/depsound/internal/gopkg"
)

// detectManifests maps an authoritative resolution file's base name to the
// lockfile KIND it parses as. Only files that carry the RESOLVED set belong
// here: go.mod (post-1.17 prune puts direct+indirect in it) and the lockfiles
// (package-lock.json / pnpm-lock.yaml / Cargo.lock, which carry transitive).
// Declaration files (package.json, Cargo.toml) are deliberately absent: their
// lockfile is authoritative and diffing it catches
// transitive bumps a manifest diff misses. A changed file whose base name is
// not here is skipped with a note, never silently.
var detectManifests = map[string]string{
	"go.mod":            "go",
	"package-lock.json": "npm",
	"pnpm-lock.yaml":    "pnpm",
	"Cargo.lock":        "crates",
}

// manifestKind classifies a changed file into a detector KIND, or (,false) to
// skip it. Lockfiles/go.mod match by base name (they live anywhere); GitHub
// Actions manifests match by LOCATION instead: a workflow under
// .github/workflows/, or a composite action's action.yml/action.yaml. Their
// pinned `uses:` refs are the resolved set the diff reads (the file IS the
// manifest), so gha rides the same detect flow as a lockfile.
func manifestKind(p string) (string, bool) {
	base := path.Base(p)
	if k, ok := detectManifests[base]; ok {
		return k, true
	}
	if isWorkflowPath(p) || base == "action.yml" || base == "action.yaml" {
		return "gha", true
	}
	return "", false
}

func isWorkflowPath(p string) bool {
	base := path.Base(p)
	return strings.HasSuffix(path.Dir(p), ".github/workflows") &&
		(strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"))
}

// detectEco resolves a detector KIND to its analysis ecosystem and github:
// default filename. gha is detect-only (no transitive-lockfile mode), so it is
// not in transitiveEcos; every other kind is.
func detectEco(kind string) transitiveEco {
	if kind == "gha" {
		return transitiveEco{analysis: "gha", lockName: ""}
	}
	return transitiveEcos[kind]
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
		for _, r := range res.Redirects {
			fmt.Printf("redirect %s:%s %s\n", r.Eco, r.Name, r.Target)
		}
		// anything detect saw but could not turn into an analysable change (a
		// manifest that failed to parse, an unsupported uses: kind) rides the
		// stream as an `unresolved` line (TAB-delimited: reason is free text),
		// which bulk turns into a failed row, so it is a loud coverage gap,
		// never an empty-list silence the caller reads as "no changes".
		for _, u := range res.Unresolved {
			fmt.Printf("unresolved\t%s\t%s\n", u.Path, strings.ReplaceAll(u.Reason, "\n", " "))
		}
		if len(res.Unresolved) > 0 {
			fmt.Fprintf(os.Stderr, "depsound: detect: %d change(s) could not be analysed (surfaced as coverage gaps in the report)\n", len(res.Unresolved))
		}
		if len(res.Added) > 0 {
			fmt.Fprintf(os.Stderr, "depsound: detect: %d new dependency(ies) in the list (census-shaped)\n", len(res.Added))
		}
		if len(res.Redirects) > 0 {
			fmt.Fprintf(os.Stderr, "depsound: detect: %d redirect(s) to a non-registry source\n", len(res.Redirects))
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

// detectRedirect is a dependency pointed at a non-registry source by a
// replace/patch/override introduced or changed in the PR: a fork, git URL, or
// local path. FACT-grade and needs no fetch; the redirect itself is the signal.
type detectRedirect struct {
	Eco    string   `json:"ecosystem"`
	Name   string   `json:"name"`   // the module being redirected
	Target string   `json:"target"` // where it now points
	Files  []string `json:"files"`
}

type detectResult struct {
	Changed   []detectChange   `json:"changed"`   // bumps (from and to)
	Added     []detectChange   `json:"added"`     // new deps (census-shaped)
	Redirects []detectRedirect `json:"redirects"` // non-registry source flags
	// Unresolved are manifests detect was asked to parse but could not (a read
	// or parse failure), kept separate from the benign Notes (an unwatched base
	// name) so the caller surfaces a real coverage gap instead of silently
	// reporting a partial set as if it were complete.
	Unresolved []detectUnresolved `json:"unresolved,omitempty"`
	Notes      []string           `json:"notes,omitempty"`
}

type detectUnresolved struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// detectChanges parses each pair's two versions, diffs them, and aggregates
// the deltas across all pairs deduped by the FULL (eco, name, from, to) tuple:
// the same dep at the same endpoints anywhere collapses to one change (merging
// provenance), the same dep at different endpoints stays distinct. Removals
// are dropped (a dep leaving is a compat note at most, never a review target).
func detectChanges(pairs []detectPair) detectResult {
	var res detectResult
	changedIdx, addedIdx, redirectIdx := map[string]int{}, map[string]int{}, map[string]int{}
	skipped := map[string]bool{}
	for _, p := range pairs {
		base := path.Base(p.path)
		kind, ok := manifestKind(p.path)
		if !ok {
			if !skipped[base] {
				skipped[base] = true
				res.Notes = append(res.Notes, fmt.Sprintf("%s: no detector for %q, skipped", p.path, base))
			}
			continue
		}
		te := detectEco(kind)
		oldDeps, err := resolveManifest(kind, p.old, te.lockName)
		if err != nil {
			res.Unresolved = append(res.Unresolved, detectUnresolved{p.path, fmt.Sprintf("parse old %s: %v", base, err)})
			continue
		}
		newDeps, err := resolveManifest(kind, p.new, te.lockName)
		if err != nil {
			res.Unresolved = append(res.Unresolved, detectUnresolved{p.path, fmt.Sprintf("parse new %s: %v", base, err)})
			continue
		}
		d := diffResolved(oldDeps, newDeps)
		for _, c := range d.changed {
			// a changed docker image or reusable workflow cannot be fetched or
			// analysed; it rides the unresolved stream so the change is a loud
			// coverage gap in the report, never a silent drop
			if kind == "gha" {
				if k := ghaUnsupportedKind(c.Path); k != "" {
					res.Unresolved = append(res.Unresolved, detectUnresolved{p.path,
						fmt.Sprintf("unsupported uses (%s): %s changed %s -> %s; not analysed, review the workflow diff", k, c.Path, c.From, c.To)})
					continue
				}
			}
			mergeDetect(&res.Changed, changedIdx, te.analysis, c.Path, c.From, c.To, c.Indirect, p.path)
		}
		for _, c := range d.added {
			if kind == "gha" {
				if k := ghaUnsupportedKind(c.Path); k != "" {
					res.Unresolved = append(res.Unresolved, detectUnresolved{p.path,
						fmt.Sprintf("unsupported uses (%s): %s added at %s; not analysed, review the workflow diff", k, c.Path, c.To)})
					continue
				}
			}
			mergeDetect(&res.Added, addedIdx, te.analysis, c.Path, "", c.To, c.Indirect, p.path)
		}
		// redirects: a replace/patch/override pointing a dependency off the
		// registry. go's replace directive is directly nameable; the lockfile
		// ecosystems' non-registry sets are a follow-on.
		if kind == "go" {
			for _, rd := range goRedirectDelta(p.old, p.new) {
				mergeRedirect(&res.Redirects, redirectIdx, te.analysis, rd, p.path)
			}
		}
	}
	sortDetect(res.Changed)
	sortDetect(res.Added)
	sortRedirects(res.Redirects)
	return res
}

// goRedirectDelta returns the replace directives added or retargeted between
// two go.mod versions. In the main module (a consumer's own go.mod, what
// detect inspects) a replace is live, so a new or changed one redirects that
// module off the registry. Keyed by the replaced module path; a parse failure
// yields nothing here (the version pass already notes it).
func goRedirectDelta(oldSrc, newSrc string) []detectRedirect {
	oldR, newR := goReplaces(oldSrc), goReplaces(newSrc)
	keys := make([]string, 0, len(newR))
	for k := range newR {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []detectRedirect
	for _, k := range keys {
		if oldR[k] == newR[k] {
			continue // unchanged replace: not introduced by this PR
		}
		name := k
		if i := strings.IndexByte(name, '@'); i >= 0 {
			name = name[:i] // drop a version-specific replace's @version
		}
		out = append(out, detectRedirect{Name: name, Target: newR[k]})
	}
	return out
}

func goReplaces(src string) map[string]string {
	if src == "" || src == "-" {
		return nil
	}
	b, err := readSource(src, "go.mod")
	if err != nil {
		return nil
	}
	m, err := gopkg.ParseBytes(src, b)
	if err != nil {
		return nil
	}
	return gopkg.ReplaceSet(m)
}

func mergeRedirect(dst *[]detectRedirect, idx map[string]int, eco string, rd detectRedirect, file string) {
	key := eco + "\x00" + rd.Name + "\x00" + rd.Target
	if i, ok := idx[key]; ok {
		(*dst)[i].Files = appendUnique((*dst)[i].Files, file)
		return
	}
	idx[key] = len(*dst)
	*dst = append(*dst, detectRedirect{Eco: eco, Name: rd.Name, Target: rd.Target, Files: []string{file}})
}

func sortRedirects(rs []detectRedirect) {
	for i := range rs {
		sort.Strings(rs[i].Files)
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Eco != rs[j].Eco {
			return rs[i].Eco < rs[j].Eco
		}
		if rs[i].Name != rs[j].Name {
			return rs[i].Name < rs[j].Name
		}
		return rs[i].Target < rs[j].Target
	})
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
