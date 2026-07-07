package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rvagg/depsound/internal/cache"
	"github.com/rvagg/depsound/internal/classify"
	"github.com/rvagg/depsound/internal/cratepkg"
	"github.com/rvagg/depsound/internal/depsdev"
	"github.com/rvagg/depsound/internal/extract"
	"github.com/rvagg/depsound/internal/fetch"
	"github.com/rvagg/depsound/internal/ghapkg"
	"github.com/rvagg/depsound/internal/gopkg"
	"github.com/rvagg/depsound/internal/npmpkg"
	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/output"
	"github.com/rvagg/depsound/internal/spec"
	"github.com/rvagg/depsound/internal/stats"
)

// censusCmd vets a SINGLE version in absolute terms: "what am I signing up
// for if I adopt this". No diff; from=none. The vet-a-virgin-dep mode.
func censusCmd(args []string) error {
	cacheDir, format, against := "", "stats", ""
	noOSV, transitive := false, false
	var cooldown time.Duration
	var pos []string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--cache-dir="):
			cacheDir = strings.TrimPrefix(a, "--cache-dir=")
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case strings.HasPrefix(a, "--against="):
			against = strings.TrimPrefix(a, "--against=")
		case strings.HasPrefix(a, "--cooldown="):
			d, err := parseCooldown(strings.TrimPrefix(a, "--cooldown="))
			if err != nil {
				return err
			}
			cooldown = d
		case a == "--no-osv":
			noOSV = true
		case a == "--transitive":
			transitive = true
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("unknown flag %q", a)
		default:
			pos = append(pos, a)
		}
	}
	transitive = transitive || against != "" // --against implies --transitive
	// version optional: default to latest, because agents guess versions
	// from stale weights; the tool resolving (and REPORTING) it is better.
	if len(pos) == 1 {
		pos = append(pos, "latest")
	}
	if len(pos) != 2 {
		return fmt.Errorf("census: want <ecosystem>:<name> [version]  (version defaults to latest)")
	}

	c, err := buildCensus(cacheDir, pos[0], pos[1], cooldown)
	if err != nil {
		return err
	}

	if !noOSV {
		c.Vulns, c.OSVFetchedAt, c.OSVQueried = osv.Present(context.Background(), &http.Client{},
			censusCacheRoot(cacheDir), c.Ecosystem, c.Name, c.Version)
	}
	if transitive {
		if err := censusResolveSubtree(c); err != nil {
			fmt.Fprintf(os.Stderr, "depsound: transitive footprint unavailable: %v\n", err)
		} else if against != "" {
			if err := censusAnnotateAgainst(c, against); err != nil {
				fmt.Fprintf(os.Stderr, "depsound: --against ignored: %v\n", err)
			}
		}
	}
	c.Coverage, c.NextActions = output.CensusGuide(c)

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(c)
	}
	fmt.Print(output.CensusText(c))
	return nil
}

// censusResolveSubtree resolves the FULL transitive footprint via deps.dev
// (the no-lockfile adopt-a-dep case). Populated non-nil on success (even for
// a zero-dep package) so the report distinguishes "resolved to none" from
// "not requested".
func censusResolveSubtree(c *output.Census) error {
	system, ok := depsdev.System(c.Ecosystem)
	if !ok {
		return fmt.Errorf("deps.dev has no resolved graph for %s; go.mod IS the resolved set for go (use depsound transitive go)", c.Ecosystem)
	}
	nodes, err := depsdev.Dependencies(context.Background(), &http.Client{}, system, c.Name, c.Version)
	if err != nil {
		return err
	}
	c.Subtree = []output.SubtreeDep{}
	for _, n := range nodes {
		c.Subtree = append(c.Subtree, output.SubtreeDep{Name: n.Name, Version: n.Version, Relation: n.Relation})
		if n.Relation == "DIRECT" {
			c.SubtreeDirect++
		} else {
			c.SubtreeIndirect++
		}
	}
	return nil
}

// censusAnnotateAgainst tags each resolved subtree dep against an existing
// tree (a lockfile the user points at): have (same version) / conflict
// (present at a different version) / new (absent), so the footprint reads as
// MARGINAL. deps.dev resolved in isolation, so this is an upper bound.
func censusAnnotateAgainst(c *output.Census, src string) error {
	have, err := parseAgainstTree(c.Ecosystem, src)
	if err != nil {
		return err
	}
	c.Against = true
	for i := range c.Subtree {
		d := &c.Subtree[i]
		versions, nameThere := have[d.Name]
		switch {
		case nameThere && versions[d.Version]:
			d.Status = "have"
			c.SubtreeHave++
		case nameThere:
			d.Status = "conflict"
			c.SubtreeConflict++
		default:
			d.Status = "new"
			c.SubtreeNew++
		}
	}
	return nil
}

// parseAgainstTree reads the user's current lockfile into a name -> versions
// set. For npm it sniffs package-lock.json (JSON) vs pnpm-lock.yaml (YAML).
func parseAgainstTree(eco, src string) (map[string]map[string]bool, error) {
	b, err := readSource(src, "")
	if err != nil {
		return nil, err
	}
	var deps []resolvedDep
	switch eco {
	case "npm":
		if t := bytes.TrimSpace(b); len(t) > 0 && t[0] == '{' {
			reg, _, e := npmpkg.ParsePackageLock(b)
			if e != nil {
				return nil, e
			}
			deps = npmLockedToResolved(reg)
		} else {
			reg, _, e := npmpkg.ParsePnpmLock(b)
			if e != nil {
				return nil, e
			}
			deps = npmLockedToResolved(reg)
		}
	case "crates":
		reg, _, e := cratepkg.ParseCargoLock(b)
		if e != nil {
			return nil, e
		}
		deps = lockedToResolved(reg)
	default:
		return nil, fmt.Errorf("--against not supported for %s", eco)
	}
	set := map[string]map[string]bool{}
	for _, d := range deps {
		if set[d.name] == nil {
			set[d.name] = map[string]bool{}
		}
		set[d.name][d.version] = true
	}
	return set, nil
}

func censusCacheRoot(cacheDir string) string {
	c, err := cache.Open(cacheDir)
	if err != nil {
		return ""
	}
	return c.Root
}

// buildCensus resolves the version (latest/cooldown), fetches and extracts
// one version into a PERSISTED tree (so an agent can grep it, like a diff
// workspace), and computes its absolute signals. OSV is merged by the
// caller.
func buildCensus(cacheDir, specStr, versionReq string, cooldown time.Duration) (*output.Census, error) {
	sp, err := spec.Parse(specStr)
	if err != nil {
		return nil, err
	}
	if sp.Eco == spec.GHA && (versionReq == "" || versionReq == "latest") {
		return nil, fmt.Errorf("gha census needs a ref (no 'latest'): depsound gha:owner/repo[/sub] <tag|branch|sha>")
	}
	c, err := cache.Open(cacheDir)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client := &http.Client{}

	res, err := fetch.ResolveVersion(ctx, client, string(sp.Eco), sp.Name, versionReq, cooldown)
	if err != nil {
		return nil, err
	}
	v, err := spec.NormalizeVersion(sp.Eco, res.Version)
	if err != nil {
		return nil, err
	}
	cen := &output.Census{Ecosystem: string(sp.Eco), Name: sp.Name, Version: v}
	if versionReq == "" || versionReq == "latest" {
		cen.Resolved = "latest -> " + v
		if !res.Published.IsZero() {
			cen.Resolved += " (published " + res.Published.UTC().Format("2006-01-02") + ")"
		}
		if res.Note != "" {
			cen.Resolved += "; " + res.Note
		}
	}

	ext := map[spec.Ecosystem]string{spec.NPM: ".tgz", spec.Go: ".zip", spec.Crates: ".crate", spec.GHA: ".tar.gz"}[sp.Eco]
	art := c.ArtifactPath(string(sp.Eco), sp.Name, v, ext)
	if _, err := os.Stat(art); err != nil {
		fmt.Fprintf(os.Stderr, "depsound: %s %s: fetching\n", sp, v)
	}
	switch sp.Eco {
	case spec.NPM:
		err = fetch.NPM(ctx, client, sp.Name, v, art)
	case spec.Go:
		err = fetch.GoModule(ctx, client, sp.Name, v, art)
	case spec.Crates:
		err = fetch.Crate(ctx, client, sp.Name, v, art)
	case spec.GHA:
		err = fetch.GHA(ctx, client, sp.Name, v, art)
	}
	if err != nil {
		return nil, err
	}

	// persist the tree so the agent can search it; re-extract only if the
	// cached tree is missing (the artifact is immutable)
	tree := c.CensusPath(string(sp.Eco), sp.Name, v)
	if _, err := os.Stat(tree); err != nil {
		tmp := tree + ".tmp"
		os.RemoveAll(tmp)
		switch sp.Eco {
		case spec.NPM, spec.Crates, spec.GHA:
			_, err = extract.TarGz(art, tmp, extract.DefaultLimits)
		case spec.Go:
			_, err = extract.Zip(art, tmp, sp.Name+"@"+v, extract.DefaultLimits)
		}
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(tree), 0o755); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, tree); err != nil && !exists(tree) {
			return nil, err
		}
	}

	// a GHA sub-path action is scoped to what you adopt (owner/repo/SUB),
	// not the whole repo; census the sub-tree and note the scoping.
	scoped := tree
	if sp.Sub != "" {
		scoped = filepath.Join(tree, sp.Sub)
		if !exists(scoped) {
			return nil, fmt.Errorf("gha sub-path %q not present at %s@%s; check the path", sp.Sub, sp.Name, v)
		}
		cen.Name = sp.Name + "/" + sp.Sub
	}
	cen.Tree = scoped
	cen.ByClass, cen.Bytes, cen.Files, cen.BigExcluded, cen.BigExcludedBytes = classifyTree(scoped)
	if sp.Eco == spec.GHA {
		if err := censusGHA(cen, scoped, art, v, sp.Sub); err != nil {
			return nil, err
		}
	} else if err := censusManifest(sp.Eco, tree, cen); err != nil {
		return nil, err
	}
	return cen, nil
}

// censusGHA fills a GHA census: the pin (sha/tag/branch, from the sidecar),
// the action.yml execution model (present form), and the sub-path caveat.
func censusGHA(cen *output.Census, scoped, art, ref, sub string) error {
	m := fetch.ReadMeta(art)
	sha, kind := "", ""
	if m != nil {
		sha = strings.TrimPrefix(m.Digest, "git-")
		kind = m.RefKind
	}
	cen.Resolved = fmt.Sprintf("%s (%s) -> %s", ref, orUnknown(kind), sha)
	switch kind {
	case "sha":
		cen.Notes = append(cen.Notes, "SHA pin (immutable, good practice)")
	case "branch":
		cen.Notes = append(cen.Notes, fmt.Sprintf("WARNING BRANCH pin %q is UNPINNED: a branch moves on EVERY push, so adopters run whatever is there at run time (worst practice). Pin a tag or, better, a SHA", ref))
	default:
		cen.Notes = append(cen.Notes, fmt.Sprintf("WARNING TAG pin %q is MUTABLE (re-pointable, the tj-actions vector); prefer a SHA pin", ref))
	}
	if sub != "" {
		cen.Notes = append(cen.Notes, fmt.Sprintf("scoped to sub-path action %q; it may reference repo-level code outside it (not shown)", sub))
	}
	a, err := ghapkg.Load(scoped)
	if err != nil {
		return err
	}
	cen.GHAUsing = a.Using
	cen.GHAExec = ghapkg.ExecPresent(a)
	cen.GHANested = a.Uses
	cen.GHACaps = ghapkg.Capabilities(scoped)
	cen.Notes = append(cen.Notes, a.Warnings...)
	return nil
}

func orUnknown(s string) string {
	if s == "" {
		return "ref"
	}
	return s
}

// parseCooldown accepts "5", "5d", or a Go duration like "120h".
func parseCooldown(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	if n, err := strconv.Atoi(strings.TrimSuffix(s, "d")); err == nil {
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("--cooldown: want days (e.g. 5 or 5d) or a duration (120h)")
	}
	return d, nil
}

// censusManifest fills the absolute execution surface and direct deps from
// the version's manifest.
func censusManifest(eco spec.Ecosystem, tree string, cen *output.Census) error {
	switch eco {
	case spec.NPM:
		p, err := npmpkg.Load(tree)
		if err != nil {
			return err
		}
		cen.Lifecycle = npmpkg.LifecyclePresent(p)
		cen.Deps = npmpkg.DepsPresent(p)
		cen.Gyp = exists(filepath.Join(tree, "binding.gyp"))
		cen.Notes = append(cen.Notes, p.Warnings...)
	case spec.Go:
		m, err := gopkg.Load(tree)
		if err != nil {
			return err
		}
		cen.Cgo = gopkg.ScanCgo(tree)
		cen.Deps = gopkg.RequirePresent(m)
		cen.Notes = append(cen.Notes, m.Warnings...)
	case spec.Crates:
		cr, err := cratepkg.Load(tree)
		if err != nil {
			return err
		}
		cen.BuildRS = cr.HasBuildRS()
		cen.ProcMacro = cr.ProcMacro
		cen.Deps = cratepkg.DepsPresent(cr)
		cen.Notes = append(cen.Notes, cr.Warnings...)
	}
	return nil
}

// classifyTree walks a single extracted tree and buckets files by class:
// the census equivalent of the diff's byClass, computed without a diff. It
// also names the biggest EXCLUDED (generated/binary) file by size, so the
// unreviewed majority a census often carries cannot hide a payload
// anonymously (a package like hono is ~99% dist/).
func classifyTree(root string) (agg []stats.ClassAgg, total int64, files int, bigExcl string, bigExclBytes int64) {
	byClass := map[string]*stats.ClassAgg{}
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		head, isBin := readHead(p)
		res := classify.File(filepath.ToSlash(rel), head, isBin)
		a := byClass[string(res.Class)]
		if a == nil {
			a = &stats.ClassAgg{Class: string(res.Class)}
			byClass[string(res.Class)] = a
		}
		a.Files++
		total += info.Size()
		files++
		if (res.Class == classify.Generated || isBin) && info.Size() > bigExclBytes {
			bigExcl = filepath.ToSlash(rel)
			bigExclBytes = info.Size()
		}
		return nil
	})
	for _, a := range byClass {
		agg = append(agg, *a)
	}
	sortClassAgg(agg)
	return agg, total, files, bigExcl, bigExclBytes
}

// readHead reads the first 4KB and flags binary via a NUL byte (no diff to
// tell us, so we detect it as git would).
func readHead(path string) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	buf = buf[:n]
	return buf, bytes.IndexByte(buf, 0) >= 0
}

func sortClassAgg(a []stats.ClassAgg) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j].Files > a[j-1].Files; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
