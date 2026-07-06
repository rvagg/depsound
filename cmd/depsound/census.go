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
	"github.com/rvagg/depsound/internal/extract"
	"github.com/rvagg/depsound/internal/fetch"
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
	cacheDir, format := "", "stats"
	noOSV := false
	var cooldown time.Duration
	var pos []string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--cache-dir="):
			cacheDir = strings.TrimPrefix(a, "--cache-dir=")
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case strings.HasPrefix(a, "--cooldown="):
			d, err := parseCooldown(strings.TrimPrefix(a, "--cooldown="))
			if err != nil {
				return err
			}
			cooldown = d
		case a == "--no-osv":
			noOSV = true
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("unknown flag %q", a)
		default:
			pos = append(pos, a)
		}
	}
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
	c.Coverage, c.NextActions = output.CensusGuide(c)

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(c)
	}
	fmt.Print(output.CensusText(c))
	return nil
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

	ext := map[spec.Ecosystem]string{spec.NPM: ".tgz", spec.Go: ".zip", spec.Crates: ".crate"}[sp.Eco]
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
		case spec.NPM, spec.Crates:
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
	cen.Tree = tree
	cen.ByClass, cen.Bytes, cen.Files = classifyTree(tree)
	if err := censusManifest(sp.Eco, tree, cen); err != nil {
		return nil, err
	}
	return cen, nil
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
// the census equivalent of the diff's byClass, computed without a diff.
func classifyTree(root string) (agg []stats.ClassAgg, total int64, files int) {
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
		return nil
	})
	for _, a := range byClass {
		agg = append(agg, *a)
	}
	sortClassAgg(agg)
	return agg, total, files
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
