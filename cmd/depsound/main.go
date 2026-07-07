// depsound sounds the depths of a dependency change: it fetches published
// artifacts, diffs them, resolves what a bump drags in, and lays the
// evidence out for an agent to inspect. A gateway to deeper review, not a
// verdict, the tool gathers and organises; the judgement is the agent's.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/rvagg/depsound/internal/cache"
	"github.com/rvagg/depsound/internal/cratepkg"
	"github.com/rvagg/depsound/internal/extract"
	"github.com/rvagg/depsound/internal/fetch"
	"github.com/rvagg/depsound/internal/ghapkg"
	"github.com/rvagg/depsound/internal/gitdiff"
	"github.com/rvagg/depsound/internal/gopkg"
	"github.com/rvagg/depsound/internal/npmpkg"
	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/output"
	"github.com/rvagg/depsound/internal/spec"
	"github.com/rvagg/depsound/internal/stats"
	"github.com/rvagg/depsound/internal/surface"
	"github.com/rvagg/depsound/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "depsound:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	// subcommands are the non-spec leading words; a spec always carries a
	// colon (npm:foo), so anything else in first position is a command
	if len(args) > 0 {
		switch args[0] {
		case "-h", "--help", "help":
			return helpCmd(args[1:])
		case "guide":
			return guideCmd(args[1:])
		case "-v", "--version", "version":
			fmt.Printf("depsound %s (stats schema %d)\n", version.Version, stats.SchemaVersion)
			return nil
		case "surface":
			return surfaceCmd(args[1:])
		case "show":
			return showCmd(args[1:])
		case "bulk":
			return bulkCmd(args[1:])
		case "census":
			return censusCmd(args[1:])
		case "transitive":
			return transitiveCmd(args[1:])
		}
	}
	// spec alone or spec+version (1-2 positionals) is a census; spec+from+to
	// (3) is a diff. The tool is a "vet", so a lone spec/version means "what
	// am I signing up for", version defaulting to latest.
	if n := positionalCount(args); n == 1 || n == 2 {
		return censusCmd(args)
	}
	return diffCmd(args)
}

// positionalCount counts non-flag arguments.
func positionalCount(args []string) int {
	n := 0
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			n++
		}
	}
	return n
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// resolved holds a materialized workspace and its parsed spec.
type resolved struct {
	ws        string
	cacheRoot string
	sp        spec.Spec
	st        *stats.Stats
	idx       *surface.Index
}

// commonArgs parses the shared "<spec> <from> <to>" tail plus --cache-dir,
// materializes the workspace, and returns it. extraFlags handles
// command-specific flags, called per unrecognized --flag.
func resolveWorkspace(args []string, extraFlags func(string) (bool, error)) (*resolved, []string, error) {
	cacheDir := ""
	var pos []string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--cache-dir="):
			cacheDir = strings.TrimPrefix(a, "--cache-dir=")
		case strings.HasPrefix(a, "-"):
			if extraFlags != nil {
				handled, err := extraFlags(a)
				if err != nil {
					return nil, nil, err
				}
				if handled {
					continue
				}
			}
			return nil, nil, fmt.Errorf("unknown flag %q (run `depsound help`)", a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) < 3 {
		return nil, nil, fmt.Errorf("want <ecosystem>:<name> <from> <to> (run `depsound help`)")
	}

	r, err := analyze(cacheDir, pos[0], pos[1], pos[2])
	if err != nil {
		return nil, nil, err
	}
	return r, pos[3:], nil
}

// analyze resolves one (spec, from, to) to a materialized workspace: the
// reusable core shared by the single-pair commands and bulk mode.
func analyze(cacheDir, specStr, fromArg, toArg string) (*resolved, error) {
	sp, err := spec.Parse(specStr)
	if err != nil {
		return nil, err
	}
	from, err := spec.NormalizeVersion(sp.Eco, fromArg)
	if err != nil {
		return nil, err
	}
	to, err := spec.NormalizeVersion(sp.Eco, toArg)
	if err != nil {
		return nil, err
	}
	c, err := cache.Open(cacheDir)
	if err != nil {
		return nil, err
	}
	// the artifact is keyed on the repo (shared across sub-paths), but the
	// workspace is scoped to the sub-path, so fold Sub into the workspace key
	wsKey := sp.Name
	if sp.Sub != "" {
		wsKey += "/" + sp.Sub
	}
	ws := c.WorkspacePath(string(sp.Eco), wsKey, from, to)
	st, err := loadWorkspace(ws)
	if err != nil {
		if st, err = materialize(c, sp, from, to, ws); err != nil {
			return nil, err
		}
	}
	idx, err := loadIndex(ws)
	if err != nil {
		return nil, err
	}
	return &resolved{ws: ws, cacheRoot: c.Root, sp: sp, st: st, idx: idx}, nil
}

func diffCmd(args []string) error {
	format := "stats"
	noOSV := false
	r, _, err := resolveWorkspace(args, func(a string) (bool, error) {
		switch {
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case a == "--no-osv":
			noOSV = true
		default:
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return err
	}

	// OSV is advisory and time-varying, so it is queried live (TTL-cached)
	// at report time for the human/JSON reports, not baked into the
	// workspace. patch/files stay pristine and skip it.
	if !noOSV && (format == "stats" || format == "json") {
		client := &http.Client{}
		r.st.Security = osv.Assess(context.Background(), client, r.cacheRoot,
			r.st.Package.Ecosystem, r.st.Package.Name, r.st.Package.From, r.st.Package.To)
	}
	// coverage + next-steps depend on the merged OSV, so compute here (not
	// in the deterministic workspace build) and attach for text and JSON
	if format == "stats" || format == "json" {
		r.st.Coverage, r.st.NextActions = output.Guide(r.st)
	}

	switch format {
	case "stats":
		fmt.Print(output.Text(r.st))
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r.st)
	case "patch":
		fmt.Fprintf(os.Stderr, "depsound: workspace %s\n", r.ws)
		return copyFile(filepath.Join(r.ws, "diff.patch"), os.Stdout)
	case "files":
		// changed-file table on stdout; tree paths for direct grepping
		// on stderr so stdout stays a clean list
		fmt.Fprintf(os.Stderr, "depsound: trees at %s/old %s/new\n", r.ws, r.ws)
		fmt.Print(output.Files(r.st))
	default:
		return fmt.Errorf("unknown format %q", format)
	}
	return nil
}

func loadIndex(ws string) (*surface.Index, error) {
	b, err := os.ReadFile(filepath.Join(ws, "surface.json"))
	if err != nil {
		return nil, err
	}
	var idx surface.Index
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, err
	}
	return &idx, nil
}

func copyFile(path string, w io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

func loadWorkspace(ws string) (*stats.Stats, error) {
	b, err := os.ReadFile(filepath.Join(ws, "stats.json"))
	if err != nil {
		return nil, err
	}
	var st stats.Stats
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	if st.Tool.Version != version.Version || st.Tool.Schema != stats.SchemaVersion {
		return nil, fmt.Errorf("workspace built by %s schema %d, rebuilding", st.Tool.Version, st.Tool.Schema)
	}
	for _, member := range []string{"diff.patch", "surface.json", "old", "new"} {
		if _, err := os.Stat(filepath.Join(ws, member)); err != nil {
			return nil, fmt.Errorf("workspace incomplete (%s missing), rebuilding", member)
		}
	}
	return &st, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func materialize(c *cache.Cache, sp spec.Spec, from, to, ws string) (*stats.Stats, error) {
	ctx := context.Background()
	// no total timeout: fetch applies a metadata deadline and a download
	// stall watchdog, so slow links with big artifacts are never killed
	// while making progress
	client := &http.Client{}

	ext := map[spec.Ecosystem]string{spec.NPM: ".tgz", spec.Go: ".zip", spec.Crates: ".crate", spec.GHA: ".tar.gz"}[sp.Eco]
	arts := map[string]string{}
	srcs := map[string]*stats.Source{}
	for _, v := range []string{from, to} {
		dest := c.ArtifactPath(string(sp.Eco), sp.Name, v, ext)
		if _, err := os.Stat(dest); err != nil {
			fmt.Fprintf(os.Stderr, "depsound: fetching %s@%s\n", sp, v)
		}
		// always goes through fetch: cache hits are rehashed against the
		// sidecar digest there, and failures refetch
		var err error
		switch sp.Eco {
		case spec.NPM:
			err = fetch.NPM(ctx, client, sp.Name, v, dest)
		case spec.Go:
			err = fetch.GoModule(ctx, client, sp.Name, v, dest)
		case spec.Crates:
			err = fetch.Crate(ctx, client, sp.Name, v, dest)
		case spec.GHA:
			err = fetch.GHA(ctx, client, sp.Name, v, dest)
		}
		if err != nil {
			return nil, err
		}
		arts[v] = dest
		if m := fetch.ReadMeta(dest); m != nil {
			srcs[v] = &stats.Source{URL: m.URL, Digest: m.Digest, Verification: m.Verification, RefKind: m.RefKind}
		}
	}

	// build in a unique temp sibling so concurrent builders never share
	// state and a valid workspace is never deleted before its replacement
	// is ready
	if err := os.MkdirAll(filepath.Dir(ws), 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(ws), ".build-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	fmt.Fprintf(os.Stderr, "depsound: %s %s->%s: extracting and diffing\n", sp, from, to)
	var skippedLinks, hostileEntries []string
	for v, sub := range map[string]string{from: "old", to: "new"} {
		var rep *extract.Report
		var err error
		switch sp.Eco {
		case spec.NPM:
			rep, err = extract.TarGz(arts[v], filepath.Join(tmp, sub), extract.DefaultLimits)
		case spec.Go:
			// module zips declare their root: module@version/
			rep, err = extract.Zip(arts[v], filepath.Join(tmp, sub), sp.Name+"@"+v, extract.DefaultLimits)
		case spec.Crates:
			// .crate is a gzip tarball rooted at name-version/
			rep, err = extract.TarGz(arts[v], filepath.Join(tmp, sub), extract.DefaultLimits)
		case spec.GHA:
			// GitHub tarball is rooted at repo-<sha>/, auto-stripped
			rep, err = extract.TarGz(arts[v], filepath.Join(tmp, sub), extract.DefaultLimits)
		}
		if err != nil {
			return nil, err
		}
		for _, l := range rep.SkippedLinks {
			skippedLinks = append(skippedLinks, sub+": "+l)
		}
		for _, h := range rep.HostileEntries {
			hostileEntries = append(hostileEntries, sub+": "+h)
		}
	}

	// a GHA sub-path action is scoped to what you actually adopt: diff the
	// sub-tree, not the whole repo. Name stays owner/repo (what we fetched);
	// Sub selects owner/repo/SUB. The action may still reference repo-level
	// code, a scoping caveat, surfaced as a note in Build.
	oldRoot, newRoot := "old", "new"
	if sp.Sub != "" {
		for _, side := range []string{"old", "new"} {
			if !exists(filepath.Join(tmp, side, sp.Sub)) {
				return nil, fmt.Errorf("gha sub-path %q not present in %s tree (%s@%s); check the path", sp.Sub, side, sp.Name, map[string]string{"old": from, "new": to}[side])
			}
		}
		oldRoot = filepath.Join("old", sp.Sub)
		newRoot = filepath.Join("new", sp.Sub)
	}

	patchPath := filepath.Join(tmp, "diff.patch")
	diffs, err := gitdiff.Diff(tmp, oldRoot, newRoot, patchPath)
	if err != nil {
		return nil, err
	}

	idx, err := surface.Parse(patchPath, oldRoot, newRoot)
	if err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(tmp, "surface.json"), idx); err != nil {
		return nil, err
	}

	input := stats.Input{
		ToolVersion:    version.Version,
		Pkg:            stats.PkgRef{Ecosystem: string(sp.Eco), Name: sp.Name, From: from, To: to},
		SubPath:        sp.Sub,
		Workspace:      ws,
		OldTree:        filepath.Join(tmp, oldRoot),
		NewTree:        filepath.Join(tmp, newRoot),
		Diffs:          diffs,
		SkippedLinks:   skippedLinks,
		HostileEntries: hostileEntries,
		SourceFrom:     srcs[from],
		SourceTo:       srcs[to],
	}
	switch sp.Eco {
	case spec.NPM:
		if input.OldPkg, err = npmpkg.Load(input.OldTree); err != nil {
			return nil, fmt.Errorf("old tree: %w", err)
		}
		if input.NewPkg, err = npmpkg.Load(input.NewTree); err != nil {
			return nil, fmt.Errorf("new tree: %w", err)
		}
	case spec.Go:
		if input.OldMod, err = gopkg.Load(input.OldTree); err != nil {
			return nil, fmt.Errorf("old tree: %w", err)
		}
		if input.NewMod, err = gopkg.Load(input.NewTree); err != nil {
			return nil, fmt.Errorf("new tree: %w", err)
		}
	case spec.Crates:
		if input.OldCrate, err = cratepkg.Load(input.OldTree); err != nil {
			return nil, fmt.Errorf("old tree: %w", err)
		}
		if input.NewCrate, err = cratepkg.Load(input.NewTree); err != nil {
			return nil, fmt.Errorf("new tree: %w", err)
		}
	case spec.GHA:
		// trees are already scoped to the action's path, so action.yml is
		// at their root
		if input.OldAction, err = ghapkg.Load(input.OldTree); err != nil {
			return nil, fmt.Errorf("old tree: %w", err)
		}
		if input.NewAction, err = ghapkg.Load(input.NewTree); err != nil {
			return nil, fmt.Errorf("new tree: %w", err)
		}
	}

	st, err := stats.Build(input)
	if err != nil {
		return nil, err
	}

	if err := writeJSON(filepath.Join(tmp, "stats.json"), st); err != nil {
		return nil, err
	}
	// Install the build. Retries close the race where two processes
	// replace the same stale workspace: in the gap where one has moved it
	// aside, the other's retried rename lands in the empty slot.
	var installErr error
	for range 3 {
		installErr = os.Rename(tmp, ws)
		if installErr == nil {
			return st, nil
		}
		// a valid workspace already there: a concurrent winner, adopt it
		if winner, werr := loadWorkspace(ws); werr == nil {
			return winner, nil
		}
		// a stale/invalid one blocks the rename: move it aside atomically,
		// swap in the new build, restore on failure
		trash := tmp + ".old"
		if os.Rename(ws, trash) == nil {
			if err2 := os.Rename(tmp, ws); err2 == nil {
				_ = os.RemoveAll(trash)
				return st, nil
			}
			_ = os.Rename(trash, ws)
		}
	}
	return nil, installErr
}
