package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rvagg/depsound/internal/fetch"
	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/output"
	"github.com/rvagg/depsound/internal/provenance"
	"github.com/rvagg/depsound/internal/spec"
)

// bulkConcurrency bounds parallel materialization; the cache is
// concurrent-safe, and a dependabot PR is a handful of deps.
const bulkConcurrency = 4

// bulkCmd runs the per-pair pipeline over a LIST of dependency changes and
// aggregates. The list is the agent's to supply (it already has it from
// the PR/diff); depsound does the analysis, not the extraction.
func bulkCmd(args []string) error {
	cacheDir, format, inputFile := "", "stats", ""
	noOSV, noProv := false, false
	var cooldown time.Duration
	var pos []string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--cache-dir="):
			cacheDir = strings.TrimPrefix(a, "--cache-dir=")
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case strings.HasPrefix(a, "--file="):
			inputFile = strings.TrimPrefix(a, "--file=")
		case strings.HasPrefix(a, "--cooldown="):
			d, err := parseCooldown(strings.TrimPrefix(a, "--cooldown="))
			if err != nil {
				return err
			}
			cooldown = d
		case a == "--no-osv":
			noOSV = true
		case a == "--no-provenance":
			noProv = true
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("unknown flag %q", a)
		default:
			pos = append(pos, a)
		}
	}

	items, err := readBulkList(inputFile, pos)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return fmt.Errorf("bulk needs `<eco>:<name> <from> <to>` lines (or a JSON array) on stdin or --file=")
	}

	results := runBulk(cacheDir, items, noOSV, noProv, cooldown)

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	if format == "markdown" {
		fmt.Print(output.Markdown(results))
		return nil
	}
	fmt.Print(output.Bulk(results))
	return nil
}

type bulkItem struct {
	spec, from, to string
	redirect       string // non-empty: spec is redirected to this target (a flag, no fetch)
	// failure is non-empty when detect could not resolve a manifest (spec is the
	// manifest path, not an eco:name): it rides the stream as a failed-analysis
	// row so a parse failure is a loud coverage gap, never silence.
	failure string
}

// readBulkList reads from --file, else a positional file arg, else stdin.
// Accepts a JSON array of {ecosystem,name,from,to} or, per line,
// `<eco>:<name> <from> <to>` (# comments and blanks skipped).
func readBulkList(inputFile string, pos []string) ([]bulkItem, error) {
	var raw []byte
	var err error
	switch {
	case inputFile != "":
		raw, err = os.ReadFile(inputFile)
	case len(pos) == 1:
		raw, err = os.ReadFile(pos[0])
	case len(pos) == 0:
		raw, err = io.ReadAll(os.Stdin)
	default:
		return nil, fmt.Errorf("bulk takes at most one input file; got %d positional args", len(pos))
	}
	if err != nil {
		return nil, err
	}

	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		return parseBulkJSON(raw)
	}
	return parseBulkLines(trimmed)
}

func parseBulkJSON(raw []byte) ([]bulkItem, error) {
	var arr []struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		From      string `json:"from"`
		To        string `json:"to"`
		Redirect  string `json:"redirect"`
	}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("bulk JSON: %w", err)
	}
	var items []bulkItem
	for _, e := range arr {
		if e.Ecosystem == "" || e.Name == "" {
			return nil, fmt.Errorf("bulk JSON entry needs ecosystem and name: %+v", e)
		}
		spc := e.Ecosystem + ":" + e.Name
		// a redirect is a flag (no version to diff); otherwise to is required,
		// with from omitted marking a new dependency (census)
		if e.Redirect != "" {
			items = append(items, bulkItem{spec: spc, redirect: e.Redirect})
			continue
		}
		if e.To == "" {
			return nil, fmt.Errorf("bulk JSON entry needs to (or redirect): %+v", e)
		}
		items = append(items, bulkItem{spec: spc, from: e.From, to: e.To})
	}
	return items, nil
}

// parseBulkLines reads either a bump (`<eco>:<name> <from> <to>`) or a new
// dependency (`<eco>:<name> <version>`, no from) per line. A new dep is
// census-shaped: there is no prior version to diff, so it carries an empty
// from and runBulk censuses it.
func parseBulkLines(s string) ([]bulkItem, error) {
	var items []bulkItem
	for line := range strings.Lines(s) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// an unresolved manifest from detect: `unresolved<TAB>path<TAB>reason`.
		// TAB-delimited because the reason is free text; it becomes a failed row.
		if rest, ok := strings.CutPrefix(line, "unresolved\t"); ok {
			path, reason, _ := strings.Cut(rest, "\t")
			items = append(items, bulkItem{spec: path, failure: reason})
			continue
		}
		f := strings.Fields(line)
		// a redirect line flags a non-registry source: `redirect <eco>:<name> <target>`
		if len(f) > 0 && f[0] == "redirect" {
			if len(f) != 3 {
				return nil, fmt.Errorf("bulk line %q: want `redirect <eco>:<name> <target>`", line)
			}
			if _, err := spec.Parse(f[1]); err != nil {
				return nil, err
			}
			items = append(items, bulkItem{spec: f[1], redirect: f[2]})
			continue
		}
		switch len(f) {
		case 2:
			if _, err := spec.Parse(f[0]); err != nil {
				return nil, err
			}
			items = append(items, bulkItem{spec: f[0], to: f[1]})
		case 3:
			if _, err := spec.Parse(f[0]); err != nil {
				return nil, err
			}
			items = append(items, bulkItem{spec: f[0], from: f[1], to: f[2]})
		default:
			return nil, fmt.Errorf("bulk line %q: want `<eco>:<name> <from> <to>` (bump), `<eco>:<name> <version>` (new dep), or `redirect <eco>:<name> <target>`", line)
		}
	}
	return items, nil
}

// censusForBulk builds a lean footprint of a newly-added dependency for the
// bulk stream: the direct census plus a known-CVE scan, the signals
// that matter when there is no prior version to diff. Transitive/provenance depth
// is left to the deeper per-dep census the report routes to.
func censusForBulk(cacheDir, specStr, version string, noOSV bool, cooldown time.Duration) (*output.Census, error) {
	c, err := buildCensus(cacheDir, specStr, version, cooldown)
	if err != nil {
		return nil, err
	}
	if !noOSV {
		c.Vulns, c.OSVFetchedAt, c.OSVQueried, c.OSVNote = osv.Present(context.Background(), &http.Client{},
			censusCacheRoot(cacheDir), c.Ecosystem, c.Name, c.Version)
	}
	c.Coverage, c.NextActions = output.CensusGuide(c)
	return c, nil
}

// bulkFail classifies an analysis error: a typed acquisition failure becomes a
// structured Unavailable (absent/denied/transient, preserving URL and status),
// so a taken-down artifact reads as a distinct fact rather than an opaque
// error; anything else stays a generic analysis failure.
func bulkFail(ref string, err error) output.BulkResult {
	if he, ok := errors.AsType[*fetch.HTTPError](err); ok {
		return output.BulkResult{Ref: ref, Unavailable: &output.Unavailable{
			Kind: he.Kind(), Status: he.Status, URL: he.URL, Hint: he.Hint,
		}}
	}
	return output.BulkResult{Ref: ref, Err: err.Error()}
}

// runBulk fans analyze()+OSV+provenance over the list, bounded-parallel,
// preserving input order in the results.
func runBulk(cacheDir string, items []bulkItem, noOSV, noProv bool, cooldown time.Duration) []output.BulkResult {
	results := make([]output.BulkResult, len(items))
	sem := make(chan struct{}, bulkConcurrency)
	var wg sync.WaitGroup
	for i, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, it bulkItem) {
			defer wg.Done()
			defer func() { <-sem }()
			// an unresolved manifest: a parse/read failure detect could not turn
			// into a change set, surfaced as a failed row (a coverage gap)
			if it.failure != "" {
				results[i] = output.BulkResult{Ref: it.spec, Err: it.failure}
				return
			}
			// a redirect is a flag, not an artifact: nothing to fetch or diff,
			// the signal is that a trusted name points off the registry
			if it.redirect != "" {
				results[i] = output.BulkResult{Ref: it.spec, Redirect: it.redirect}
				return
			}
			// no from = a newly-added dependency: census its whole footprint,
			// there is no prior version to diff against
			if it.from == "" {
				ref := it.spec + " " + it.to
				c, err := censusForBulk(cacheDir, it.spec, it.to, noOSV, cooldown)
				if err != nil {
					results[i] = output.BulkResult{Ref: ref, Err: err.Error()}
					return
				}
				results[i] = output.BulkResult{Ref: ref, Census: c}
				return
			}
			ref := it.spec + " " + it.from + " -> " + it.to
			r, err := analyze(cacheDir, it.spec, it.from, it.to, cooldown)
			if err != nil {
				results[i] = bulkFail(ref, err)
				return
			}
			if !noOSV {
				r.st.Security = osv.Assess(context.Background(), &http.Client{}, r.cacheRoot,
					r.st.Package.Ecosystem, r.st.Package.Name, r.st.Package.From, r.st.Package.To)
			}
			// provenance deltas vs the prior version (the account-takeover shape);
			// Assess is a no-op for ecosystems deps.dev does not cover
			if !noProv {
				r.st.Provenance = provenance.Assess(context.Background(),
					r.st.Package.Ecosystem, r.st.Package.Name, r.st.Package.To, r.st.Package.From)
			}
			r.st.Coverage, r.st.NextActions = output.Guide(r.st)
			results[i] = output.BulkResult{Ref: ref, Stats: r.st}
		}(i, it)
	}
	wg.Wait()
	return results
}
