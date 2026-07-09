package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/output"
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
	noOSV := false
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

	results := runBulk(cacheDir, items, noOSV, cooldown)

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	fmt.Print(output.Bulk(results))
	return nil
}

type bulkItem struct {
	spec, from, to string
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
	}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("bulk JSON: %w", err)
	}
	var items []bulkItem
	for _, e := range arr {
		if e.Ecosystem == "" || e.Name == "" || e.From == "" || e.To == "" {
			return nil, fmt.Errorf("bulk JSON entry needs ecosystem, name, from, to: %+v", e)
		}
		items = append(items, bulkItem{spec: e.Ecosystem + ":" + e.Name, from: e.From, to: e.To})
	}
	return items, nil
}

func parseBulkLines(s string) ([]bulkItem, error) {
	var items []bulkItem
	for line := range strings.Lines(s) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			return nil, fmt.Errorf("bulk line %q: want `<eco>:<name> <from> <to>`", line)
		}
		if _, err := spec.Parse(f[0]); err != nil {
			return nil, err
		}
		items = append(items, bulkItem{spec: f[0], from: f[1], to: f[2]})
	}
	return items, nil
}

// runBulk fans analyze()+OSV over the list, bounded-parallel, preserving
// input order in the results.
func runBulk(cacheDir string, items []bulkItem, noOSV bool, cooldown time.Duration) []output.BulkResult {
	results := make([]output.BulkResult, len(items))
	sem := make(chan struct{}, bulkConcurrency)
	var wg sync.WaitGroup
	for i, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, it bulkItem) {
			defer wg.Done()
			defer func() { <-sem }()
			ref := it.spec + " " + it.from + " -> " + it.to
			r, err := analyze(cacheDir, it.spec, it.from, it.to, cooldown)
			if err != nil {
				results[i] = output.BulkResult{Ref: ref, Err: err.Error()}
				return
			}
			if !noOSV {
				r.st.Security = osv.Assess(context.Background(), &http.Client{}, r.cacheRoot,
					r.st.Package.Ecosystem, r.st.Package.Name, r.st.Package.From, r.st.Package.To)
			}
			r.st.Coverage, r.st.NextActions = output.Guide(r.st)
			results[i] = output.BulkResult{Ref: ref, Stats: r.st}
		}(i, it)
	}
	wg.Wait()
	return results
}
