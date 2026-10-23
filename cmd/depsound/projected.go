package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/rvagg/depsound/internal/depsdev"
	"github.com/rvagg/depsound/internal/fetch"
	"github.com/rvagg/depsound/internal/output"
	"github.com/rvagg/depsound/internal/spec"
)

// transitiveProjected answers "what does this bump drag in" for a repo with
// no lockfile to diff: deps.dev resolves the package at each endpoint and the
// same diff, churn tree, and bulk router render the delta. deps.dev resolves
// the package in isolation and live, so this is a projection of the dep's own
// tree, never the tree you install; the renderer says so.
func transitiveProjected(cacheDir, specStr, fromArg, toArg string, cooldown time.Duration, noOSV bool, format string) error {
	sp, err := spec.Parse(specStr)
	if err != nil {
		return err
	}
	system, ok := depsdev.System(string(sp.Eco))
	if !ok {
		if sp.Eco == spec.Go {
			return fmt.Errorf("no projection needed for go: go.mod IS the resolved set, so diff the pair (`depsound transitive go --old=<base go.mod> --new=<PR go.mod>`)")
		}
		return fmt.Errorf("deps.dev has no resolved graph for %s; projection covers npm and crates", sp.Eco)
	}
	ctx, client := context.Background(), &http.Client{}
	from, to, err := resolvePair(ctx, client, sp, fromArg, toArg, cooldown)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "depsound: projecting %s:%s %s -> %s via deps.dev\n",
		sp.Eco, output.EscapeText(sp.Name), output.EscapeText(from), output.EscapeText(to))
	oldG, oldErr := depsdev.Resolve(ctx, client, system, sp.Name, from)
	newG, newErr := depsdev.Resolve(ctx, client, system, sp.Name, to)
	if oldErr != nil || newErr != nil {
		gap := oldErr
		if gap == nil {
			gap = newErr
		}
		tr := output.TransitiveResult{
			Ecosystem:     string(sp.Eco),
			Projected:     sp.Name,
			Flat:          true,
			ProjectionGap: gap.Error(),
			Changed: runBulk(cacheDir, []bulkItem{{
				spec: string(sp.Eco) + ":" + sp.Name, from: from, to: to,
			}}, noOSV, provenanceUnavailableFallback, cooldown),
		}
		if format == "json" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(tr)
		}
		fmt.Print(output.Transitive(tr))
		return nil
	}

	res := diffResolved(nodesToResolved(oldG.Deps), nodesToResolved(newG.Deps))
	// the bumped package roots the churn rather than sitting inside its own
	// subtree, so it leads the report: it is the dep you actually changed
	res.changed = append([]output.ModuleRef{{Path: sp.Name, From: from, To: to}}, res.changed...)

	var items []bulkItem
	for _, c := range res.changed {
		items = append(items, bulkItem{spec: string(sp.Eco) + ":" + c.Path, from: c.From, to: c.To})
	}
	fmt.Fprintf(os.Stderr, "depsound: %s projected: %d changed (incl. the bump), %d added, %d removed; analysing changes and added modules\n",
		output.EscapeText(sp.Name), len(res.changed), len(res.added), len(res.removed))
	tr := output.TransitiveResult{
		Ecosystem: string(sp.Eco),
		Projected: sp.Name,
		Flat:      true, // deps.dev's direct/indirect is relative to the dep, not to you
		Changed:   runBulk(cacheDir, items, noOSV, provenanceUnavailableFallback, cooldown),
		Added:     res.added,
		Removed:   res.removed,
	}
	attributeCause(newG.Root, newG.Edges[newG.Root], newG.Edges, tr.Added)
	attributeCause(oldG.Root, oldG.Edges[oldG.Root], oldG.Edges, tr.Removed)
	analyseAdded(cacheDir, string(sp.Eco), tr.Added, noOSV)
	tr.Tree, tr.TreeNote = buildChurnTree([]string{newG.Root}, newG.Edges, res.changed, res.added)

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(tr)
	}
	fmt.Print(output.Transitive(tr))
	return nil
}

// resolvePair resolves two version args (each may be a range or "latest") to
// the concrete endpoints the projection runs on.
func resolvePair(ctx context.Context, client *http.Client, sp spec.Spec, fromArg, toArg string, cooldown time.Duration) (from, to string, err error) {
	fromRes, err := fetch.ResolveVersion(ctx, client, string(sp.Eco), sp.Name, fromArg, cooldown)
	if err != nil {
		return "", "", fmt.Errorf("resolve from %q: %w", fromArg, err)
	}
	toRes, err := fetch.ResolveVersion(ctx, client, string(sp.Eco), sp.Name, toArg, cooldown)
	if err != nil {
		return "", "", fmt.Errorf("resolve to %q: %w", toArg, err)
	}
	if from, err = spec.NormalizeVersion(sp.Eco, fromRes.Version); err != nil {
		return "", "", err
	}
	if to, err = spec.NormalizeVersion(sp.Eco, toRes.Version); err != nil {
		return "", "", err
	}
	if from == to {
		return "", "", fmt.Errorf("%q and %q both resolve to %s; nothing to project", fromArg, toArg, from)
	}
	return from, to, nil
}

// nodesToResolved adapts a deps.dev subtree to the ecosystem-neutral resolved
// set the lockfile diff works on.
func nodesToResolved(nodes []depsdev.Node) []resolvedDep {
	out := make([]resolvedDep, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, resolvedDep{n.Name, n.Version, n.Relation != "DIRECT"})
	}
	return out
}
