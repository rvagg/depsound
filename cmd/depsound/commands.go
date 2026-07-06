package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/rvagg/depsound/internal/gopkg"
	"github.com/rvagg/depsound/internal/output"
	"github.com/rvagg/depsound/internal/spec"
	"github.com/rvagg/depsound/internal/surface"
)

// surfaceCmd intersects the diff with a consumer's usage units and reports
// per-unit status. This is the flagship distiller: gnark's 1577 files
// become the handful a bls12-381 consumer must actually read.
func surfaceCmd(args []string) error {
	var uses, usesFile, format string
	var sourceOnly, subtree bool
	r, _, err := resolveWorkspace(args, func(a string) (bool, error) {
		switch {
		case strings.HasPrefix(a, "--uses="):
			uses = strings.TrimPrefix(a, "--uses=")
		case strings.HasPrefix(a, "--uses-file="):
			usesFile = strings.TrimPrefix(a, "--uses-file=")
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case a == "--source-only":
			sourceOnly = true
		case a == "--subtree":
			subtree = true
		default:
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return err
	}

	// class per changed file, from stats; the index itself stays pure
	class := map[string]string{}
	for _, e := range r.st.Files.Entries {
		class[e.Path] = e.Class
	}
	annotate := func(files []surface.FileSurface) []surface.FileSurface {
		out := files[:0:0]
		for _, f := range files {
			f.Class = class[f.Path]
			if sourceOnly && f.Class != "source" {
				continue
			}
			out = append(out, f)
		}
		return out
	}

	units, err := gatherUnits(uses, usesFile)
	if err != nil {
		return err
	}
	if len(units) == 0 {
		return fmt.Errorf("surface needs consumer units: --uses=a,b,c or --uses-file=path")
	}

	// Go unit mapping needs the exact module path, read from the new
	// tree's go.mod. Without it, absolute import paths cannot be mapped
	// and must fail SAFE (unmapped), never noChangedFiles.
	modulePath := ""
	if r.sp.Eco == spec.Go {
		if m, err := gopkg.Load(r.ws + "/new"); err == nil {
			modulePath = m.Path()
		}
	}

	results := make([]surface.UnitResult, 0, len(units))
	for _, u := range units {
		prefixes, detail, scoped := normalizeUnit(r.sp.Eco, modulePath, u)
		if !scoped {
			results = append(results, surface.UnitResult{Unit: u, Status: surface.StatusOutOfScope, Detail: detail})
			continue
		}
		// default: honest Go package-dir semantics (own vs descendant).
		// --subtree collapses the whole area into the match, for when the
		// agent has judged the nested packages reachable and wants them
		// counted (the "I use this area" case).
		packageDirs := r.sp.Eco == spec.Go && !subtree
		res := r.idx.Match(u, prefixes, packageDirs)
		res.Detail = detail
		res.Files = annotate(res.Files)
		res.Descendants = annotate(res.Descendants)
		// --source-only can empty a positive result; recompute its status
		// from what survives, so neither matched nor subpackagesOnly is
		// left claiming files it no longer has.
		if sourceOnly && (res.Status == surface.StatusMatched || res.Status == surface.StatusSubpackagesOnly) {
			switch {
			case len(res.Files) > 0:
				res.Status = surface.StatusMatched
			case len(res.Descendants) > 0:
				res.Status = surface.StatusSubpackagesOnly
			default:
				res.Status = surface.StatusNoChangedFiles
				res.Detail = "only non-source files (test/docs/generated) changed here"
			}
		}
		results = append(results, res)
	}

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"package":     r.st.Package,
			"units":       results,
			"workspace":   r.ws,
			"limitations": output.SurfaceLimitations(string(r.sp.Eco)),
		})
	}
	fmt.Print(output.Surface(r.st, results, r.idx, r.ws))
	return nil
}

// showCmd extracts targeted slices of diff.patch: a file, a directory, or
// a symbol. stdout stays a valid patch; the breadcrumb goes to stderr.
func showCmd(args []string) error {
	var file, dir, symbol string
	r, _, err := resolveWorkspace(args, func(a string) (bool, error) {
		switch {
		case strings.HasPrefix(a, "--file="):
			file = strings.TrimPrefix(a, "--file=")
		case strings.HasPrefix(a, "--dir="):
			dir = strings.TrimPrefix(a, "--dir=")
		case strings.HasPrefix(a, "--symbol="):
			symbol = strings.TrimPrefix(a, "--symbol=")
		default:
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	set := 0
	for _, s := range []string{file, dir, symbol} {
		if s != "" {
			set++
		}
	}
	if set != 1 {
		return fmt.Errorf("show needs exactly one of --file=, --dir=, --symbol=")
	}

	raw, err := os.ReadFile(r.ws + "/diff.patch")
	if err != nil {
		return err
	}

	var sel []surface.FileSurface
	switch {
	case file != "":
		for _, f := range r.idx.Files {
			if f.Path == file {
				sel = append(sel, f)
			}
		}
	case dir != "":
		// show a directory as a subtree (path semantics), not Go-package
		res := r.idx.Match(dir, []string{dir}, false)
		sel = res.Files
	case symbol != "":
		// scan headers AND hunk bodies so a symbol changed at its own
		// declaration line (attributed by git to the preceding symbol)
		// is still found
		sel = r.idx.SymbolHunks(raw, symbol)
	}
	if len(sel) == 0 {
		return fmt.Errorf("no changed content matches that selector")
	}
	fmt.Fprintf(os.Stderr, "depsound: workspace %s\n", r.ws)
	_, err = os.Stdout.Write(r.idx.Extract(raw, sel))
	return err
}

func gatherUnits(uses, usesFile string) ([]string, error) {
	var raw []string
	if uses != "" {
		raw = append(raw, strings.Split(uses, ",")...)
	}
	if usesFile != "" {
		b, err := os.ReadFile(usesFile)
		if err != nil {
			return nil, err
		}
		s := strings.TrimSpace(string(b))
		if strings.HasPrefix(s, "[") { // JSON array
			var arr []string
			if err := json.Unmarshal(b, &arr); err != nil {
				return nil, fmt.Errorf("--uses-file JSON: %w", err)
			}
			raw = append(raw, arr...)
		} else {
			for line := range strings.Lines(s) {
				raw = append(raw, line)
			}
		}
	}
	var units []string
	for _, u := range raw {
		if u = strings.TrimSpace(u); u != "" {
			units = append(units, u)
		}
	}
	return units, nil
}

// normalizeUnit maps a consumer-written usage unit to tree-relative path
// prefixes. Returns (prefixes, detail, inScope). nil prefixes with
// inScope=true means unmapped (Match reports it); inScope=false means the
// mechanism is unsupported (outOfScope).
func normalizeUnit(eco spec.Ecosystem, modulePath, unit string) ([]string, string, bool) {
	unit = strings.Trim(unit, "/")
	switch eco {
	case spec.Go:
		return normalizeGoUnit(modulePath, unit)
	default:
		return []string{unit}, "", true
	}
}

// looksAbsolute reports whether an import path has a dotted first segment
// (github.com, golang.org), the marker of a fully-qualified module path
// as opposed to an already-tree-relative package dir.
func looksAbsolute(imp string) bool {
	first, _, _ := strings.Cut(imp, "/")
	return strings.Contains(first, ".")
}

// normalizeGoUnit maps a Go import path to the tree-relative package dir
// using the artifact's actual module path. A root-package import (unit ==
// module path) maps to "" and matches the whole module surface. An
// absolute import that does not belong to this module, or one we cannot
// map because go.mod is absent, fails SAFE to unmapped rather than
// silently reporting noChangedFiles.
func normalizeGoUnit(modulePath, imp string) ([]string, string, bool) {
	if modulePath != "" {
		if imp == modulePath {
			return []string{""}, "module root package (whole-module surface)", true
		}
		if rel, ok := strings.CutPrefix(imp, modulePath+"/"); ok {
			return []string{rel}, "import under this module (subtree match)", true
		}
		if looksAbsolute(imp) {
			return nil, "import path is not part of module " + modulePath, true // -> unmapped
		}
		return []string{imp}, "treated as tree-relative path (subtree match)", true
	}
	// no module path (older artifact, no go.mod): absolute paths are
	// unmappable, relative ones are used as-is
	if looksAbsolute(imp) {
		return nil, "module path unknown (no go.mod in artifact); cannot map an absolute import path", true
	}
	return []string{imp}, "treated as tree-relative path (subtree match)", true
}
