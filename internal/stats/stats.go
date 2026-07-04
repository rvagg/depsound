// Package stats defines depvet's report schema (the contract consumed by
// agents) and assembles it from the diff, the trees and the manifests.
package stats

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rvagg/depvet/internal/classify"
	"github.com/rvagg/depvet/internal/cratepkg"
	"github.com/rvagg/depvet/internal/gitdiff"
	"github.com/rvagg/depvet/internal/gopkg"
	"github.com/rvagg/depvet/internal/manifest"
	"github.com/rvagg/depvet/internal/npmpkg"
	"github.com/rvagg/depvet/internal/osv"
)

// SchemaVersion 2: the npm-specific compat.engines field became the
// ecosystem-neutral compat.constraints (a breaking rename, hence the
// bump, per the evolution rule).
const SchemaVersion = 2

type Stats struct {
	Tool         Tool                 `json:"tool"`
	Package      PkgRef               `json:"package"`
	Artifact     Artifact             `json:"artifact"`
	Runnable     Runnable             `json:"runnable"`
	Compat       Compat               `json:"compat"`
	Dependencies []manifest.DepChange `json:"dependencies"`
	Files        FilesSection         `json:"files"`
	Embedded     []EmbeddedMarker     `json:"embeddedMarkers,omitempty"`
	Security     Security             `json:"security"`
	Workspace    string               `json:"workspace"`
	Notes        []string             `json:"notes,omitempty"`
	// Coverage and NextActions are the anti-false-security spine: what
	// the tool did and did NOT check, and where to point judgement next.
	// Populated at report time (they depend on the live OSV merge), so a
	// clean result never reads as a verdict.
	Coverage    *Coverage    `json:"coverage,omitempty"`
	NextActions []NextAction `json:"nextActions,omitempty"`
}

type Coverage struct {
	Checked    []string `json:"checked"`
	NotChecked []string `json:"notChecked"`
}

type NextAction struct {
	Reason  string `json:"reason"`
	Command string `json:"command,omitempty"`
}

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Schema  int    `json:"schema"`
}

type PkgRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	From      string `json:"from"`
	To        string `json:"to"`
}

type Artifact struct {
	BytesFrom int64 `json:"bytesFrom"`
	BytesTo   int64 `json:"bytesTo"`
	FilesFrom int   `json:"filesFrom"`
	FilesTo   int   `json:"filesTo"`
	// SkippedLinks are symlink/hardlink entries never materialized; the
	// trees diverge from the install-time artifact by exactly this list.
	SkippedLinks []string `json:"skippedLinks,omitempty"`
	// HostileEntries are archive members with traversal/absolute/control-
	// byte names, skipped at extraction; their presence is a loud signal.
	HostileEntries []string `json:"hostileEntries,omitempty"`
	// Source provenance makes a report reproducible from the JSON alone.
	SourceFrom *Source `json:"sourceFrom,omitempty"`
	SourceTo   *Source `json:"sourceTo,omitempty"`
}

type Source struct {
	URL    string `json:"url"`
	Digest string `json:"digest"`
	// Verification distinguishes registry/sumdb-verified artifacts from
	// TLS-trust-only ones; "tls-only" prefixed values get a note.
	Verification string `json:"verification,omitempty"`
}

type Runnable struct {
	Lifecycle []manifest.Change `json:"lifecycle"`
	Bin       []manifest.Change `json:"bin"`
	GypFrom   bool              `json:"nodeGypFrom"`
	GypTo     bool              `json:"nodeGypTo"`
	// cgo means C compilation at the consumer's build time (Go only)
	CgoFrom bool `json:"cgoFrom,omitempty"`
	CgoTo   bool `json:"cgoTo,omitempty"`
	// build.rs and proc-macro both run code at the consumer's compile
	// time (crates only)
	BuildRSFrom   bool `json:"buildRsFrom,omitempty"`
	BuildRSTo     bool `json:"buildRsTo,omitempty"`
	ProcMacroFrom bool `json:"procMacroFrom,omitempty"`
	ProcMacroTo   bool `json:"procMacroTo,omitempty"`
}

type Compat struct {
	TypeFrom string `json:"typeFrom,omitempty"`
	TypeTo   string `json:"typeTo,omitempty"`
	// Constraints carry full display labels in Key: engines.node,
	// go directive, toolchain, rust-version
	Constraints []manifest.Change       `json:"constraints"`
	Exports     []manifest.ExportChange `json:"exports"`
}

// Security is the OSV assessment. It is NOT part of the deterministic
// workspace build (OSV is an advisory snapshot); it is queried live at
// report time and merged in before rendering.
type Security = osv.Assessment

type FilesSection struct {
	Changed int `json:"changed"`
	Added   int `json:"linesAdded"`
	Removed int `json:"linesRemoved"`
	// ReviewSurface* excludes confidently-generated (marker/suffix) and
	// binary files: the hand-written surface a reviewer actually reads.
	// It is a triage aid, NOT a trust boundary: the full totals above
	// still count everything, and path-only "generated" files (weakly
	// classified, possibly hand-edited or a hidden payload) are KEPT in
	// the surface deliberately.
	ReviewFiles   int         `json:"reviewSurfaceFiles"`
	ReviewAdded   int         `json:"reviewSurfaceAdded"`
	ReviewRemoved int         `json:"reviewSurfaceRemoved"`
	ExcludedGen   []string    `json:"excludedGenerated,omitempty"`
	ByClass       []ClassAgg  `json:"byClass"`
	TrivialChurn  int         `json:"trivialChurn"` // changed files with <=2 line delta
	Flagged       []Flag      `json:"flagged"`
	Entries       []FileEntry `json:"entries"`
}

type ClassAgg struct {
	Class   string `json:"class"`
	Files   int    `json:"files"`
	Added   int    `json:"linesAdded"`
	Removed int    `json:"linesRemoved"`
}

type FileEntry struct {
	Path     string `json:"path"`
	OldPath  string `json:"oldPath,omitempty"`
	Status   string `json:"status"`
	Class    string `json:"class"`
	Evidence string `json:"evidence,omitempty"`
	Added    int    `json:"added"`
	Removed  int    `json:"removed"`
}

type Flag struct {
	Path    string             `json:"path"`
	Reason  string             `json:"reason"`
	Metrics classify.JSMetrics `json:"metrics"`
}

// EmbeddedMarker is a recognized upstream-identity string (see
// classify.EmbeddedMarkers) whose value changed inside a vendored blob: a
// lead pointing at the real upstream delta to review when the generated
// churn is otherwise opaque.
type EmbeddedMarker struct {
	File string `json:"file"`
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
}

// maxHeadBytes bounds the classification read; generated markers live in
// the first lines of real generated files.
const maxHeadBytes = 4096

// minifiedLineLen is the flag threshold; the metrics themselves are
// reported so the agent can apply its own judgement.
const minifiedLineLen = 1000

type Input struct {
	ToolVersion    string
	Pkg            PkgRef
	Workspace      string
	OldTree        string
	NewTree        string
	Diffs          []gitdiff.FileDiff
	OldPkg         *npmpkg.Package // npm only
	NewPkg         *npmpkg.Package
	OldMod         *gopkg.Mod // go only
	NewMod         *gopkg.Mod
	OldCrate       *cratepkg.Crate // crates only
	NewCrate       *cratepkg.Crate
	SkippedLinks   []string
	HostileEntries []string
	SourceFrom     *Source
	SourceTo       *Source
}

func Build(in Input) (*Stats, error) {
	s := &Stats{
		Tool:      Tool{Name: "depvet", Version: in.ToolVersion, Schema: SchemaVersion},
		Package:   in.Pkg,
		Workspace: in.Workspace,
		// Security is queried live at report time, not baked into the
		// deterministic workspace.
	}

	var err error
	s.Artifact.BytesFrom, s.Artifact.FilesFrom, err = treeSize(in.OldTree)
	if err != nil {
		return nil, err
	}
	s.Artifact.BytesTo, s.Artifact.FilesTo, err = treeSize(in.NewTree)
	if err != nil {
		return nil, err
	}
	s.Artifact.SkippedLinks = in.SkippedLinks
	s.Artifact.HostileEntries = in.HostileEntries
	s.Artifact.SourceFrom = in.SourceFrom
	s.Artifact.SourceTo = in.SourceTo
	if in.SourceFrom == nil || in.SourceTo == nil {
		s.Notes = append(s.Notes, "artifact provenance incomplete (cached before sidecars existed); refetch to restore")
	}
	for side, src := range map[string]*Source{"from": in.SourceFrom, "to": in.SourceTo} {
		if src != nil && strings.HasPrefix(src.Verification, "tls-only") {
			s.Notes = append(s.Notes, side+" artifact verified by TLS trust only (no registry integrity or checksum database record)")
		}
	}

	switch {
	case in.OldPkg != nil && in.NewPkg != nil:
		for _, w := range in.OldPkg.Warnings {
			s.Notes = append(s.Notes, "old package.json: "+w)
		}
		for _, w := range in.NewPkg.Warnings {
			s.Notes = append(s.Notes, "new package.json: "+w)
		}
		s.Runnable.Lifecycle = npmpkg.LifecycleDelta(in.OldPkg, in.NewPkg)
		s.Runnable.Bin = npmpkg.BinDelta(in.OldPkg, in.NewPkg)
		s.Runnable.GypFrom = exists(filepath.Join(in.OldTree, "binding.gyp"))
		s.Runnable.GypTo = exists(filepath.Join(in.NewTree, "binding.gyp"))
		if in.OldPkg.Type != in.NewPkg.Type {
			s.Compat.TypeFrom = orDefault(in.OldPkg.Type, "commonjs")
			s.Compat.TypeTo = orDefault(in.NewPkg.Type, "commonjs")
		}
		s.Compat.Constraints = npmpkg.EnginesDelta(in.OldPkg, in.NewPkg)
		s.Compat.Exports, err = npmpkg.ExportsDelta(in.OldPkg, in.NewPkg)
		if err != nil {
			s.Notes = append(s.Notes, "exports resolution failed: "+err.Error())
		}
		s.Dependencies = npmpkg.DepsDelta(in.OldPkg, in.NewPkg)

	case in.OldMod != nil && in.NewMod != nil:
		for _, w := range in.OldMod.Warnings {
			s.Notes = append(s.Notes, "old go.mod: "+w)
		}
		for _, w := range in.NewMod.Warnings {
			s.Notes = append(s.Notes, "new go.mod: "+w)
		}
		s.Runnable.CgoFrom = gopkg.ScanCgo(in.OldTree)
		s.Runnable.CgoTo = gopkg.ScanCgo(in.NewTree)
		s.Compat.Constraints = gopkg.ConstraintsDelta(in.OldMod, in.NewMod)
		s.Dependencies = gopkg.RequireDelta(in.OldMod, in.NewMod)

	case in.OldCrate != nil && in.NewCrate != nil:
		for _, w := range in.OldCrate.Warnings {
			s.Notes = append(s.Notes, "old Cargo.toml: "+w)
		}
		for _, w := range in.NewCrate.Warnings {
			s.Notes = append(s.Notes, "new Cargo.toml: "+w)
		}
		s.Runnable.BuildRSFrom = in.OldCrate.HasBuildRS()
		s.Runnable.BuildRSTo = in.NewCrate.HasBuildRS()
		s.Runnable.ProcMacroFrom = in.OldCrate.ProcMacro
		s.Runnable.ProcMacroTo = in.NewCrate.ProcMacro
		s.Compat.Constraints = append(
			cratepkg.ConstraintsDelta(in.OldCrate, in.NewCrate),
			cratepkg.FeaturesDelta(in.OldCrate, in.NewCrate)...)
		s.Dependencies = cratepkg.DepsDelta(in.OldCrate, in.NewCrate)
	}

	agg := map[string]*ClassAgg{}
	for _, d := range in.Diffs {
		head := readHead(in.NewTree, in.OldTree, d)
		res := classify.File(d.Path, head, d.Binary)

		// A C-family file that embeds a recognized upstream identity
		// marker is vendored code (a marker deep in the file, past the
		// head-classification window, e.g. sqlite3-binding.h). Reclassify
		// source -> generated and collect the marker delta in one read.
		if d.Status != "D" && !d.Binary && isCFamily(d.Path) {
			present, deltas := embeddedScan(in.OldTree, in.NewTree, d.Path, d.Status)
			s.Embedded = append(s.Embedded, deltas...)
			if present && res.Class == classify.Source {
				res = classify.Result{Class: classify.Generated, Evidence: "embeds an upstream identity marker (vendored)", Basis: classify.BasisMarker}
			}
		}

		e := FileEntry{
			Path: d.Path, OldPath: d.OldPath, Status: d.Status,
			Class: string(res.Class), Added: d.Added, Removed: d.Removed,
		}
		// empty only for source, the default class when no rule matches
		e.Evidence = res.Evidence
		s.Files.Entries = append(s.Files.Entries, e)
		s.Files.Changed++
		s.Files.Added += d.Added
		s.Files.Removed += d.Removed
		if d.Status == "M" && d.Added+d.Removed <= 2 && !d.Binary {
			s.Files.TrivialChurn++
		}

		// Review surface: exclude only CONFIDENTLY-generated (marker or
		// suffix) and binary files. Path-only "generated" files stay in,
		// because a hand-edit or hidden payload under dist/ must not be
		// silently dropped from the number a reviewer trusts.
		if d.Binary || (res.Class == classify.Generated && res.Basis.Strong()) {
			if res.Class == classify.Generated && res.Basis.Strong() {
				s.Files.ExcludedGen = append(s.Files.ExcludedGen, d.Path)
			}
		} else {
			s.Files.ReviewFiles++
			s.Files.ReviewAdded += d.Added
			s.Files.ReviewRemoved += d.Removed
		}

		a := agg[string(res.Class)]
		if a == nil {
			a = &ClassAgg{Class: string(res.Class)}
			agg[string(res.Class)] = a
		}
		a.Files++
		a.Added += d.Added
		a.Removed += d.Removed

		if isJS(d.Path) && d.Status != "D" && !d.Binary {
			if content, err := os.ReadFile(filepath.Join(in.NewTree, d.Path)); err == nil {
				m := classify.Metrics(content)
				if m.MaxLine >= minifiedLineLen {
					s.Files.Flagged = append(s.Files.Flagged, Flag{
						Path: d.Path, Reason: "minified-looking (long lines)", Metrics: m,
					})
				}
			}
		}

	}
	for _, a := range agg {
		s.Files.ByClass = append(s.Files.ByClass, *a)
	}
	sort.Slice(s.Files.ByClass, func(i, j int) bool {
		return s.Files.ByClass[i].Files > s.Files.ByClass[j].Files
	})

	// Always disclose the heuristic when the review-surface number leans on
	// it: a file only APPEARS generated to our classifier, and markers are
	// attacker-writable. This note rides into agent context (JSON notes).
	if n := len(s.Files.ExcludedGen); n > 0 {
		s.Notes = append(s.Notes, fmt.Sprintf(
			"review surface excludes %d file(s) our heuristic classified generated; this is a GUESS (markers are attacker-writable), inspect them if the change's intent is unclear: %s",
			n, strings.Join(s.Files.ExcludedGen, ", ")))
	}
	return s, nil
}

// embeddedScan reads a changed file once and reports whether it embeds
// recognized upstream-identity markers (for vendored-code reclassification)
// and which markers changed value (the review lead).
func embeddedScan(oldTree, newTree, path, status string) (present bool, deltas []EmbeddedMarker) {
	newC, err := os.ReadFile(filepath.Join(newTree, path))
	if err != nil {
		return false, nil
	}
	newV := classify.EmbeddedMarkers(newC)
	if len(newV) == 0 {
		return false, nil
	}
	if status != "M" {
		return true, nil
	}
	oldC, err := os.ReadFile(filepath.Join(oldTree, path))
	if err != nil {
		return true, nil
	}
	oldV := classify.EmbeddedMarkers(oldC)
	for name, to := range newV {
		if from := oldV[name]; from != to {
			deltas = append(deltas, EmbeddedMarker{File: path, Name: name, From: from, To: to})
		}
	}
	sort.Slice(deltas, func(i, j int) bool { return deltas[i].Name < deltas[j].Name })
	return true, deltas
}

func isCFamily(p string) bool {
	for _, ext := range []string{".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func readHead(newTree, oldTree string, d gitdiff.FileDiff) []byte {
	p := filepath.Join(newTree, d.Path)
	if d.Status == "D" {
		p = filepath.Join(oldTree, d.Path)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, maxHeadBytes)
	n, _ := f.Read(buf)
	return buf[:n]
}

func isJS(p string) bool {
	return strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs") || strings.HasSuffix(p, ".cjs")
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func treeSize(root string) (bytes int64, files int, err error) {
	err = filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			bytes += info.Size()
			files++
		}
		return nil
	})
	return bytes, files, err
}
