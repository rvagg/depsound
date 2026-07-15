// Package stats defines depsound's report schema (the contract consumed by
// agents) and assembles it from the diff, the trees and the manifests.
package stats

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rvagg/depsound/internal/classify"
	"github.com/rvagg/depsound/internal/cratepkg"
	"github.com/rvagg/depsound/internal/ghapkg"
	"github.com/rvagg/depsound/internal/gitdiff"
	"github.com/rvagg/depsound/internal/gopkg"
	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/npmpkg"
	"github.com/rvagg/depsound/internal/osv"
	"github.com/rvagg/depsound/internal/provenance"
)

// SchemaVersion 2: the npm-specific compat.engines field became the
// ecosystem-neutral compat.constraints (a breaking rename, hence the
// bump, per the evolution rule).
const SchemaVersion = 2

// Resolution records how a semver-range or "latest" version ARG became the
// concrete version reviewed, and, for the to side, the satisfying versions
// newer than it, which a consumer with a shorter or no cooldown installs
// instead and which this review did not cover.
type Resolution struct {
	FromSpec string   `json:"fromSpec,omitempty"` // raw from arg, if it was a range/latest
	ToSpec   string   `json:"toSpec,omitempty"`   // raw to arg, if it was a range/latest
	ToNewer  []string `json:"toNewer,omitempty"`  // satisfying versions newer than the resolved to
}

type Stats struct {
	Tool         Tool                 `json:"tool"`
	Package      PkgRef               `json:"package"`
	Artifact     Artifact             `json:"artifact"`
	Runnable     Runnable             `json:"runnable"`
	Compat       Compat               `json:"compat"`
	Dependencies []manifest.DepChange `json:"dependencies"`
	// Entrypoints are the new version's npm runtime payload files (resolved
	// exports/main/bin): the code that runs on import, to read first.
	Entrypoints []string           `json:"entrypoints,omitempty"`
	Files       FilesSection       `json:"files"`
	Embedded    []EmbeddedMarker   `json:"embeddedMarkers,omitempty"`
	Security    Security           `json:"security"`
	Action      *ActionSection     `json:"action,omitempty"` // gha only
	Provenance  *provenance.Result `json:"provenance,omitempty"`
	Resolution  *Resolution        `json:"resolution,omitempty"`
	Workspace   string             `json:"workspace"`
	Notes       []string           `json:"notes,omitempty"`
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
	// RefKind is the GitHub Actions pin tier (sha|tag|branch).
	RefKind string `json:"refKind,omitempty"`
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
	Path    string `json:"path"`
	OldPath string `json:"oldPath,omitempty"`
	Status  string `json:"status"`
	Class   string `json:"class"`
	// Excluded is the SINGLE source of truth for review-surface exclusion
	// (binary or strongly-classified generated), so every "excluded" claim
	// in output uses the same definition ReviewFiles counted by.
	Excluded bool   `json:"excluded,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Added    int    `json:"added"`
	Removed  int    `json:"removed"`
	// Binary marks an opaque file git reports as -/- (zero line delta): its
	// change is invisible to line-based ranking, so it is ranked by BYTES
	// instead. BytesFrom/BytesTo are populated for binaries (0 for an absent
	// side), so an added .node/.wasm/executable can never hide behind 0 lines.
	Binary    bool  `json:"binary,omitempty"`
	BytesFrom int64 `json:"bytesFrom,omitempty"`
	BytesTo   int64 `json:"bytesTo,omitempty"`
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

// ActionSection is the GitHub Actions execution model + pinning: WHAT runs
// (using node/docker/composite, pre/post hooks) and how immutably it is
// pinned. Present only for the gha ecosystem.
type ActionSection struct {
	Pins      []ActionPin       `json:"pins"`
	UsingFrom string            `json:"usingFrom,omitempty"`
	UsingTo   string            `json:"usingTo,omitempty"`
	Exec      []manifest.Change `json:"exec,omitempty"`   // pre/post/main/image/using deltas
	Nested    []string          `json:"nested,omitempty"` // composite `uses:` (transitive)
	SubPath   string            `json:"subPath,omitempty"`
	// Caps are the runner powers the code references (grep, evadable lead);
	// CapsIntroduced is the subset NEW in this bump, the load-bearing delta.
	Caps           []string `json:"caps,omitempty"`
	CapsIntroduced []string `json:"capsIntroduced,omitempty"`
}

// ActionPin is one side's pin: the ref, its immutability tier, the commit.
type ActionPin struct {
	Side string `json:"side"` // from | to
	Ref  string `json:"ref"`
	Kind string `json:"kind"` // sha | tag | branch
	SHA  string `json:"sha"`
}

type Input struct {
	ToolVersion    string
	Pkg            PkgRef
	SubPath        string         // GHA sub-path action (owner/repo/SUB); scoping caveat
	OldAction      *ghapkg.Action // gha only
	NewAction      *ghapkg.Action
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
		Tool:      Tool{Name: "depsound", Version: in.ToolVersion, Schema: SchemaVersion},
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
		if src != nil && strings.HasPrefix(src.Verification, "tls-only") && in.Pkg.Ecosystem != "gha" {
			s.Notes = append(s.Notes, side+" artifact verified by TLS trust only (no registry integrity or checksum database record)")
		}
	}
	// GitHub Actions pinning: a tag is a MUTABLE pointer, the supply-chain
	// vector (tj-actions: re-pointed tags at a secret-dumping commit). Report
	// what each ref resolves to and push toward SHA pins.
	if in.Pkg.Ecosystem == "gha" {
		s.Action = buildAction(in)
		if in.SubPath != "" {
			s.Notes = append(s.Notes, fmt.Sprintf("scoped to the sub-path action %q; the action may still reference repo-level code outside it (not shown)", in.SubPath))
		}
		for _, a := range []*ghapkg.Action{in.OldAction, in.NewAction} {
			s.Notes = append(s.Notes, actionWarnings(a)...)
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
		s.Entrypoints = npmpkg.Entrypoints(in.NewPkg)

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

		// Review surface: exclude only CONFIDENTLY-generated (marker or
		// suffix) and binary files. Path-only "generated" files stay in,
		// because a hand-edit or hidden payload under dist/ must not be
		// silently dropped from the number a reviewer trusts.
		strongGen := res.Class == classify.Generated && res.Basis.Strong()
		excluded := d.Binary || strongGen

		e := FileEntry{
			Path: d.Path, OldPath: d.OldPath, Status: d.Status,
			Class: string(res.Class), Excluded: excluded, Added: d.Added, Removed: d.Removed,
			Binary: d.Binary,
		}
		// a binary's line delta is a git -/- (zero), so record byte sizes: the
		// only way an added/changed opaque payload can be ranked and named
		if d.Binary {
			e.BytesFrom, e.BytesTo = binaryBytes(in.OldTree, in.NewTree, d.OldPath, d.Path, d.Status)
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

		if excluded {
			if strongGen {
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

	// The excluded-file callout (heuristic disclosure, "attacker-writable
	// GUESS") is rendered once, in the files header, from FileEntry.Excluded,
	// the same definition ReviewFiles counted by. ExcludedGen stays in JSON
	// as the structured list; it is not re-narrated here.
	return s, nil
}

// buildAction assembles the GitHub Actions section: pins for both sides and,
// when action.yml parsed on both, the execution-model delta and composite
// nesting. Rendering (and the escalating pin warnings) live in output.
func buildAction(in Input) *ActionSection {
	sec := &ActionSection{
		SubPath: in.SubPath,
		Pins:    []ActionPin{pinOf("from", in.Pkg.From, in.SourceFrom), pinOf("to", in.Pkg.To, in.SourceTo)},
	}
	if in.OldAction != nil && in.NewAction != nil {
		sec.UsingFrom = in.OldAction.Using
		sec.UsingTo = in.NewAction.Using
		sec.Exec = ghapkg.ExecDelta(in.OldAction, in.NewAction)
		sec.Nested = in.NewAction.Uses
	}
	// what the executed code reaches (grep of the dist bundle + scripts):
	// present references and, crucially, which are NEW in this bump
	sec.Caps, sec.CapsIntroduced = ghapkg.CapabilityDelta(in.OldTree, in.NewTree)
	return sec
}

// pinOf classifies a ref into an ActionPin. The tier rides in Source.RefKind
// (resolved at fetch time); the ref-shape fallback covers sidecars written
// before RefKind existed.
func pinOf(side, ref string, src *Source) ActionPin {
	p := ActionPin{Side: side, Ref: ref}
	if src != nil {
		p.SHA = strings.TrimPrefix(src.Digest, "git-")
		p.Kind = src.RefKind
	}
	if p.Kind == "" {
		if isHexSHA(ref) {
			p.Kind = "sha"
		} else {
			p.Kind = "tag"
		}
	}
	return p
}

func actionWarnings(a *ghapkg.Action) []string {
	if a == nil {
		return nil
	}
	return a.Warnings
}

func isHexSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
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

// binaryBytes stats the old and new sizes of a binary file (0 for an absent
// side), so a byte delta exists where git reports a zero line delta.
func binaryBytes(oldTree, newTree, oldPath, path, status string) (from, to int64) {
	if status != "A" {
		op := oldPath
		if op == "" {
			op = path
		}
		if fi, err := os.Stat(filepath.Join(oldTree, op)); err == nil {
			from = fi.Size()
		}
	}
	if status != "D" {
		if fi, err := os.Stat(filepath.Join(newTree, path)); err == nil {
			to = fi.Size()
		}
	}
	return
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
