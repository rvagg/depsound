// Package stats defines depvet's report schema (the contract consumed by
// agents) and assembles it from the diff, the trees and the manifests.
package stats

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rvagg/depvet/internal/classify"
	"github.com/rvagg/depvet/internal/gitdiff"
	"github.com/rvagg/depvet/internal/npmpkg"
)

const SchemaVersion = 1

type Stats struct {
	Tool         Tool               `json:"tool"`
	Package      PkgRef             `json:"package"`
	Artifact     Artifact           `json:"artifact"`
	Runnable     Runnable           `json:"runnable"`
	Compat       Compat             `json:"compat"`
	Dependencies []npmpkg.DepChange `json:"dependencies"`
	Files        FilesSection       `json:"files"`
	Security     Security           `json:"security"`
	Workspace    string             `json:"workspace"`
	Notes        []string           `json:"notes,omitempty"`
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
}

type Runnable struct {
	Lifecycle []npmpkg.Change `json:"lifecycle"`
	Bin       []npmpkg.Change `json:"bin"`
	GypFrom   bool            `json:"nodeGypFrom"`
	GypTo     bool            `json:"nodeGypTo"`
}

type Compat struct {
	TypeFrom string                `json:"typeFrom,omitempty"`
	TypeTo   string                `json:"typeTo,omitempty"`
	Engines  []npmpkg.Change       `json:"engines"`
	Exports  []npmpkg.ExportChange `json:"exports"`
}

type Security struct {
	Queried bool   `json:"queried"`
	Note    string `json:"note,omitempty"`
}

type FilesSection struct {
	Changed      int         `json:"changed"`
	Added        int         `json:"linesAdded"`
	Removed      int         `json:"linesRemoved"`
	ByClass      []ClassAgg  `json:"byClass"`
	TrivialChurn int         `json:"trivialChurn"` // changed files with <=2 line delta
	Flagged      []Flag      `json:"flagged"`
	Entries      []FileEntry `json:"entries"`
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
	OldPkg         *npmpkg.Package
	NewPkg         *npmpkg.Package
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
		Security:  Security{Queried: false, Note: "OSV integration pending"},
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
	s.Compat.Engines = npmpkg.EnginesDelta(in.OldPkg, in.NewPkg)
	s.Compat.Exports, err = npmpkg.ExportsDelta(in.OldPkg, in.NewPkg)
	if err != nil {
		s.Notes = append(s.Notes, "exports resolution failed: "+err.Error())
	}

	s.Dependencies = npmpkg.DepsDelta(in.OldPkg, in.NewPkg)

	agg := map[string]*ClassAgg{}
	for _, d := range in.Diffs {
		head := readHead(in.NewTree, in.OldTree, d)
		res := classify.File(d.Path, head, d.Binary)

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
	return s, nil
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
