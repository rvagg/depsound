package surface

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

type Index struct {
	Files []FileSurface `json:"files"`
}

type FileSurface struct {
	Path    string `json:"path"`
	OldPath string `json:"oldPath,omitempty"`
	Binary  bool   `json:"binary,omitempty"`
	Hunks   []Hunk `json:"hunks,omitempty"`
	// PatchLine is where this file's "diff --git" header sits in
	// diff.patch (1-based), for targeted extraction.
	PatchLine int `json:"patchLine"`
	// Class is enriched at query time from stats (not persisted in the
	// index), so surface can separate the source a consumer compiles
	// from test/docs/generated noise.
	Class string `json:"class,omitempty"`
}

type Hunk struct {
	OldStart  int    `json:"oldStart"`
	OldLines  int    `json:"oldLines"`
	NewStart  int    `json:"newStart"`
	NewLines  int    `json:"newLines"`
	Symbol    string `json:"symbol,omitempty"` // attacker-influenced; taint when rendering
	PatchLine int    `json:"patchLine"`
}

var hunkRe = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@ ?(.*)$`)

// Parse builds the index from a git --no-index patch whose trees were
// rooted at oldName/ and newName/.
func Parse(patchPath, oldName, newName string) (*Index, error) {
	b, err := os.ReadFile(patchPath)
	if err != nil {
		return nil, err
	}
	idx := &Index{}
	var cur *FileSurface
	lineNo := 0
	for line := range bytes.Lines(b) {
		lineNo++
		switch {
		case bytes.HasPrefix(line, []byte("diff --git ")):
			// format: diff --git a/<p1> b/<p2>; split on " b/" (paths
			// with a literal " b/" substring would confuse this; hunk
			// content is unaffected either way)
			rest := strings.TrimPrefix(strings.TrimSuffix(string(line), "\n"), "diff --git ")
			a, bside, ok := strings.Cut(rest, " b/")
			if !ok {
				continue
			}
			oldP := stripRoot(strings.TrimPrefix(a, "a/"), oldName, newName)
			newP := stripRoot(bside, newName, oldName)
			fs := FileSurface{Path: newP, PatchLine: lineNo}
			if oldP != newP {
				fs.OldPath = oldP
			}
			idx.Files = append(idx.Files, fs)
			cur = &idx.Files[len(idx.Files)-1]
		case bytes.HasPrefix(line, []byte("Binary files ")):
			if cur != nil {
				cur.Binary = true
			}
		case bytes.HasPrefix(line, []byte("@@ ")):
			if cur == nil {
				continue
			}
			m := hunkRe.FindStringSubmatch(strings.TrimSuffix(string(line), "\n"))
			if m == nil {
				continue
			}
			h := Hunk{
				OldStart:  atoi(m[1]),
				OldLines:  atoiDefault(m[2], 1),
				NewStart:  atoi(m[3]),
				NewLines:  atoiDefault(m[4], 1),
				Symbol:    strings.TrimSpace(m[5]),
				PatchLine: lineNo,
			}
			cur.Hunks = append(cur.Hunks, h)
		}
	}
	return idx, nil
}

func stripRoot(p, primary, secondary string) string {
	p = strings.TrimPrefix(p, primary+"/")
	p = strings.TrimPrefix(p, secondary+"/")
	return p
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	return atoi(s)
}

// DirRollup aggregates by directory prefix at the given depth, so a
// consumer can see at a glance which areas of a sprawling module a
// release concentrates in.
type DirStat struct {
	Dir     string   `json:"dir"`
	Files   int      `json:"files"`
	Hunks   int      `json:"hunks"`
	Symbols []string `json:"symbols,omitempty"`
}

func (idx *Index) DirRollup(depth int) []DirStat {
	agg := map[string]*DirStat{}
	for _, f := range idx.Files {
		segs := strings.Split(f.Path, "/")
		d := min(depth, len(segs)-1)
		dir := "."
		if d > 0 {
			dir = strings.Join(segs[:d], "/")
		}
		a := agg[dir]
		if a == nil {
			a = &DirStat{Dir: dir}
			agg[dir] = a
		}
		a.Files++
		a.Hunks += len(f.Hunks)
	}
	out := make([]DirStat, 0, len(agg))
	for _, a := range agg {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Files > out[j].Files })
	return out
}

// Unit statuses. "No result" has several meanings with different weights;
// only noChangedFiles is a positive all-clear, and subpackagesOnly is NOT
// a match for the unit itself.
const (
	StatusMatched         = "matched"
	StatusSubpackagesOnly = "subpackagesOnly"
	StatusNoChangedFiles  = "noChangedFiles"
	StatusUnmapped        = "unmapped"
	StatusOutOfScope      = "outOfScope"
)

type UnitResult struct {
	Unit     string   `json:"unit"`
	Status   string   `json:"status"`
	Prefixes []string `json:"resolvedPrefixes,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	// Files changed in the unit's OWN package (or, for path semantics,
	// its subtree). Descendants changed in packages nested below it,
	// which the consumer may or may not import.
	Files       []FileSurface `json:"files,omitempty"`
	Descendants []FileSurface `json:"descendants,omitempty"`
}

// Match filters the index by tree-path prefixes. With packageDirs (Go,
// where a package IS a directory), a changed file counts as the unit only
// if its directory equals the prefix; files in nested directories are
// DESCENDANT packages, reported separately because importing a package
// does not import its subpackages. Without packageDirs (npm/path
// semantics) the whole subtree is the unit.
func (idx *Index) Match(unit string, prefixes []string, packageDirs bool) UnitResult {
	r := UnitResult{Unit: unit, Prefixes: prefixes}
	if len(prefixes) == 0 {
		r.Status = StatusUnmapped
		return r
	}
	for _, f := range idx.Files {
		for _, p := range prefixes {
			own, desc := matchKind(f.Path, p, packageDirs)
			if own {
				r.Files = append(r.Files, f)
				break
			}
			if desc {
				r.Descendants = append(r.Descendants, f)
				break
			}
		}
	}
	switch {
	case len(r.Files) > 0:
		r.Status = StatusMatched
	case len(r.Descendants) > 0:
		r.Status = StatusSubpackagesOnly
	default:
		r.Status = StatusNoChangedFiles
	}
	return r
}

// matchKind decides whether a changed file is in the unit's own package,
// a descendant package, or unrelated.
func matchKind(filePath, prefix string, packageDirs bool) (own, descendant bool) {
	prefix = strings.Trim(prefix, "/")
	root := prefix == "" || prefix == "."

	if !packageDirs {
		// path semantics: exact file or anything in the subtree is "own"
		if root || filePath == prefix || strings.HasPrefix(filePath, prefix+"/") {
			return true, false
		}
		return false, false
	}

	// package-dir semantics: compare the file's directory to the prefix
	dir := ""
	if i := strings.LastIndex(filePath, "/"); i >= 0 {
		dir = filePath[:i]
	}
	if root {
		return dir == "", dir != ""
	}
	switch {
	case dir == prefix, filePath == prefix:
		return true, false
	case strings.HasPrefix(dir, prefix+"/"):
		return false, true
	}
	return false, false
}

// SymbolHunks returns files filtered to hunks matching sub
// (case-insensitive) in the enclosing-symbol header OR the hunk body. The
// body scan matters because git's function-context header names the
// ENCLOSING declaration, so a change to `func bindText` at its own
// signature line is attributed to the preceding symbol; scanning the body
// catches the definition itself. patch may be nil to match headers only.
func (idx *Index) SymbolHunks(patch []byte, sub string) []FileSurface {
	lower := strings.ToLower(sub)
	var lines [][]byte
	var bounds marks
	if patch != nil {
		lines = splitKeepNewlines(patch)
		bounds = idx.boundaries(len(lines))
	}

	var out []FileSurface
	for _, f := range idx.Files {
		var hits []Hunk
		for _, h := range f.Hunks {
			match := strings.Contains(strings.ToLower(h.Symbol), lower)
			if !match && patch != nil {
				body := section(lines, h.PatchLine, bounds.next(h.PatchLine))
				match = bytes.Contains(bytes.ToLower(body), []byte(lower))
			}
			if match {
				hits = append(hits, h)
			}
		}
		if len(hits) > 0 {
			c := f
			c.Hunks = hits
			out = append(out, c)
		}
	}
	return out
}

// Attributed reports how many hunks carry a symbol, the index's own
// honesty metric (101/103 on the sqlite amalgamation).
func (idx *Index) Attributed() (with, total int) {
	for _, f := range idx.Files {
		for _, h := range f.Hunks {
			total++
			if h.Symbol != "" {
				with++
			}
		}
	}
	return with, total
}

func (idx *Index) String() string {
	w, t := idx.Attributed()
	return fmt.Sprintf("%d files, %d hunks (%d symbol-attributed)", len(idx.Files), t, w)
}
