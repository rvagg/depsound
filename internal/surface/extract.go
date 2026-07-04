package surface

import (
	"bytes"
	"sort"
)

// Extract slices raw patch text for the selected files. When a selected
// file carries a filtered hunk subset (symbol queries), only those hunks
// are emitted under the file's header; otherwise the whole file section
// is emitted. Output is verbatim patch bytes: untrusted content in
// trusted framing, kept valid for tooling that reads unified diffs.
func (idx *Index) Extract(patch []byte, sel []FileSurface) []byte {
	lines := splitKeepNewlines(patch)
	bounds := idx.boundaries(len(lines))

	var out bytes.Buffer
	for _, f := range sel {
		full := idx.fileByPath(f.Path)
		if full == nil {
			continue
		}
		if len(f.Hunks) == len(full.Hunks) || len(f.Hunks) == 0 {
			// whole file section: header through last hunk
			out.Write(section(lines, f.PatchLine, bounds.nextFile(f.PatchLine)))
			continue
		}
		// header lines (diff --git, index, ---, +++) then selected hunks
		headerEnd := bounds.next(f.PatchLine)
		out.Write(section(lines, f.PatchLine, headerEnd))
		for _, h := range f.Hunks {
			out.Write(section(lines, h.PatchLine, bounds.next(h.PatchLine)))
		}
	}
	return out.Bytes()
}

func (idx *Index) fileByPath(p string) *FileSurface {
	for i := range idx.Files {
		if idx.Files[i].Path == p {
			return &idx.Files[i]
		}
	}
	return nil
}

type marks struct {
	all   []int // every file header and hunk start, sorted, plus sentinel
	files []int // file headers only, sorted, plus sentinel
}

func (idx *Index) boundaries(totalLines int) marks {
	m := marks{}
	for _, f := range idx.Files {
		m.all = append(m.all, f.PatchLine)
		m.files = append(m.files, f.PatchLine)
		for _, h := range f.Hunks {
			m.all = append(m.all, h.PatchLine)
		}
	}
	sentinel := totalLines + 1
	m.all = append(m.all, sentinel)
	m.files = append(m.files, sentinel)
	sort.Ints(m.all)
	sort.Ints(m.files)
	return m
}

func (m marks) next(after int) int     { return firstGreater(m.all, after) }
func (m marks) nextFile(after int) int { return firstGreater(m.files, after) }

func firstGreater(sorted []int, v int) int {
	i := sort.SearchInts(sorted, v+1)
	return sorted[i]
}

// section returns lines [from, to) as bytes; line numbers are 1-based.
func section(lines [][]byte, from, to int) []byte {
	if from < 1 {
		from = 1
	}
	if to > len(lines)+1 {
		to = len(lines) + 1
	}
	var b bytes.Buffer
	for i := from; i < to; i++ {
		b.Write(lines[i-1])
	}
	return b.Bytes()
}

func splitKeepNewlines(b []byte) [][]byte {
	var lines [][]byte
	for line := range bytes.Lines(b) {
		lines = append(lines, line)
	}
	return lines
}
