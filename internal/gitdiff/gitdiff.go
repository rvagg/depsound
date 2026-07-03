// Package gitdiff shells out to git diff --no-index over two extracted
// trees. git is a documented external dependency: its rename detection and
// function-context hunk headers are battle-tested and not worth reimplementing.
package gitdiff

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type FileDiff struct {
	Path    string // new-side path (old-side for deletions), tree-relative
	OldPath string // set only for real renames
	Status  string // A, M, D, R
	Added   int
	Removed int
	Binary  bool
}

// Diff compares dir/oldName against dir/newName and writes the full patch
// to patchPath. Paths in the result are relative to the tree roots.
func Diff(dir, oldName, newName, patchPath string) ([]FileDiff, error) {
	raw, err := run(dir, "diff", "--no-index", "--no-ext-diff", "-M", "--raw", "-z", oldName, newName)
	if err != nil {
		return nil, err
	}
	num, err := run(dir, "diff", "--no-index", "--no-ext-diff", "-M", "--numstat", "-z", oldName, newName)
	if err != nil {
		return nil, err
	}
	patch, err := run(dir, "diff", "--no-index", "--no-ext-diff", "-M", oldName, newName)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(patchPath, patch, 0o644); err != nil {
		return nil, err
	}

	diffs, err := parseRaw(raw, oldName, newName)
	if err != nil {
		return nil, err
	}
	if err := applyNumstat(diffs, num); err != nil {
		return nil, err
	}
	return diffs, nil
}

func run(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-c", "core.quotePath=false", "-c", "core.autocrlf=false"}, args...)...)
	cmd.Dir = dir
	// Pin the invocation environment. Repo discovery would let in-tree
	// .gitattributes gate output ("*.js -diff" renders a payload as
	// "Binary files differ" and flips the exit code) whenever the
	// workspace sits under any git repo; user/system config could alter
	// rendering the parser relies on.
	cmd.Env = append(os.Environ(),
		"GIT_DIR="+os.DevNull,
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_SYSTEM="+os.DevNull,
	)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		// exit 1 just means the trees differ
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return out.Bytes(), nil
		}
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, errb.String())
	}
	return out.Bytes(), nil
}

// parseRaw parses `--raw -z` output: ":oldmode newmode oldsha newsha S\0path\0"
// with a second path for R/C entries.
func parseRaw(out []byte, oldName, newName string) ([]FileDiff, error) {
	parts := splitNul(out)
	var diffs []FileDiff
	for i := 0; i < len(parts); i++ {
		meta := parts[i]
		if meta == "" {
			continue
		}
		if !strings.HasPrefix(meta, ":") {
			return nil, fmt.Errorf("unexpected raw diff entry %q", meta)
		}
		fields := strings.Fields(meta[1:])
		if len(fields) < 5 {
			return nil, fmt.Errorf("short raw diff entry %q", meta)
		}
		status := fields[4][:1]
		var src, dst string
		switch status {
		case "R", "C":
			if i+2 >= len(parts) {
				return nil, fmt.Errorf("truncated raw diff after %q", meta)
			}
			src, dst = parts[i+1], parts[i+2]
			i += 2
		default:
			if i+1 >= len(parts) {
				return nil, fmt.Errorf("truncated raw diff after %q", meta)
			}
			src = parts[i+1]
			dst = src
			i++
		}
		d := normalize(status, src, dst, oldName, newName)
		diffs = append(diffs, d)
	}
	return diffs, nil
}

// normalize strips the tree-root prefixes and collapses --no-index's
// whole-tree "rename" framing (old/x -> new/x) back to a modification.
// M entries carry only the old-side path, so both roots are tried.
func normalize(status, src, dst, oldName, newName string) FileDiff {
	relSrc := stripRoot(stripRoot(src, oldName), newName)
	relDst := stripRoot(stripRoot(dst, newName), oldName)
	d := FileDiff{Status: status, Path: relDst}
	switch status {
	case "A":
		d.Path = relDst
	case "D":
		d.Path = relSrc
	case "R", "C":
		if relSrc == relDst {
			d.Status = "M"
		} else {
			d.Status = "R"
			d.OldPath = relSrc
		}
	}
	return d
}

func stripRoot(p, root string) string {
	p = strings.TrimPrefix(p, root+"/")
	return p
}

// applyNumstat fills Added/Removed/Binary from `--numstat -z` output:
// "added\tremoved\tpath\0" or, for renames, "added\tremoved\t\0src\0dst\0".
// Entries arrive in the same order as --raw output.
func applyNumstat(diffs []FileDiff, out []byte) error {
	parts := splitNul(out)
	idx := 0
	for i := 0; i < len(parts); i++ {
		p := parts[i]
		if p == "" {
			continue
		}
		fields := strings.SplitN(p, "\t", 3)
		if len(fields) != 3 {
			return fmt.Errorf("unexpected numstat entry %q", p)
		}
		if fields[2] == "" { // rename form: paths follow as two NUL fields
			if i+2 >= len(parts) {
				return fmt.Errorf("truncated numstat after %q", p)
			}
			i += 2
		}
		if idx >= len(diffs) {
			return fmt.Errorf("numstat has more entries than raw diff")
		}
		d := &diffs[idx]
		idx++
		if fields[0] == "-" { // binary
			d.Binary = true
			continue
		}
		added, err1 := strconv.Atoi(fields[0])
		removed, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("bad numstat counts in %q", p)
		}
		d.Added, d.Removed = added, removed
	}
	if idx != len(diffs) {
		return fmt.Errorf("numstat entries (%d) != raw entries (%d)", idx, len(diffs))
	}
	return nil
}

func splitNul(b []byte) []string {
	return strings.Split(string(b), "\x00")
}
