// Package gopkg analyses go.mod across two versions of a module and
// scans for cgo, the Go build-time execution surface.
package gopkg

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/rvagg/depvet/internal/manifest"
)

type Mod struct {
	File     *modfile.File
	Warnings []string
}

// Load parses dir/go.mod. Like the npm loader, it is forgiving: a
// missing or unparseable go.mod degrades to empty with a warning, since
// pre-modules artifacts exist and must still be analysable.
func Load(dir string) (*Mod, error) {
	p := filepath.Join(dir, "go.mod")
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &Mod{File: &modfile.File{}, Warnings: []string{"no go.mod in artifact"}}, nil
		}
		return nil, err
	}
	f, err := modfile.Parse("go.mod", b, nil)
	if err != nil {
		return &Mod{File: &modfile.File{}, Warnings: []string{fmt.Sprintf("go.mod unparseable, ignored: %v", err)}}, nil
	}
	return &Mod{File: f}, nil
}

// ConstraintsDelta reports forced-adjacency changes: the go directive
// (bumps propagate into consumers' go.mod), toolchain, and tool blocks.
func ConstraintsDelta(a, b *Mod) []manifest.Change {
	var out []manifest.Change
	out = appendDelta(out, "go directive", goVersion(a), goVersion(b))
	out = appendDelta(out, "toolchain", toolchain(a), toolchain(b))
	out = appendDelta(out, "tool block", tools(a), tools(b))
	return out
}

// RequireDelta reports direct requirement changes plus any replace
// directives, which bypass the module proxy and are always flagged.
func RequireDelta(a, b *Mod) []manifest.DepChange {
	var out []manifest.DepChange
	for _, c := range mapDelta(requires(a), requires(b)) {
		out = append(out, manifest.DepChange{
			Section: "require", Name: c.Key, Status: c.Status, From: c.From, To: c.To,
		})
	}
	for _, c := range mapDelta(replaces(a), replaces(b)) {
		dc := manifest.DepChange{
			Section: "replace", Name: c.Key, Status: c.Status, From: c.From, To: c.To,
			Flag: "replace directive bypasses the module proxy",
		}
		out = append(out, dc)
	}
	return out
}

func goVersion(m *Mod) string {
	if m.File.Go != nil {
		return m.File.Go.Version
	}
	return ""
}

func toolchain(m *Mod) string {
	if m.File.Toolchain != nil {
		return m.File.Toolchain.Name
	}
	return ""
}

func tools(m *Mod) string {
	var t []string
	for _, tool := range m.File.Tool {
		t = append(t, tool.Path)
	}
	sort.Strings(t)
	return strings.Join(t, ", ")
}

// requires maps DIRECT requirements only; indirect churn is lockfile
// noise at this layer.
func requires(m *Mod) map[string]string {
	out := map[string]string{}
	for _, r := range m.File.Require {
		if !r.Indirect {
			out[r.Mod.Path] = r.Mod.Version
		}
	}
	return out
}

func replaces(m *Mod) map[string]string {
	out := map[string]string{}
	for _, r := range m.File.Replace {
		v := r.New.Path
		if r.New.Version != "" {
			v += "@" + r.New.Version
		}
		// key includes Old.Version so version-specific replaces of the
		// same path do not alias
		k := r.Old.Path
		if r.Old.Version != "" {
			k += "@" + r.Old.Version
		}
		out[k] = v
	}
	return out
}

// cgoImport matches both forms, with or without a trailing comment:
// import "C" and a bare "C" line inside an import block.
var cgoImport = regexp.MustCompile(`(?m)^\s*(?:import\s+)?"C"\s*(?://.*)?$`)

// ScanCgo reports whether any .go file in the tree imports "C". cgo
// means C compilation at the consumer's build time, the Go analog of a
// build script, so a false negative is the expensive direction: files
// are read WHOLE, because the cgo preamble comment above import "C"
// carries the C code and routinely exceeds any head-bytes bound.
func ScanCgo(root string) bool {
	found := false
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found {
			return filepath.SkipAll
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		if cgoImport.Match(b) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func appendDelta(out []manifest.Change, key, from, to string) []manifest.Change {
	switch {
	case from == to:
		return out
	case from == "":
		return append(out, manifest.Change{Key: key, Status: "added", To: to})
	case to == "":
		return append(out, manifest.Change{Key: key, Status: "removed", From: from})
	default:
		return append(out, manifest.Change{Key: key, Status: "changed", From: from, To: to})
	}
}

func mapDelta(a, b map[string]string) []manifest.Change {
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var out []manifest.Change
	for _, k := range sorted {
		out = appendDelta(out, k, a[k], b[k])
	}
	return out
}
