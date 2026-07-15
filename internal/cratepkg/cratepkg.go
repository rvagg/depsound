package cratepkg

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/rvagg/depsound/internal/manifest"
)

// Crate is the parsed Cargo.toml. crates.io publishes a NORMALIZED
// Cargo.toml (deps sorted, inline tables expanded), a gift for stable
// diffing; Cargo.toml.orig carries author intent but we read the
// normalized one for semantics.
type Crate struct {
	Edition     string
	RustVersion string
	ProcMacro   bool
	// BuildScript is the ACTIVE build-script path (crate-relative), or "" if
	// none. It honors package.build: a custom path, false (disabled even when
	// build.rs exists), or the default build.rs when present. This, not a bare
	// root-build.rs stat, is the execution surface.
	BuildScript string
	Features    map[string][]string
	Deps        map[string]string // name -> version req (rendered)
	DevDeps     map[string]string
	BuildDeps   map[string]string
	Warnings    []string
	dir         string
}

// rawManifest mirrors the subset of Cargo.toml we read. Dep values are
// either a bare version string or a table with version/path/git/package.
type rawManifest struct {
	Package struct {
		Edition     any    `toml:"edition"` // string, or {workspace=true}
		RustVersion string `toml:"rust-version"`
		Build       any    `toml:"build"` // a custom script PATH (string), or false to disable
	} `toml:"package"`
	Lib struct {
		ProcMacro bool `toml:"proc-macro"`
	} `toml:"lib"`
	Features     map[string][]string       `toml:"features"`
	Dependencies map[string]toml.Primitive `toml:"dependencies"`
	DevDeps      map[string]toml.Primitive `toml:"dev-dependencies"`
	BuildDeps    map[string]toml.Primitive `toml:"build-dependencies"`
}

func Load(dir string) (*Crate, error) {
	c := &Crate{dir: dir, Features: map[string][]string{}}
	b, err := os.ReadFile(filepath.Join(dir, "Cargo.toml"))
	if err != nil {
		// Every published crate MUST ship a Cargo.toml, so absence is
		// anomalous, not a benign old-format case (unlike Go's optional
		// go.mod): a malformed artifact, or a manifest our extractor
		// skipped as hostile. Report it as suspicious, don't swallow it.
		reason := "unreadable"
		if os.IsNotExist(err) {
			reason = "missing"
		}
		c.Warnings = append(c.Warnings, "Cargo.toml "+reason+
			"; every published crate must ship one, so this artifact is anomalous, treat with suspicion")
		return c, nil
	}
	var raw rawManifest
	md, err := toml.Decode(string(b), &raw)
	if err != nil {
		// Parses-not: either a format we don't understand or a crafted
		// manifest; either way we cannot vouch for its contents.
		c.Warnings = append(c.Warnings, "Cargo.toml present but unparseable, ignored (treat manifest-derived fields as unknown): "+err.Error())
		return c, nil
	}
	c.Edition = editionString(raw.Package.Edition)
	c.RustVersion = raw.Package.RustVersion
	c.ProcMacro = raw.Lib.ProcMacro
	c.BuildScript = resolveBuildScript(dir, raw.Package.Build)
	if c.BuildScript != "" && (filepath.IsAbs(c.BuildScript) || strings.HasPrefix(c.BuildScript, "..")) {
		c.Warnings = append(c.Warnings, "package.build points outside the crate ("+c.BuildScript+"): unusual, verify")
	}
	if raw.Features != nil {
		c.Features = raw.Features
	}
	c.Deps = renderDeps(md, raw.Dependencies)
	c.DevDeps = renderDeps(md, raw.DevDeps)
	c.BuildDeps = renderDeps(md, raw.BuildDeps)
	return c, nil
}

func editionString(v any) string {
	switch e := v.(type) {
	case string:
		return e
	default:
		return "" // {workspace=true} or absent
	}
}

// renderDeps flattens each dependency to a comparable string. A table dep
// renders its version plus any non-registry source (path/git) and a
// `package =` rename, both of which are review-relevant.
func renderDeps(md toml.MetaData, deps map[string]toml.Primitive) map[string]string {
	out := map[string]string{}
	for name, prim := range deps {
		var s string
		if md.PrimitiveDecode(prim, &s) == nil {
			out[name] = s
			continue
		}
		var t struct {
			Version string `toml:"version"`
			Path    string `toml:"path"`
			Git     string `toml:"git"`
			Package string `toml:"package"`
		}
		if md.PrimitiveDecode(prim, &t) != nil {
			out[name] = "?"
			continue
		}
		parts := []string{}
		if t.Version != "" {
			parts = append(parts, t.Version)
		}
		if t.Package != "" && t.Package != name {
			parts = append(parts, "package="+t.Package)
		}
		if t.Path != "" {
			parts = append(parts, "path")
		}
		if t.Git != "" {
			parts = append(parts, "git="+t.Git)
		}
		out[name] = strings.Join(parts, " ")
	}
	return out
}

// ConstraintsDelta reports forced-adjacency changes: edition and MSRV
// (rust-version), both of which propagate compile requirements to
// consumers. MSRV notably moves inside patch releases.
func ConstraintsDelta(a, b *Crate) []manifest.Change {
	var out []manifest.Change
	out = appendDelta(out, "edition", a.Edition, b.Edition)
	out = appendDelta(out, "rust-version (MSRV)", a.RustVersion, b.RustVersion)
	return out
}

// FeaturesDelta reports added/removed/changed feature flags; a changed
// default-feature set can silently alter what a consumer compiles. Keys
// are prefixed so they read distinctly among the compat constraints.
func FeaturesDelta(a, b *Crate) []manifest.Change {
	deltas := mapDelta(featureStrings(a.Features), featureStrings(b.Features))
	for i := range deltas {
		deltas[i].Key = "feature." + deltas[i].Key
	}
	return deltas
}

func featureStrings(f map[string][]string) map[string]string {
	out := map[string]string{}
	for k, v := range f {
		sorted := append([]string(nil), v...)
		sort.Strings(sorted)
		out[k] = strings.Join(sorted, ", ")
	}
	return out
}

// DepsDelta reports dependency changes across the three sections, with
// non-registry specs (path/git) flagged.
func DepsDelta(a, b *Crate) []manifest.DepChange {
	var out []manifest.DepChange
	sections := []struct {
		name       string
		oldM, newM map[string]string
	}{
		{"dependencies", a.Deps, b.Deps},
		{"dev-dependencies", a.DevDeps, b.DevDeps},
		{"build-dependencies", a.BuildDeps, b.BuildDeps},
	}
	for _, s := range sections {
		for _, c := range mapDelta(s.oldM, s.newM) {
			dc := manifest.DepChange{Section: s.name, Name: c.Key, Status: c.Status, From: c.From, To: c.To}
			if c.Status != "removed" {
				dc.Flag = flagFor(s.name, c.To)
			}
			out = append(out, dc)
		}
	}
	return out
}

// flagFor surfaces a redirected dependency: path/git bypass the registry;
// a `package =` alias in [dependencies] means the import resolves to a
// DIFFERENT crate than its name (the published redirect vector, since
// [patch]/[replace] are stripped on publish). Only [dependencies] is
// flagged for aliasing: dev/build aliases are common and benign (e.g.
// testing two versions of one crate) and do not reach consumers.
func flagFor(section, spec string) string {
	if f := specFlag(spec); f != "" {
		return f
	}
	if section == "dependencies" && strings.Contains(spec, "package=") {
		return "aliased to a different package name (import resolves to another crate; verify the target)"
	}
	return ""
}

// DepsPresent lists declared dependencies across sections (absolute/
// census form), with path/git/alias redirects flagged.
func DepsPresent(c *Crate) []manifest.DepChange {
	var out []manifest.DepChange
	sections := []struct {
		name string
		m    map[string]string
	}{{"dependencies", c.Deps}, {"dev-dependencies", c.DevDeps}, {"build-dependencies", c.BuildDeps}}
	for _, s := range sections {
		names := make([]string, 0, len(s.m))
		for n := range s.m {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			dc := manifest.DepChange{Section: s.name, Name: n, Status: "present", To: s.m[n]}
			if f := flagFor(s.name, s.m[n]); f != "" {
				dc.Flag = f
			}
			out = append(out, dc)
		}
	}
	return out
}

func specFlag(spec string) string {
	switch {
	case strings.Contains(spec, "path"):
		return "path dependency (local, bypasses the registry)"
	case strings.Contains(spec, "git="):
		return "git dependency (bypasses the registry)"
	}
	return ""
}

// HasBuildRS reports whether the crate ships a build.rs (a build script
// that runs at the consumer's compile time: the cargo analog of an npm
// install hook).
// HasBuildRS reports whether the crate runs a build script at the consumer's
// build time. It honors package.build, so a crate with build = "custom.rs" is
// caught (a root-build.rs stat would miss it) and one with build = false is not
// a false positive (build.rs may exist but is inert).
func (c *Crate) HasBuildRS() bool {
	return c.BuildScript != ""
}

// resolveBuildScript maps package.build to the active build-script path:
// false -> none (even if build.rs exists); a string -> that custom path; absent
// -> build.rs when it is present. A custom string is kept as configured (Cargo
// runs it regardless of whether the file resolves cleanly, so the execution
// surface exists); a suspicious path is flagged by the caller, not dropped.
func resolveBuildScript(dir string, build any) string {
	switch v := build.(type) {
	case bool:
		return "" // build = false: disabled
	case string:
		if v == "" {
			return ""
		}
		return filepath.Clean(v)
	default: // absent: default is build.rs if it exists
		if _, err := os.Stat(filepath.Join(dir, "build.rs")); err == nil {
			return "build.rs"
		}
		return ""
	}
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
