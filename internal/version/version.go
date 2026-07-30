// Package version reports the tool version and the sole outbound User-Agent.
// The version number lives in exactly one place, version.json (which also
// drives the release tag); this package DERIVES from that tag rather than
// keeping a second hardcoded copy that could drift. Release binaries get it
// from the linker; `go install ...@version` reads it from the recorded module
// version; anything else is a working-tree build and says so.
package version

import (
	"runtime/debug"
	"strings"
)

// version is injected by goreleaser on release builds:
//
//	-X github.com/rvagg/depsound/internal/version.version={{ .Version }}
var version string

// Version is the tool version, normalized without a leading "v". It gates
// workspace reuse and stamps stats.json.
var Version = resolve()

// UserAgent is the sole User-Agent for all depsound HTTP requests, derived
// from Version so it can never disagree with it.
var UserAgent = "depsound/" + Version + " (+https://github.com/rvagg/depsound)"

func resolve() string {
	if version != "" {
		return strings.TrimPrefix(version, "v")
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi.Main.Version == "" {
		return "dev"
	}
	return fromBuildInfo(bi.Main.Version, vcsRevision(bi))
}

// fromBuildInfo turns a recorded module version into what this build should
// call itself. A released module version (go install ...@vX.Y.Z) is used as
// given. Anything else is a working-tree build: since Go 1.24 those carry a
// VCS-derived PSEUDO-version, which names a release that does not exist (the
// tag after the newest one reachable), so reporting it verbatim would stamp
// stats.json and the User-Agent with a version nobody can fetch. Report dev
// and keep the commit, which is the part with any evidentiary value.
func fromBuildInfo(modVersion, revision string) string {
	v := strings.TrimPrefix(modVersion, "v")
	if v == "(devel)" || isPseudo(v) {
		if len(revision) >= 7 {
			return "dev-" + revision[:7]
		}
		return "dev"
	}
	return v
}

// isPseudo recognises the shapes Go gives a build that is not at a release
// tag: a pseudo-version (a -0.<timestamp>-<commit> or -<timestamp>-<commit>
// suffix) and the +dirty marker for uncommitted changes.
func isPseudo(v string) bool {
	if strings.Contains(v, "+dirty") {
		return true
	}
	base, pre, ok := strings.Cut(v, "-")
	if !ok || base == "" {
		return false
	}
	// a pseudo-version's prerelease ends in <14-digit timestamp>-<12-hex>
	fields := strings.Split(pre, "-")
	if len(fields) < 2 {
		return false
	}
	stamp, commit := fields[len(fields)-2], fields[len(fields)-1]
	// the stamp field carries a counter prefix when the base tag is a release
	// ("-0.<timestamp>") or a prerelease ("-rc.1.0.<timestamp>")
	if i := strings.LastIndex(stamp, "."); i >= 0 {
		stamp = stamp[i+1:]
	}
	return len(stamp) == 14 && allDigits(stamp) && len(commit) == 12 && allHex(commit)
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func allHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// vcsRevision is the commit Go records for a VCS-stamped build, "" when it
// recorded none.
func vcsRevision(bi *debug.BuildInfo) string {
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return ""
}
