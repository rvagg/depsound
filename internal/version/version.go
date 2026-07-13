// Package version reports the tool version and the sole outbound User-Agent.
// The version number lives in exactly one place, version.json (which also
// drives the release tag); this package DERIVES from that tag rather than
// keeping a second hardcoded copy that could drift. Release binaries get it
// from the linker; `go install ...@version` reads it from the recorded module
// version; a local build reports "dev".
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
	v := version
	if v == "" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version
		}
	}
	if v == "" {
		v = "dev"
	}
	return strings.TrimPrefix(v, "v")
}
