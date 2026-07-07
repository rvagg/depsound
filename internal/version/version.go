// Package version is the single source of the tool version and the one
// User-Agent used for every outbound request, so neither can drift.
package version

// Version is the tool version, bumped on release; it also gates workspace
// reuse and stamps stats.json.
const Version = "0.13.0"

// UserAgent is the sole User-Agent for all depsound HTTP requests, derived
// from Version so it can never disagree with it.
const UserAgent = "depsound/" + Version + " (+https://github.com/rvagg/depsound)"
