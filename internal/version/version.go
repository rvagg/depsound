// Package version is the single source of the tool version and the one
// User-Agent used for every outbound request, so neither can drift.
package version

// Version is the tool version, bumped on release; it also gates workspace
// reuse and stamps stats.json.
const Version = "0.5.2"

// UserAgent is the sole User-Agent for all depvet HTTP requests, derived
// from Version so it can never disagree with it.
const UserAgent = "depvet/" + Version + " (+https://github.com/rvagg/depvet)"
