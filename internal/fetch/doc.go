// Package fetch downloads exactly the artifacts a package manager would
// install, directly from the registries over HTTPS, never invoking
// ecosystem tooling that could execute code. Every artifact is verified
// against registry integrity data before it enters the cache and is
// recorded with a provenance sidecar (source URL + digest); cache hits
// are rehashed on every use, so immutability is enforced, not assumed.
//
// One file per ecosystem: npm.go today, the Go module proxy and
// crates.io to follow.
package fetch
