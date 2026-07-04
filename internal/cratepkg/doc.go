// Package cratepkg analyses Cargo.toml across two versions of a crate:
// compatibility constraints (edition, MSRV, features), dependency deltas,
// and the build-time execution surface (build.rs, proc-macro). It reads
// the registry-normalized manifest crates.io publishes (deps sorted,
// inline tables expanded), which makes semantic diffing stable.
package cratepkg
