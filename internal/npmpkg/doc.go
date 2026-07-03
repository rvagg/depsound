// Package npmpkg analyses package.json across two versions of a package.
//
// npmpkg.go: manifest loading and keyed deltas: lifecycle scripts (the
// install-time execution surface), bin entries, engines, and dependency
// changes with non-registry specs (git/url/file) flagged.
//
// exports.go: module-format compatibility via a resolution table rather
// than package classification: the specified Node resolution algorithm
// runs against both versions' export maps (object key order preserved,
// because it changes resolution) and the outcomes are diffed, turning
// "is this package ESM or CJS" into precise per-subpath rows like
// "require of . resolved to ./index.js (cjs), now ./index.js (esm)".
package npmpkg
