// Package osv queries the OSV.dev vulnerability database for a package
// version and assesses an upgrade: which vulnerabilities the bump fixes,
// which it leaves in place, and which it introduces. Results are advisory
// snapshots (OSV lags real advisories), never a gate: depvet informs, it
// does not block.
package osv
