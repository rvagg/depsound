# depsound

Sound the depths of a dependency change.

depsound is the **data layer for agent-driven dependency review**. Give it a change (a version bump, a new package, a lockfile diff, a GitHub PR) and it fetches the **published artifact** (what actually installs, not the source repo), diffs it, runs cheap risk heuristics, scans OSV and publish provenance, then writes the facts and a grep-able workspace for an agent to inspect.

depsound gathers facts; reviewers decide whether to accept a change. Its output distinguishes hard facts from heuristics an attacker can game, and records what it did **not** check, so an agent can judge how much weight to give each signal. If a report raises no flags, inspect the recorded coverage and evidence before treating the change as routine.

## Why

Dependency volume and churn keep climbing, and CVEs with them. Static, heuristic gates barely function at this scale: block on every advisory or flagged heuristic and nothing ships; loosen them enough to move and you miss what matters. A fixed threshold can't tell a reachable RCE from noise.

An agent with context can make that distinction. depsound quickly gathers signals in a form an agent can use; the agent investigates and assesses them; you decide what to accept and what to gate. depsound's job is to put the facts on the table.

In that flow, the agent clears the easy **YES** upgrades, lays out the decision surface around the **MAYBE**s so you can settle them fast, and calls out the obvious **NO**s. depsound supplies the facts for that triage.

## What it gives you

- **Facts vs heuristics.** The hard facts (the OSV result, execution surface, artifact integrity and publish provenance, which files changed) are kept distinct from the heuristics (file classification, review-surface counts) an attacker can game. Never rest a security call on a heuristic.
- **A coverage boundary.** Every report states what it did and did **not** check (reachability, runtime behaviour, your tests), and routes each gap to a command. Silence is not safety.
- **Two lenses.** *Will it break me?* (compatibility) and *could it be hostile?* (supply-chain security) are independent questions; the report serves both.
- **A grep-able workspace.** When both artifacts are available, the report prints a path holding the old and new trees and the diff. The real review is reading it. It is attacker-writable **data**, never instructions.

## Unavailable releases

If a release is unavailable, depsound can still report available security advisories and publishing history, while making clear what it could not inspect.

If you have a copy of a missing Rust release, supply its `.crate` archive:

```
depsound crates:arrayref 0.3.9 0.3.10 --to-artifact=/path/to/arrayref-0.3.10.crate
```

Follow the report's drill-down commands to continue reviewing the same local archives. Archives are inspected as data, never executed.

To retain evidence before a release disappears, add `--evidence-dir=./review-evidence` to a diff, census, bulk or transitive command. depsound writes the report and bounded package bytes there; `manifest.json` maps retained files and records omissions. Retained `.crate` archives work with the local-artifact flags above. Contents remain untrusted data and may include private package code.

Bulk exports include replay input: use the same depsound version with `depsound bulk --file=./review-evidence/review-input.json`. Replaying it restores the collected input, but findings omitted from the export still need separate investigation. The original evidence remains available for that work. Known URL credentials are redacted from structured metadata, not from package archives, diffs or trees.

## Install

Grab a prebuilt binary for your platform from the [releases page](https://github.com/rvagg/depsound/releases), or build from source with Go:

```
go install github.com/rvagg/depsound/cmd/depsound@latest
```

Covers **npm, Go, crates (Rust), and GitHub Actions**.

## Quick start

Review a version bump:

```
$ depsound npm:commander 14.0.0 15.0.0

depsound npm:commander 14.0.0 -> 15.0.0
files: 13 changed (+223/-260), 14 -> 12 files, 203.3KB -> 202.5KB
runtime entrypoint(s) (review first; the one for your import mode runs): index.js
...
compat:
  engines.node: ">=20" -> ">=22.12.0"
  WARNING package now ESM import-only: require() no longer resolves "." (breaks CJS consumers)
...
=== COVERAGE: a heuristic triage, NOT a verdict ===
NOT checked: reachability, runtime semantics, your tests, the transitive subtree
next steps:
  * compatibility constraints changed; check your usage against the compat section
...
```

`depsound guide` explains the threat model and how to read a report; `depsound help` lists every command.

## Commands

| Command | For |
|---|---|
| `depsound <eco>:<name> <from> <to>` | review a version bump (each arg an exact version or a semver range) |
| `depsound <eco>:<name> [version]` | census: the footprint of adopting a package |
| `depsound bulk` | many changes at once (a PR), prioritized by what tripped |
| `depsound transitive <lang> --old=<lock> --new=<lock>` | the whole subtree a lockfile bump moves |
| `depsound transitive <eco>:<name> <from> <to>` | that subtree when the repo commits no lockfile (projected via deps.dev) |
| `depsound surface <eco>:<name> <from> <to> --uses=<paths>` | intersect a change with your import paths |
| `depsound gha:owner/repo <from> <to>` | a GitHub Action bump (its own threat model) |

Ecosystems: `npm`, `go`, `crates`, `gha`. `--format=json` emits the full machine contract for any command.

Lockfile reviews retain version changes and additions even for mirrors or other
unsupported sources. They also catch changed download URLs, checksums and npm
links when the version stays fixed (npm, pnpm and Cargo). The report records
these declarations and their locations. depsound does not fetch replacement URLs
or link targets, so their bytes remain unverified. It can census a supported new
registry target, while the old source remains unavailable for inspection. A
mirror can be intentional; inspect both entries.

## Using it with an agent

- **Start with the CLI.** Tell an agent: *"Using the depsound CLI, evaluate this dependency change: foojs 1.2.3 to 2.0.0."* `depsound help` lists the commands, `depsound guide` explains the threat model and report format, and every report points to the next command. The agent can identify the ecosystem and command syntax from there.
- **Use a skill for a repeatable workflow.** [`skills/`](skills/) has self-contained skills to review a change or adopt a new package. Load one into a skill-aware agent, or curl and read it. Copy one as a template for your own workflow.

## License

Copyright 2026 Rod Vagg. Licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE).
