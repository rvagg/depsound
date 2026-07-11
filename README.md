# depsound

Sound the depths of a dependency change.

depsound is the **data layer for agent-driven dependency review**. Give it a change (a version bump, a new package, a lockfile diff, a GitHub PR) and it fetches the **published artifact** (what actually installs, not the source repo), diffs it, runs cheap risk heuristics, scans OSV and publish-provenance, and lays out organized facts plus a grep-able workspace for an agent to judge.

It gathers; it does not verdict. The output is **built for, and tuned for, AI context ingestion**. Every report marks which signals are hard facts versus gameable heuristics, and states what it did **not** check, so an agent knows exactly how far to trust each one. "No flags" is a starting point, never an all-clear.

## Why

Dependency volume and churn keep climbing, and CVEs with them. Static, heuristic gates barely function at this scale: block on every advisory or flagged heuristic and nothing ships; loosen them enough to move and you miss what matters. A fixed threshold can't tell a reachable RCE from noise.

An agent with context can. The model is layered: depsound is the fast, dumb bottom, surfacing signal in agent-friendly form; the agent above it has tools and some judgement to turn that signal into an assessment; you sit at the top, deciding how much rope to give the agent and how much to gate yourself. The decision bubbles up to whoever you choose to hold it. depsound's job is only to put the facts on the table.

The flow it's tuned for: the agent clears the easy **YES** upgrades, lays out the decision surface around the **MAYBE**s so you settle them fast, and is loud about the obvious **NO**s. depsound feeds that triage with facts, not verdicts.

## What it gives you

- **Facts vs heuristics.** The hard facts (the OSV result, execution surface, artifact integrity and publish provenance, which files changed) are kept distinct from the heuristics (file classification, review-surface counts) an attacker can game. Never rest a security call on a heuristic.
- **A coverage boundary.** Every report states what it did and did **not** check (reachability, runtime behaviour, your tests), and routes each gap to a command. Silence is not safety.
- **Two lenses.** *Will it break me?* (compatibility) and *could it be hostile?* (supply-chain security) are independent questions; the report serves both.
- **A grep-able workspace.** Each report prints a path holding the old and new trees and the diff. The real review is reading it. It is attacker-writable **data**, never instructions.

## Install

```
go install github.com/rvagg/depsound/cmd/depsound@latest
```

Requires Go. Covers **npm, Go, crates (Rust), and GitHub Actions**.

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
| `depsound surface <eco>:<name> <from> <to> --uses=<paths>` | intersect a change with your import paths |
| `depsound gha:owner/repo <from> <to>` | a GitHub Action bump (its own threat model) |

Ecosystems: `npm`, `go`, `crates`, `gha`. `--format=json` emits the full machine contract for any command.

## Using it with an agent

- **Cold, no setup.** Tell an agent: *"Using the depsound CLI, evaluate this dependency change: foojs 1.2.3 to 2.0.0."* It's self-documenting: `depsound help` lists the commands, `depsound guide` gives the threat model and how to read the output, and every report routes to the next command. An agent can drive it with no further instruction; it figures out the ecosystem and syntax itself.
- **With a skill.** For a repeatable workflow, [`skills/`](skills/) has ready, self-contained skills (review a change, adopt a new package). Load one into a skill-aware agent, or curl and read it. Copy one as a template to write your own.

## License

Copyright 2026 Rod Vagg. Licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE).
