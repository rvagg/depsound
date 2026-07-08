package main

import (
	"fmt"
	"strings"
)

// identity is the one-paragraph statement of what depsound is, reused by
// help and guide so the gateway framing never drifts.
const identity = `depsound: sound the depths of a dependency change. It fetches the published
artifact, diffs two versions, and lays the evidence out for you to inspect.
A gateway to review, never a verdict: it surfaces mechanical facts and points
you deeper; the judgement is yours. "No flags" is a starting point, never an
all-clear.`

// routingTable answers the highest-leverage question, which command when. It
// is generated (not hand-spaced) so the command column stays aligned, and
// uses <spec> = <ecosystem>:<name> to keep the long rows inside 80 columns.
// Sentence case: this is orientation, not warning; caps do not earn a place.
var routingTable = buildRouting()

func buildRouting() string {
	rows := []struct{ when, cmd string }{
		{"a version bump you have", "depsound <spec> <from> <to>"},
		{"a GitHub Action bump", "depsound gha:owner/repo <from> <to>"},
		{"adopting a new dependency", "depsound <spec> [version]  (census)"},
		{"many bumps at once (a PR)", "depsound bulk  (list on stdin)"},
		{"a lockfile bump's subtree", "depsound transitive <lang> --old --new"},
		{"a big diff vs your imports", "depsound surface <spec> <from> <to> --uses"},
		{"one file/dir of a diff", "depsound show <spec> <from> <to> --file"},
	}
	w := 0
	for _, r := range rows {
		if len(r.when) > w {
			w = len(r.when)
		}
	}
	var b strings.Builder
	b.WriteString("which command when  (<spec> = <ecosystem>:<name>, e.g. npm:commander):\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "  %-*s  %s\n", w, r.when, r.cmd)
	}
	return strings.TrimRight(b.String(), "\n")
}

// usage is the short top-level help: identity, routing, one line per
// pathway, and pointers OUT to per-command help and the session guide. The
// detail lives in help <cmd> and guide, not here.
var usage = identity + `

` + routingTable + `

ecosystems: npm, go, crates, gha    <lang> for transitive: go, crates, npm, pnpm
global flags: --format=json  --no-osv  --cache-dir=DIR
per-command detail: ` + "`depsound help <command>`" + `
  <command>: diff, census, bulk, transitive, surface, show, gha

Run ` + "`depsound guide`" + ` once per session: the threat model, how to read the
output, and the two lenses (security vs compatibility) every review needs.`

// cmdHelp holds per-command detail, reached via help <command>, so the top-
// level help stays a routing table rather than a wall.
var cmdHelp = map[string]string{
	"diff": `depsound <ecosystem>:<name> <from> <to> [--format=stats|json|patch|files] [--no-osv]

Diffs two PUBLISHED versions (what installs, not the repo) and reports the
file diff, execution surface, manifest compatibility, and OSV. Versions come
straight off a Dependabot title; depsound normalizes them per ecosystem.
  --format=stats   human report (default)
  --format=json    the full stats.json contract for machine consumers
  --format=patch   the raw diff.patch on stdout
  --format=files   the changed-file table (tree-relative paths to grep)
  --no-osv         skip the known-CVE scan`,

	"census": `depsound <ecosystem>:<name> [version] [--transitive] [--cooldown=<days>] [--format=stats|json] [--no-osv]

Vets a SINGLE version in absolute terms: what you sign up for by adopting it
(no diff). Version defaults to latest; depsound resolves and REPORTS the
concrete version (agents guess stale versions from weights).
  --transitive    resolve the FULL transitive footprint via deps.dev (npm and
                  crates; a deps.dev estimate, not your exact install; for go,
                  go.mod is the resolved set, use depsound transitive go)
  --against=<lock>  subtract your current lockfile so the footprint reads as
                  MARGINAL (new to you / different-version / already-have), not
                  standalone. Implies --transitive; an upper bound (deps.dev
                  resolved in isolation). For the exact delta, generate a
                  current+newdep lockfile and diff it (see depsound guide).
  --cooldown=<d>  pick the newest release at least d days old (the pnpm
                  minimumReleaseAge posture; a fresh compromised release is
                  withheld)`,

	"bulk": `depsound bulk [--file=<list>] [--format=stats|json] [--no-osv]

Runs the per-pair analysis over a LIST of bumps (one "<eco>:<name> <from> <to>"
per line, or a JSON array) from stdin or --file, and renders a prioritized
ROUTER: which deps tripped which signals, most-severe first, each a POINTER to
inspect (drill with the single-pair command, instant once cached). The list is
yours to supply, from a PR diff, a go.mod diff, etc.`,

	"transitive": `depsound transitive <go|crates|npm|pnpm> --old=<lockfile> --new=<lockfile> [--format=stats|json] [--no-osv]

Resolves the whole subtree a bump drags in by diffing two resolved lockfiles:
  go      two go.mod        (the require block incl. // indirect IS the set)
  crates  two Cargo.lock    (the flat resolved package list)
  npm     two package-lock.json  (lockfileVersion 2/3, npm 7+; v1 unsupported)
  pnpm    two pnpm-lock.yaml (lockfileVersion 9.x, pnpm 9+; analysed on npm)
Changed deps run through the bulk router; added are listed (new code, census
each); removed are noted. A name carrying multiple versions (Cargo/npm dedup)
is handled by pairing a lone removed+added as a bump.
--old/--new each accept:
  a local PATH
  an https URL (github raw works; a github.com/blob URL is rewritten)
  github:owner/repo@ref[:path]  (API contents; private repos need GITHUB_TOKEN;
    path defaults to the ecosystem lockfile name)
No lockfile committed, or adopting a new dep? Generate one with a resolution-
only command (runs no package code), e.g. npm install --package-lock-only
--ignore-scripts, then diff. See depsound guide.`,

	"surface": `depsound surface <ecosystem>:<name> <from> <to> --uses=<unit,unit,...>

Intersects the diff with YOUR consumer usage units and reports per-unit status,
so a big diff collapses to "does it touch what I actually use". Units are
ecosystem-native: Go import paths, npm subpaths/file paths. Matching is per-
package for Go (a changed NESTED package reports as SUBPACKAGES ONLY, not a
match, since importing a package does not import its subpackages).
  --uses-file=P    newline or JSON-array list instead of --uses=
  --source-only    drop test/docs/generated matches
  --subtree        subtree (whole-area) matching, not per-package
  --format=json    machine output
Matching is by PATH, not reachability: a match is not proof you are affected,
and a non-match is not proof you are safe. It narrows where to look.`,

	"show": `depsound show <ecosystem>:<name> <from> <to> --file=X | --dir=Y | --symbol=Z

Extracts a targeted slice of the diff as a valid patch on stdout, for reading
one file, directory, or symbol without the whole diff. Exactly one selector.`,

	"gha": `GitHub Actions: depsound gha:owner/repo[/sub-path] <from> <to>  (diff)
                depsound gha:owner/repo[/sub-path] <ref>       (census)

A GHA dependency is owner/repo pinned to a ref; the artifact is the repo tree
at the resolved commit (what runs). depsound resolves each ref and GRADES the
pin, the load-bearing supply-chain control:
  SHA     immutable (best)
  tag     mutable, re-pointable (the tj-actions vector)
  branch  unpinned, moves on every push (worst)
Sub-path actions (owner/repo/dir) scope to the sub-tree you adopt. A single ref
(a branch or SHA, no version) is a census.

Threat model: an action runs on a CI RUNNER, not your machine, so running code
is its whole job (pre/post/main/using are context, not alarms). The risk is
what the runner grants: secrets, GITHUB_TOKEN, OIDC, push/publish powers, and
network pivot on self-hosted. So the pin, the dist bundle change, nested actions,
and what the code reaches are the signals, not "it runs code".`,
}

// helpCmd prints the routing help, or per-command detail for help <command>.
func helpCmd(args []string) error {
	if len(args) == 0 {
		fmt.Println(usage)
		return nil
	}
	name := args[0]
	if name == "guide" {
		return guideCmd(nil)
	}
	if text, ok := cmdHelp[name]; ok {
		fmt.Println(text)
		return nil
	}
	known := make([]string, 0, len(cmdHelp))
	for k := range cmdHelp {
		known = append(known, k)
	}
	return fmt.Errorf("no help for %q; try one of: %s (or `depsound guide`)", name, strings.Join(known, ", "))
}
