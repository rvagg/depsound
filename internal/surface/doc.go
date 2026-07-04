// Package surface turns diff.patch into a queryable index: which files
// changed, which hunks they contain, and which enclosing symbol each hunk
// falls in (from git's function-context hunk headers, which attribute
// ~98% of hunks even in a vendored C amalgamation). This is the
// compression layer that lets an agent holding "my project uses these
// five packages" intersect instead of reading a 40k-line diff.
//
// surface.go: the index, parsing, and prefix/package matching.
// extract.go: slicing verbatim patch text for selected files and hunks.
//
// Matching is by path, deliberately NOT by import reachability: it
// answers "what changed in X's directory", not "what changed that reaches
// my use of X". Transitive impact through a module's internal imports is
// the consuming agent's judgement (and a planned import-graph feature);
// the output states this blind spot plainly so a small match is never
// mistaken for low impact.
package surface
