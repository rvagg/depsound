package fetch

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// A dependency manifest often bumps a semver RANGE (`^9.3.0` -> `^10.2.0`),
// not an exact version. The concrete version a consumer installs is the
// highest published version satisfying the range under their install policy,
// so the range must be resolved, and the set of newer satisfying versions
// (which a less-cooled-down consumer would install instead) reported.
//
// Only the operators dependency bots actually emit are handled: `^`, `~`,
// exact, and single `>=`/`>`/`<=`/`<` comparators. Compound ranges (`||`,
// hyphen, space-joined comparators) and x-ranges are declined, so the caller
// reviews the literal arg and says so, honest about the boundary rather than
// guessing.

// isRange reports whether a version arg is a semver range (needs resolving
// against published versions) rather than an exact version or "latest".
func isRange(s string) bool {
	if s == "" || s == "latest" {
		return false
	}
	return strings.ContainsAny(s, "^~<>=*|xX ")
}

// rangeResolvable reports whether the range is one of the shapes we resolve.
// A range that is not resolvable is declined loudly, never silently guessed.
func rangeResolvable(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" || s == "x" || s == "X" {
		return true
	}
	if strings.ContainsAny(s, " ,") || strings.Contains(s, "||") {
		return false // compound
	}
	_, _, _, ok := boundsFor(s)
	return ok
}

// satisfies reports whether a concrete published version is inside a
// (resolvable) range. Prereleases are excluded, matching npm's default that a
// caret/tilde range does not admit prereleases.
func satisfies(version, rng string) bool {
	v := canonicalV(version)
	if !semver.IsValid(v) || semver.Prerelease(v) != "" {
		return false
	}
	rng = strings.TrimSpace(rng)
	if rng == "" || rng == "*" || rng == "x" || rng == "X" {
		return true
	}
	op, lo, hi, ok := boundsFor(rng)
	if !ok {
		return false
	}
	switch op {
	case "range": // [lo, hi)
		return semver.Compare(v, lo) >= 0 && semver.Compare(v, hi) < 0
	case ">=":
		return semver.Compare(v, lo) >= 0
	case ">":
		return semver.Compare(v, lo) > 0
	case "<=":
		return semver.Compare(v, hi) <= 0
	case "<":
		return semver.Compare(v, hi) < 0
	case "==":
		return semver.Compare(v, lo) == 0
	}
	return false
}

// boundsFor parses a single-comparator range into an operator and its
// canonical bound(s). For `^`/`~` it returns op "range" with a half-open
// [lo, hi); for a comparator it returns that comparator with the bound in lo
// (>=,>) or hi (<=,<); for a bare version, "==".
func boundsFor(s string) (op, lo, hi string, ok bool) {
	switch {
	case strings.HasPrefix(s, "^"):
		lo, hi, ok = caretBounds(s[1:])
		return "range", lo, hi, ok
	case strings.HasPrefix(s, "~"):
		lo, hi, ok = tildeBounds(s[1:])
		return "range", lo, hi, ok
	case strings.HasPrefix(s, ">="):
		return ">=", exactBound(s[2:]), "", validBound(s[2:])
	case strings.HasPrefix(s, "<="):
		return "<=", "", exactBound(s[2:]), validBound(s[2:])
	case strings.HasPrefix(s, ">"):
		return ">", exactBound(s[1:]), "", validBound(s[1:])
	case strings.HasPrefix(s, "<"):
		return "<", "", exactBound(s[1:]), validBound(s[1:])
	default:
		if strings.ContainsAny(s, "xX*") {
			return "", "", "", false // x-range: declined
		}
		return "==", exactBound(s), "", validBound(s)
	}
}

func caretBounds(s string) (lo, hi string, ok bool) {
	maj, min, pat, ok := parseMMP(s)
	if !ok {
		return "", "", false
	}
	lo = ver(maj, min, pat)
	switch {
	case maj > 0:
		hi = ver(maj+1, 0, 0)
	case min > 0:
		hi = ver(0, min+1, 0)
	default:
		hi = ver(0, 0, pat+1)
	}
	return lo, hi, true
}

func tildeBounds(s string) (lo, hi string, ok bool) {
	maj, min, pat, ok := parseMMP(s)
	if !ok {
		return "", "", false
	}
	return ver(maj, min, pat), ver(maj, min+1, 0), true
}

func exactBound(s string) string { return canonicalV(strings.TrimSpace(s)) }

func validBound(s string) bool { return semver.IsValid(canonicalV(strings.TrimSpace(s))) }

// parseMMP reads major.minor.patch, tolerating missing trailing components
// (which default to 0) and a leading v; a wildcard component makes it not a
// plain version (declined).
func parseMMP(s string) (maj, min, pat int, ok bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return 0, 0, 0, false
	}
	out := [3]int{}
	for i, p := range parts {
		if p == "" || p == "x" || p == "X" || p == "*" {
			return 0, 0, 0, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return 0, 0, 0, false
		}
		out[i] = n
	}
	return out[0], out[1], out[2], true
}

func ver(maj, min, pat int) string { return fmt.Sprintf("v%d.%d.%d", maj, min, pat) }

func sortSemver(vs []string) {
	sort.Slice(vs, func(i, j int) bool { return semver.Compare(canonicalV(vs[i]), canonicalV(vs[j])) < 0 })
}

// maxSatisfying returns the highest of the given versions inside the range,
// or "" if none satisfy.
func maxSatisfying(versions []string, rng string) string {
	best := ""
	for _, v := range versions {
		if !satisfies(v, rng) {
			continue
		}
		if best == "" || semverGreater(v, best) {
			best = v
		}
	}
	return best
}

// newerSatisfying returns the versions that satisfy the range AND are newer
// than pick, sorted ascending: the set a consumer with a shorter (or no)
// cooldown would install instead of pick, and which this review did not cover.
func newerSatisfying(versions []string, rng, pick string) []string {
	var out []string
	for _, v := range versions {
		if satisfies(v, rng) && semverGreater(v, pick) {
			out = append(out, v)
		}
	}
	sortSemver(out)
	return out
}
