// Package ghapkg parses a GitHub Action manifest (action.yml) into its
// execution model: the GHA analog of a package manifest, WHAT runs and HOW.
// A real YAML parser is used deliberately, hand-parsing would invite a
// parser-differential attack where a crafted manifest hides a pre/post hook
// from us that the runner still executes.
package ghapkg

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rvagg/depsound/internal/manifest"
)

// Action is the parsed action.yml execution surface.
type Action struct {
	Found bool   // an action.yml/action.yaml was present
	File  string // which basename was found
	Using string // node20 | node16 | docker | composite | ""
	Main  string // node entrypoint
	Pre   string // runs BEFORE the action on the runner (execution surface)
	Post  string // runs AFTER the action
	Image string // docker: Dockerfile path or docker://<ref>
	// Composite steps: nested actions (a transitive dimension) and inline
	// shell. Uses lists the pinned refs; RunSteps counts `run:` shell steps.
	Uses     []string
	RunSteps int
	Warnings []string
}

// actionBasenames are the two manifest names GitHub accepts, in the order
// it resolves them.
var actionBasenames = []string{"action.yml", "action.yaml"}

// Load reads the action manifest from dir (already scoped to the action's
// path). A missing manifest is not an error: dir may be a repo with no
// root action, or the sub-path may not carry one, Found stays false.
func Load(dir string) (*Action, error) {
	a := &Action{}
	var b []byte
	for _, name := range actionBasenames {
		if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			b, a.File = data, name
			break
		}
	}
	if b == nil {
		return a, nil
	}
	a.Found = true

	var raw struct {
		Runs struct {
			Using string `yaml:"using"`
			Main  string `yaml:"main"`
			Pre   string `yaml:"pre"`
			Post  string `yaml:"post"`
			Image string `yaml:"image"`
			Steps []struct {
				Run  string `yaml:"run"`
				Uses string `yaml:"uses"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		a.Warnings = append(a.Warnings, a.File+" present but unparseable, execution model unknown: "+err.Error())
		return a, nil
	}
	a.Using = raw.Runs.Using
	a.Main = raw.Runs.Main
	a.Pre = raw.Runs.Pre
	a.Post = raw.Runs.Post
	a.Image = raw.Runs.Image
	for _, s := range raw.Runs.Steps {
		if s.Uses != "" {
			a.Uses = append(a.Uses, s.Uses)
		} else if s.Run != "" {
			a.RunSteps++
		}
	}
	return a, nil
}

// Use is one `uses:` reference in a workflow or composite action. Kind
// classifies the shape: "action" (owner/repo[/sub]@ref, fetchable and
// diffable), "docker" (a container image; identity/ref split so a changed
// image still surfaces, though depsound cannot fetch it), "reusable" (a
// remote workflow call, same deal), "local" (`./path`, the repo's own code,
// reviewed in its own PR diff), or "" (no ref / malformed; GitHub itself
// rejects those workflows).
type Use struct {
	Identity string
	Ref      string
	Raw      string
	Kind     string
}

// WorkflowUses extracts the action references a GitHub Actions workflow file or
// a composite action.yml declares: for a workflow, `jobs.<id>.steps[].uses` and
// `jobs.<id>.uses` (reusable-workflow calls); for a composite action,
// `runs.steps[].uses`. It reads a real YAML parse (a crafted file must not hide
// a `uses:` the runner would honour) and returns them in deterministic order. A
// parse error is returned so the caller records a coverage gap, never a silent
// miss. This is the DETECTION analog of the lockfile parsers: the workflow IS
// the manifest, its pinned refs are the resolved set.
func WorkflowUses(b []byte) ([]Use, error) {
	var raw struct {
		Jobs map[string]struct {
			Uses  string `yaml:"uses"`
			Steps []struct {
				Uses string `yaml:"uses"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
		Runs struct {
			Steps []struct {
				Uses string `yaml:"uses"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	var uses []Use
	add := func(v string) {
		if v != "" {
			uses = append(uses, parseUse(v))
		}
	}
	names := make([]string, 0, len(raw.Jobs))
	for n := range raw.Jobs {
		names = append(names, n)
	}
	sort.Strings(names) // maps iterate randomly; a stable resolved set must not
	for _, n := range names {
		j := raw.Jobs[n]
		add(j.Uses) // a reusable-workflow call at the job level
		for _, s := range j.Steps {
			add(s.Uses)
		}
	}
	for _, s := range raw.Runs.Steps { // a composite action.yml
		add(s.Uses)
	}
	return uses, nil
}

// parseUse splits a `uses:` value into (Identity, Ref) and classifies its
// Kind. A trailing `# comment` is already stripped by the YAML scalar, so a
// SHA pin with its `# vX` version comment yields the SHA cleanly.
func parseUse(v string) Use {
	u := Use{Raw: v}
	switch {
	case strings.HasPrefix(v, "./"), strings.HasPrefix(v, "../"): // local action
		u.Kind = "local"
		return u
	case strings.HasPrefix(v, "docker://"):
		// docker://image[:tag] or docker://image@digest; the identity/ref
		// split keeps a changed or retargeted image pairable in a diff
		u.Kind = "docker"
		img := strings.TrimPrefix(v, "docker://")
		if at := strings.LastIndexByte(img, '@'); at > 0 {
			u.Identity, u.Ref = "docker://"+img[:at], img[at+1:]
		} else if c := strings.LastIndexByte(img, ':'); c > strings.LastIndexByte(img, '/') {
			u.Identity, u.Ref = "docker://"+img[:c], img[c+1:]
		} else {
			u.Identity = v // no tag: implicit latest
		}
		return u
	}
	at := strings.LastIndexByte(v, '@')
	if at <= 0 { // no ref, or malformed
		return u
	}
	id := v[:at]
	if strings.Contains(id, "/.github/workflows/") {
		u.Kind = "reusable"
		u.Identity, u.Ref = id, v[at+1:]
		return u
	}
	u.Kind = "action"
	u.Identity, u.Ref = id, v[at+1:]
	return u
}

// ExecDelta reports execution-model changes between two versions. pre/post
// carry an emphasis marker because a NEWLY added hook runs code around the
// action, the GHA analog of a new install script.
func ExecDelta(a, b *Action) []manifest.Change {
	var out []manifest.Change
	// "using" is rendered by the section header (UsingFrom/To), not here
	out = appendDelta(out, "main", a.Main, b.Main)
	out = appendDelta(out, "pre-hook", a.Pre, b.Pre)
	out = appendDelta(out, "post-hook", a.Post, b.Post)
	out = appendDelta(out, "docker image", a.Image, b.Image)
	return out
}

// ExecPresent lists the execution surface a single version declares
// (census form): what would run if you adopt it.
func ExecPresent(a *Action) []manifest.Change {
	var out []manifest.Change
	add := func(k, v string) {
		if v != "" {
			out = append(out, manifest.Change{Key: k, Status: "present", To: v})
		}
	}
	// "using" is rendered separately (GHAUsing); list only the entrypoints
	add("main", a.Main)
	add("pre-hook", a.Pre)
	add("post-hook", a.Post)
	add("docker image", a.Image)
	return out
}

func appendDelta(out []manifest.Change, key, from, to string) []manifest.Change {
	switch {
	case from == to:
		return out
	case from == "":
		return append(out, manifest.Change{Key: key, Status: "added", To: to})
	case to == "":
		return append(out, manifest.Change{Key: key, Status: "removed", From: from})
	default:
		return append(out, manifest.Change{Key: key, Status: "changed", From: from, To: to})
	}
}
