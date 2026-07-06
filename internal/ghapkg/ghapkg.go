// Package ghapkg parses a GitHub Action manifest (action.yml) into its
// execution model: the GHA analog of a package manifest, WHAT runs and HOW.
// A real YAML parser is used deliberately, hand-parsing would invite a
// parser-differential attack where a crafted manifest hides a pre/post hook
// from us that the runner still executes.
package ghapkg

import (
	"os"
	"path/filepath"

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
