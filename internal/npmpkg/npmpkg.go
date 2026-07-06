package npmpkg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rvagg/depsound/internal/manifest"
)

type Package struct {
	Name     string
	Version  string
	Type     string
	Main     string
	Engines  map[string]string
	Scripts  map[string]string
	Exports  json.RawMessage
	Bin      json.RawMessage
	Deps     map[string]string
	Peer     map[string]string
	Optional map[string]string
	// Warnings records known fields whose shape was not what npm
	// documents (ancient packages have engines-as-array and worse);
	// such fields degrade to empty rather than failing the run.
	Warnings []string
}

// Load is deliberately forgiving: unknown fields are ignored and
// misshapen known fields degrade to empty with a warning. A package npm
// would install must never be one depsound refuses to analyse; only
// package.json not being a JSON object at all is an error.
func Load(dir string) (*Package, error) {
	b, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("package.json: %w", err)
	}
	p := &Package{Exports: raw["exports"], Bin: raw["bin"]}
	p.Name = p.str(raw, "name")
	p.Version = p.str(raw, "version")
	p.Type = p.str(raw, "type")
	p.Main = p.str(raw, "main")
	p.Engines = p.stringMap(raw, "engines")
	p.Scripts = p.stringMap(raw, "scripts")
	p.Deps = p.stringMap(raw, "dependencies")
	p.Peer = p.stringMap(raw, "peerDependencies")
	p.Optional = p.stringMap(raw, "optionalDependencies")
	return p, nil
}

func (p *Package) str(raw map[string]json.RawMessage, key string) string {
	r, ok := raw[key]
	if !ok || string(r) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(r, &s); err != nil {
		p.warn(key)
		return ""
	}
	return s
}

func (p *Package) stringMap(raw map[string]json.RawMessage, key string) map[string]string {
	r, ok := raw[key]
	if !ok || string(r) == "null" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(r, &m); err == nil {
		return m
	}
	// salvage string-valued entries from a mixed-type object
	var loose map[string]json.RawMessage
	if err := json.Unmarshal(r, &loose); err != nil {
		p.warn(key)
		return nil
	}
	p.warn(key)
	m = map[string]string{}
	for k, v := range loose {
		var s string
		if json.Unmarshal(v, &s) == nil {
			m[k] = s
		}
	}
	return m
}

func (p *Package) warn(key string) {
	p.Warnings = append(p.Warnings, fmt.Sprintf("field %q has unexpected shape, partially or fully ignored", key))
}

// Delta types are the shared ecosystem-neutral ones.
type (
	Change       = manifest.Change
	DepChange    = manifest.DepChange
	ExportChange = manifest.ExportChange
)

// lifecycleScripts can execute on a consumer's machine in some install
// path; they are the number one npm attack signal. npm runs pre<x>/post<x>
// around any script, so the hook set is wider than the obvious three:
// preinstall/install/postinstall run for registry installs; prepare (and
// its pre/post), prepack and postpack run when installing git
// dependencies. Scripts that only run on the author's machine (publish,
// version, test, and prepublish, which lost its run-on-install behaviour
// back in npm 5) are deliberately excluded.
var lifecycleScripts = []string{
	"preinstall", "install", "postinstall",
	"preprepare", "prepare", "postprepare",
	"prepack", "postpack",
}

func LifecycleDelta(a, b *Package) []Change {
	var out []Change
	for _, k := range lifecycleScripts {
		out = appendDelta(out, k, a.Scripts[k], b.Scripts[k])
	}
	return out
}

// LifecyclePresent lists the lifecycle scripts a package ships (the
// absolute/census form): what would run on install, not a delta.
func LifecyclePresent(p *Package) []Change {
	var out []Change
	for _, k := range lifecycleScripts {
		if v := p.Scripts[k]; v != "" {
			out = append(out, Change{Key: k, Status: "present", To: v})
		}
	}
	return out
}

// DepsPresent lists all declared dependencies (absolute/census form).
func DepsPresent(p *Package) []DepChange {
	var out []DepChange
	sections := []struct {
		name string
		m    map[string]string
	}{{"dependencies", p.Deps}, {"peerDependencies", p.Peer}, {"optionalDependencies", p.Optional}}
	for _, s := range sections {
		names := make([]string, 0, len(s.m))
		for n := range s.m {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			dc := DepChange{Section: s.name, Name: n, Status: "present", To: s.m[n]}
			if f := specFlag(s.m[n]); f != "" {
				dc.Flag = f
			}
			out = append(out, dc)
		}
	}
	return out
}

func BinDelta(a, b *Package) []Change {
	return mapDelta(binMap(a), binMap(b))
}

func binMap(p *Package) map[string]string {
	m := map[string]string{}
	if len(p.Bin) == 0 {
		return m
	}
	var s string
	if json.Unmarshal(p.Bin, &s) == nil {
		m[p.Name] = s
		return m
	}
	_ = json.Unmarshal(p.Bin, &m)
	return m
}

// EnginesDelta emits full display labels (engines.node) since Change.Key
// is rendered verbatim across ecosystems.
func EnginesDelta(a, b *Package) []Change {
	deltas := mapDelta(a.Engines, b.Engines)
	for i := range deltas {
		deltas[i].Key = "engines." + deltas[i].Key
	}
	return deltas
}

func DepsDelta(a, b *Package) []DepChange {
	var out []DepChange
	sections := []struct {
		name string
		oldM map[string]string
		newM map[string]string
	}{
		{"dependencies", a.Deps, b.Deps},
		{"peerDependencies", a.Peer, b.Peer},
		{"optionalDependencies", a.Optional, b.Optional},
	}
	for _, s := range sections {
		for _, c := range mapDelta(s.oldM, s.newM) {
			dc := DepChange{Section: s.name, Name: c.Key, Status: c.Status, From: c.From, To: c.To}
			if f := specFlag(c.To); f != "" && c.Status != "removed" {
				dc.Flag = f
			}
			out = append(out, dc)
		}
	}
	return out
}

// specFlag identifies dependency specs that bypass the registry.
func specFlag(spec string) string {
	switch {
	case spec == "":
		return ""
	case strings.Contains(spec, "://"),
		strings.HasPrefix(spec, "git+"),
		strings.HasPrefix(spec, "git:"),
		strings.HasPrefix(spec, "github:"):
		return "git/url dependency"
	case strings.HasPrefix(spec, "file:"), strings.HasPrefix(spec, "link:"):
		return "filesystem dependency"
	}
	return ""
}

func appendDelta(out []Change, key, from, to string) []Change {
	switch {
	case from == to:
		return out
	case from == "":
		return append(out, Change{Key: key, Status: "added", To: to})
	case to == "":
		return append(out, Change{Key: key, Status: "removed", From: from})
	default:
		return append(out, Change{Key: key, Status: "changed", From: from, To: to})
	}
}

func mapDelta(a, b map[string]string) []Change {
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var out []Change
	for _, k := range sorted {
		out = appendDelta(out, k, a[k], b[k])
	}
	return out
}
