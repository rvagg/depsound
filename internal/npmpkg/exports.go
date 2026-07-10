package npmpkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

// The resolution table sidesteps "is this package ESM or CJS": for each
// export subpath under each standard condition set, run the specified Node
// resolution algorithm against both versions and diff the outcomes.

// Entrypoints lists the package's runtime payload files: the resolved "."
// export (require and import conditions), or main/index.js when there is no
// exports map, plus any bin scripts. These are the files that execute when the
// package is imported or its command is invoked, so they are what to read
// first, even when classed "generated".
func Entrypoints(p *Package) []string {
	seen := map[string]bool{}
	var out []string
	add := func(f string) {
		f, _, ok := splitOutcome(f) // drop any " (format)" tag
		if !ok {
			return
		}
		f = strings.TrimPrefix(f, "./")
		if f == "" || strings.Contains(f, "*") {
			return // unresolvable, or a wildcard subpath, not a concrete file
		}
		f = path.Clean(f)
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	if table, err := resolutionTable(p); err == nil {
		for _, c := range []string{"require", "import"} {
			add(table["."+"\x00"+c])
		}
	}
	bins := binMap(p)
	keys := make([]string, 0, len(bins))
	for k := range bins {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		add(bins[k])
	}
	return out
}

func ExportsDelta(a, b *Package) ([]ExportChange, error) {
	oldT, err := resolutionTable(a)
	if err != nil {
		return nil, fmt.Errorf("%s exports: %w", a.Version, err)
	}
	newT, err := resolutionTable(b)
	if err != nil {
		return nil, fmt.Errorf("%s exports: %w", b.Version, err)
	}

	keys := map[string]bool{}
	for k := range oldT {
		keys[k] = true
	}
	for k := range newT {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	var out []ExportChange
	for _, k := range sorted {
		from, to := oldT[k], newT[k]
		if from == to {
			continue
		}
		subpath, cond, _ := strings.Cut(k, "\x00")
		out = append(out, ExportChange{
			Subpath:   subpath,
			Condition: cond,
			From:      from,
			To:        to,
			Note:      note(cond, from, to),
		})
	}
	return out, nil
}

func note(cond, from, to string) string {
	switch {
	case from != "" && to == "" && cond == "require":
		return "require() no longer resolves (breaks CJS consumers)"
	case from == "" && to != "":
		return "newly exported"
	case samePathDifferentFormat(from, to):
		return "same path, format flipped"
	}
	// import-condition removal needs no note: the value already reads "(unresolvable)"
	return ""
}

func samePathDifferentFormat(from, to string) bool {
	fp, ff, ok1 := splitOutcome(from)
	tp, tf, ok2 := splitOutcome(to)
	return ok1 && ok2 && fp == tp && ff != tf
}

func splitOutcome(s string) (p, format string, ok bool) {
	p, rest, found := strings.Cut(s, " (")
	if !found {
		return s, "", s != ""
	}
	return p, strings.TrimSuffix(rest, ")"), true
}

// resolutionTable maps "subpath\0condition" to a resolved outcome for the
// condition sets {require,node,default} and {import,node,default}.
func resolutionTable(p *Package) (map[string]string, error) {
	table := map[string]string{}
	conds := []string{"require", "import"}

	if len(p.Exports) == 0 || bytes.Equal(p.Exports, []byte("null")) {
		// legacy resolution: main (default index.js), format from type
		m := p.Main
		if m == "" {
			m = "./index.js"
		}
		if !strings.HasPrefix(m, "./") {
			m = "./" + path.Clean(m)
		}
		for _, c := range conds {
			table["."+"\x00"+c] = outcome(m, p.Type)
		}
		return table, nil
	}

	root, err := parseNode(p.Exports)
	if err != nil {
		return nil, err
	}

	subpaths := map[string]*node{}
	if root.kind == 'o' && len(root.keys) > 0 && strings.HasPrefix(root.keys[0], ".") {
		for i, k := range root.keys {
			subpaths[k] = root.vals[i]
		}
	} else {
		subpaths["."] = root
	}

	for sub, target := range subpaths {
		for _, c := range conds {
			active := map[string]bool{c: true, "node": true}
			r := resolveTarget(target, active)
			key := sub + "\x00" + c
			if r == "" {
				table[key] = ""
			} else {
				table[key] = outcome(r, p.Type)
			}
		}
	}
	return table, nil
}

func outcome(p, pkgType string) string {
	format := ""
	switch {
	case strings.HasSuffix(p, ".mjs"):
		format = "esm"
	case strings.HasSuffix(p, ".cjs"):
		format = "cjs"
	case strings.HasSuffix(p, ".json"):
		format = "json"
	case strings.HasSuffix(p, ".js"), strings.HasSuffix(p, "/*"), strings.Contains(p, "*"):
		if pkgType == "module" {
			format = "esm"
		} else {
			format = "cjs"
		}
	}
	if format == "" {
		return p
	}
	return p + " (" + format + ")"
}

// resolveTarget walks a target in key order per the Node algorithm: the
// first matching condition wins and its result (even unresolvable) stops
// the walk. "types" is a tooling condition, skipped.
func resolveTarget(n *node, active map[string]bool) string {
	switch n.kind {
	case 's':
		return n.str
	case 'a':
		for _, c := range n.arr {
			if r := resolveTarget(c, active); r != "" {
				return r
			}
		}
		return ""
	case 'o':
		for i, k := range n.keys {
			if k == "types" {
				continue
			}
			if active[k] || k == "default" {
				return resolveTarget(n.vals[i], active)
			}
		}
		return ""
	default: // null or non-string scalar: explicitly unavailable
		return ""
	}
}

// node is a JSON value with object key order preserved; encoding/json maps
// discard order and Node's algorithm depends on it.
type node struct {
	kind byte // 's' string, 'a' array, 'o' object, 'n' null/other
	str  string
	arr  []*node
	keys []string
	vals []*node
}

func parseNode(raw json.RawMessage) (*node, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	n, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	return n, nil
}

func decodeValue(dec *json.Decoder) (*node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			n := &node{kind: 'o'}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("non-string object key %v", kt)
				}
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				n.keys = append(n.keys, key)
				n.vals = append(n.vals, v)
			}
			_, err := dec.Token() // consume '}'
			return n, err
		case '[':
			n := &node{kind: 'a'}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				n.arr = append(n.arr, v)
			}
			_, err := dec.Token() // consume ']'
			return n, err
		}
		return nil, fmt.Errorf("unexpected delimiter %v", t)
	case string:
		return &node{kind: 's', str: t}, nil
	default:
		return &node{kind: 'n'}, nil
	}
}
