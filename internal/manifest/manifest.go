// Package manifest holds the ecosystem-neutral delta types that analysis
// packages (npmpkg, gopkg, later cratepkg) produce and stats consumes.
package manifest

// Change is a keyed string delta: lifecycle scripts, bin entries,
// compatibility constraints. Status is added, removed or changed. Key is
// a full display label ("postinstall", "engines.node", "go directive").
type Change struct {
	Key    string `json:"key"`
	Status string `json:"status"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
}

type DepChange struct {
	Section string `json:"section"` // dependencies, peerDependencies, require, replace, ...
	Name    string `json:"name"`
	Status  string `json:"status"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Flag    string `json:"flag,omitempty"` // specs that bypass the registry, local replaces
}

type ExportChange struct {
	Subpath   string `json:"subpath"`
	Condition string `json:"condition"` // require or import
	From      string `json:"from"`      // "path (format)", or "" for unresolvable
	To        string `json:"to"`
	Note      string `json:"note,omitempty"`
}
