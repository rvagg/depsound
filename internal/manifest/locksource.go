package manifest

import (
	"net/url"
	"strings"
)

// LockSource records declared acquisition metadata, not verified package bytes.
// Empty fields are unknown; Location identifies an entry within the lockfile.
type LockSource struct {
	Location  string `json:"location,omitempty"`
	Resolved  string `json:"resolved"`
	Host      string `json:"host"`
	Integrity string `json:"integrity"`
	Link      bool   `json:"link,omitempty"`
}

// LockChange retains both source sets for one unchanged package version.
// Multiple installations or registries must not collapse onto an arbitrary entry.
type LockChange struct {
	Ecosystem string       `json:"ecosystem"`
	Name      string       `json:"name"`
	Version   string       `json:"version"`
	From      []LockSource `json:"from"`
	To        []LockSource `json:"to"`
	Files     []string     `json:"files,omitempty"`
}

func NewLockSource(location, resolved, integrity string) LockSource {
	s := LockSource{Location: location, Resolved: resolved, Integrity: integrity}
	raw := resolved
	for _, prefix := range []string{"registry+", "sparse+", "git+"} {
		raw = strings.TrimPrefix(raw, prefix)
	}
	if u, err := url.Parse(raw); err == nil {
		s.Host = u.Hostname()
	}
	return s
}
