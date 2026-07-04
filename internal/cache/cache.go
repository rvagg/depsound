// Package cache lays out depvet's on-disk state. Artifacts are immutable
// compressed downloads keyed by (ecosystem, name, version); workspaces are
// regenerable derivations keyed by the version pair and tool version.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Cache struct {
	Root string
}

func Open(root string) (*Cache, error) {
	if root == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return nil, fmt.Errorf("resolving cache dir: %w", err)
		}
		root = filepath.Join(base, "depvet")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &Cache{Root: root}, nil
}

// Component maps an attacker-influenced string (package names arrive from
// manifest parsing) to a single safe path segment. The allowlisted form is
// for human browsability only; uniqueness comes from the hash suffix, so
// sanitizer collisions cannot alias two entries and traversal is
// structurally impossible. Uppercase is folded because case-insensitive
// filesystems must not alias distinct names; the hash keeps them distinct.
func Component(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		default:
			b.WriteRune('_')
		}
	}
	s := strings.TrimLeft(b.String(), "._-")
	if s == "" {
		s = "x"
	}
	if len(s) > 64 {
		s = s[:64]
	}
	sum := sha256.Sum256([]byte(raw))
	return s + "-" + hex.EncodeToString(sum[:4])
}

func (c *Cache) ArtifactPath(eco, name, version, ext string) string {
	return filepath.Join(c.Root, "artifacts", eco, Component(name), Component(version)+ext)
}

func (c *Cache) WorkspacePath(eco, name, from, to string) string {
	return filepath.Join(c.Root, "workspaces", eco, Component(name), Component(from)+"--"+Component(to))
}

// CensusPath is the persisted single-version tree, so an agent can grep
// the package it is vetting the way it greps a diff workspace.
func (c *Cache) CensusPath(eco, name, version string) string {
	return filepath.Join(c.Root, "census", eco, Component(name), Component(version))
}
