package main

import (
	"sort"

	"github.com/rvagg/depsound/internal/manifest"
)

type lockIdentity struct{ name, version string }
type lockAcquisition struct {
	resolved, integrity string
	link                bool
}

func lockSources(deps []resolvedDep) map[lockIdentity][]manifest.LockSource {
	var out map[lockIdentity][]manifest.LockSource
	for _, d := range deps {
		if d.source == nil {
			continue
		}
		if out == nil {
			out = make(map[lockIdentity][]manifest.LockSource)
		}
		key := lockIdentity{d.name, d.version}
		out[key] = append(out[key], *d.source)
	}
	return out
}

// Source locations explain duplicate installations; moving an identical source
// between node_modules paths does not itself change the acquisition metadata.
func sameAcquisitions(a, b []manifest.LockSource) bool {
	seen := make(map[lockAcquisition]bool, len(a))
	var locations map[string]lockAcquisition
	for _, s := range a {
		seen[lockAcquisition{s.Resolved, s.Integrity, s.Link}] = false
		if s.Location != "" {
			if locations == nil {
				locations = make(map[string]lockAcquisition)
			}
			locations[s.Location] = lockAcquisition{s.Resolved, s.Integrity, s.Link}
		}
	}
	matched := 0
	for _, s := range b {
		key := lockAcquisition{s.Resolved, s.Integrity, s.Link}
		if before, shared := locations[s.Location]; shared && before != key {
			return false
		}
		done, exists := seen[key]
		if !exists {
			return false
		}
		if !done {
			seen[key] = true
			matched++
		}
	}
	return matched == len(seen)
}

func sortLockSources(sources []manifest.LockSource) {
	sort.Slice(sources, func(i, j int) bool {
		a, b := sources[i], sources[j]
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		if a.Resolved != b.Resolved {
			return a.Resolved < b.Resolved
		}
		if a.Integrity != b.Integrity {
			return a.Integrity < b.Integrity
		}
		return !a.Link && b.Link
	})
}

func diffLockSources(old, niu []resolvedDep) []manifest.LockChange {
	if len(old) == 0 || len(niu) == 0 {
		return nil
	}
	a, b := lockSources(old), lockSources(niu)
	var changes []manifest.LockChange
	for key, from := range a {
		to := b[key]
		if len(to) == 0 || sameAcquisitions(from, to) {
			continue
		}
		sortLockSources(from)
		sortLockSources(to)
		changes = append(changes, manifest.LockChange{Name: key.name, Version: key.version, From: from, To: to})
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Name != changes[j].Name {
			return changes[i].Name < changes[j].Name
		}
		return changes[i].Version < changes[j].Version
	})
	return changes
}

func compareLockSources(a, b []manifest.LockSource) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		for _, pair := range [3][2]string{
			{a[i].Location, b[i].Location},
			{a[i].Resolved, b[i].Resolved},
			{a[i].Integrity, b[i].Integrity},
		} {
			if pair[0] < pair[1] {
				return -1
			}
			if pair[0] > pair[1] {
				return 1
			}
		}
		if a[i].Link != b[i].Link {
			if !a[i].Link {
				return -1
			}
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
