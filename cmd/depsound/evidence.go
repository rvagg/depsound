package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rvagg/depsound/internal/cache"
	"github.com/rvagg/depsound/internal/evidence"
	"github.com/rvagg/depsound/internal/fetch"
	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/output"
	"github.com/rvagg/depsound/internal/stats"
)

func exportEvidence(cacheDir, destination, kind string, report any, replay *manifest.ReviewPacket) error {
	c, err := cache.Open(cacheDir)
	if err != nil {
		return err
	}
	items, err := evidenceItems(c, report)
	if err != nil {
		return err
	}
	_, err = evidence.Export(c.Root, destination, evidence.Input{
		Kind: kind, Report: report, Replay: replay, Items: items,
	}, evidence.DefaultLimits)
	if err != nil {
		return fmt.Errorf("export evidence: %w", err)
	}
	return nil
}

func evidenceItems(c *cache.Cache, report any) ([]evidence.Item, error) {
	switch report := report.(type) {
	case *stats.Stats:
		return []evidence.Item{evidenceStats(c, report)}, nil
	case *output.Census:
		return []evidence.Item{evidenceCensus(c, report)}, nil
	case []output.BulkResult:
		return evidenceBulk(c, report), nil
	case output.TransitiveResult:
		return evidenceTransitive(c, report), nil
	default:
		return nil, fmt.Errorf("unsupported evidence report %T", report)
	}
}

func evidenceStats(c *cache.Cache, st *stats.Stats) evidence.Item {
	item := evidence.Item{
		Ref:       st.Package.Ecosystem + ":" + st.Package.Name + " " + st.Package.From + " " + st.Package.To,
		Workspace: st.Workspace,
	}
	item.Sources = append(item.Sources,
		evidenceDiffSource(c, st, "from", st.Package.From, st.Artifact.SourceFrom),
		evidenceDiffSource(c, st, "to", st.Package.To, st.Artifact.SourceTo))
	for _, unavailable := range st.Artifact.Unavailable {
		if unavailable == nil {
			continue
		}
		for i := range item.Sources {
			if item.Sources[i].Side == unavailable.Side {
				item.Sources[i].Unavailable = unavailable
			}
		}
	}
	return item
}

func evidenceDiffSource(c *cache.Cache, st *stats.Stats, side, version string, source *stats.Source) evidence.Source {
	es := evidence.Source{Side: side, Metadata: source}
	if source == nil {
		return es
	}
	es.Archive, es.Extension = evidenceArchive(c, st.Package.Ecosystem, st.Package.Name, version, source)
	if es.Archive != "" && !isLocalCrate(source) {
		es.MetaFile = fetch.MetaPath(es.Archive)
	}
	if st.Workspace != "" {
		es.Tree = filepath.Join(st.Workspace, map[string]string{"from": "old", "to": "new"}[side])
	}
	return es
}

func evidenceCensus(cacheStore *cache.Cache, c *output.Census) evidence.Item {
	item := evidence.Item{Ref: c.Ecosystem + ":" + c.Name + " " + c.Version}
	source := evidence.Source{Metadata: c.Source, Unavailable: c.Unavailable}
	if c.Source == nil {
		item.Sources = []evidence.Source{source}
		return item
	}

	name, key := evidencePackageName(c.Ecosystem, c.Name), c.Version
	if c.Ecosystem == "gha" {
		key = strings.TrimPrefix(c.Source.Digest, "git-")
	} else if c.Ecosystem == "crates" && isLocalCrate(c.Source) {
		key = localCrateKey(c.Version, fetch.Meta{URL: c.Source.URL, Digest: c.Source.Digest, Verification: c.Source.Verification})
	}
	source.Archive, source.Extension = evidenceArchive(cacheStore, c.Ecosystem, c.Name, c.Version, c.Source)
	if source.Archive != "" && !isLocalCrate(c.Source) {
		source.MetaFile = fetch.MetaPath(source.Archive)
	}
	root := cacheStore.CensusPath(c.Ecosystem, name, key)
	source.Tree = c.Tree
	source.ExtractFile = root + ".extract.json"
	item.Sources = []evidence.Source{source}
	return item
}

func evidenceArchive(c *cache.Cache, ecosystem, name, version string, source *stats.Source) (string, string) {
	if ecosystem == "crates" && isLocalCrate(source) {
		return filepath.Join(c.LocalCrateDir(), strings.TrimPrefix(source.Digest, "sha256-")), ".crate"
	}
	name = evidencePackageName(ecosystem, name)
	key, ext := version, ""
	switch ecosystem {
	case "npm":
		ext = ".tgz"
	case "go":
		ext = ".zip"
	case "crates":
		ext = ".crate"
	case "gha":
		ext = ".tar.gz"
		key = strings.TrimPrefix(source.Digest, "git-")
	default:
		return "", ""
	}
	return c.ArtifactPath(ecosystem, name, key, ext), ext
}

func evidencePackageName(ecosystem, name string) string {
	if ecosystem != "gha" {
		return name
	}
	parts := strings.Split(name, "/")
	if len(parts) < 2 {
		return name
	}
	return strings.Join(parts[:2], "/")
}

func isLocalCrate(source *stats.Source) bool {
	return source != nil && (source.Verification == fetch.VerifyLocalSHA256 || source.Verification == fetch.VerifyLocalRegistry256)
}

func evidenceBulk(c *cache.Cache, results []output.BulkResult) []evidence.Item {
	items := make([]evidence.Item, 0, len(results))
	for _, result := range results {
		if result.Stats != nil {
			item := evidenceStats(c, result.Stats)
			item.Ref = result.Ref
			items = append(items, item)
		}
		if result.Census != nil {
			item := evidenceCensus(c, result.Census)
			item.Ref = result.Ref
			items = append(items, item)
		}
	}
	return items
}

func evidenceTransitive(c *cache.Cache, result output.TransitiveResult) []evidence.Item {
	items := evidenceBulk(c, result.Changed)
	for _, added := range result.Added {
		if added.Analysis == nil {
			continue
		}
		if added.Analysis.Stats != nil {
			item := evidenceStats(c, added.Analysis.Stats)
			item.Ref = added.Analysis.Ref
			items = append(items, item)
		}
		if added.Analysis.Census != nil {
			item := evidenceCensus(c, added.Analysis.Census)
			item.Ref = added.Analysis.Ref
			items = append(items, item)
		}
	}
	return items
}
