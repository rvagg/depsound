package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/output"
	"github.com/rvagg/depsound/internal/spec"
	"github.com/rvagg/depsound/internal/version"
)

func parseReviewPacket(raw []byte) ([]bulkItem, error) {
	var packet manifest.ReviewPacket
	if err := json.Unmarshal(raw, &packet); err != nil {
		return nil, fmt.Errorf("review input: %w", err)
	}
	if packet.Schema != 1 {
		return nil, fmt.Errorf("review input schema %d is unsupported", packet.Schema)
	}
	if strings.TrimPrefix(packet.ToolVersion, "v") != version.Version {
		return nil, fmt.Errorf("review input requires depsound %q, running %q", packet.ToolVersion, version.Version)
	}
	if packet.Mode != "bulk" && packet.Mode != "evidence" {
		return nil, fmt.Errorf("review input mode %q is unsupported", packet.Mode)
	}
	if packet.Mode == "evidence" && len(packet.Items) > 0 {
		return nil, fmt.Errorf("evidence-only review input cannot contain acquisition items")
	}
	items, err := parseReviewItems(packet.Items)
	if err != nil {
		return nil, err
	}
	for _, omitted := range packet.Omitted {
		if omitted.Ref == "" || omitted.Reason == "" {
			return nil, fmt.Errorf("review input omission needs ref and reason")
		}
		items = append(items, bulkItem{spec: omitted.Ref, failure: omitted.Reason})
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("review input has no replayable or evidence-only items")
	}
	return items, nil
}

// Replay uses collected identities and versions, never display references or
// ranges that could select a different release on the next run.
func bulkReplay(items []bulkItem, results []output.BulkResult) *manifest.ReviewPacket {
	packet := &manifest.ReviewPacket{Schema: 1, ToolVersion: version.Version, Mode: "bulk"}
	if len(items) == 0 || len(items) != len(results) {
		packet.Mode, packet.Reason = "evidence", "The collected review input is incomplete."
		return packet
	}
	for i, result := range results {
		var input manifest.ReviewItem
		var omission string
		switch {
		case result.LockChange != nil:
			if result.LockChange.ToRegistry &&
				(result.Census == nil || result.Census.Unavailable != nil || result.Unavailable != nil || result.Err != "") {
				omission = "Registry-target census is evidence-only; inspect retained evidence."
				break
			}
			input.LockChange = result.LockChange
		case result.Redirect != "":
			sp, err := spec.Parse(items[i].spec)
			if err != nil {
				omission = "Declaration is evidence-only; inspect retained evidence."
				break
			}
			input.Ecosystem, input.Name, input.Redirect = string(sp.Eco), sp.Name, result.Redirect
		case result.Stats != nil && len(result.Stats.Artifact.Unavailable) == 0:
			p := result.Stats.Package
			input.Ecosystem, input.Name, input.From, input.To = p.Ecosystem, p.Name, p.From, p.To
			if p.Ecosystem == "gha" {
				from, to := result.Stats.Artifact.SourceFrom, result.Stats.Artifact.SourceTo
				if from == nil || to == nil || !strings.HasPrefix(from.Digest, "git-") || !strings.HasPrefix(to.Digest, "git-") {
					omission = "Action artifact identity is evidence-only; inspect retained evidence."
					break
				}
				input.From, input.To = strings.TrimPrefix(from.Digest, "git-"), strings.TrimPrefix(to.Digest, "git-")
			}
		case result.Census != nil && result.Census.Unavailable == nil:
			c := result.Census
			input.Ecosystem, input.Name, input.To = c.Ecosystem, c.Name, c.Version
			if c.Ecosystem == "gha" {
				if c.Source == nil || !strings.HasPrefix(c.Source.Digest, "git-") {
					omission = "Action artifact identity is evidence-only; inspect retained evidence."
					break
				}
				input.To = strings.TrimPrefix(c.Source.Digest, "git-")
			}
		default:
			omission = "Artifact query is evidence-only; inspect retained evidence."
		}
		if omission != "" {
			packet.Omitted = append(packet.Omitted, manifest.ReviewOmission{Ref: replayRef(result.Ref), Reason: omission})
			continue
		}
		packet.Items = append(packet.Items, input)
	}
	if len(packet.Items) == 0 {
		packet.Mode, packet.Reason = "evidence", "No rows have an equivalent artifact query."
	}
	return packet
}

func replayRef(ref string) string {
	return output.EscapeText(ref)
}
