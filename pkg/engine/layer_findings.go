/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// layerFindingKey retains the finding's complete evidence and provenance. Only
// document bookkeeping and timing are excluded: a shared block name alone must
// never collapse different values, remediation, locations or module callers.
type layerFindingKey struct {
	file string
	// Bound the retained key even when evidence contains the entire source file.
	// This digest is internal deduplication bookkeeping, not report identity.
	evidence [sha256.Size]byte
}

func newLayerFindingKey(v *model.Vulnerability, file string) layerFindingKey {
	evidence := *v
	evidence.ID = 0
	evidence.FileID = ""
	evidence.ScanID = ""
	evidence.QueryDuration = 0
	encoded, _ := json.Marshal(evidence) // Vulnerability contains only JSON-safe fields.
	return layerFindingKey{file: file, evidence: sha256.Sum256(encoded)}
}

// dropRepeatedLayerFindings removes the findings of the later documents of an
// expanded Terraform file (see converter.BuildLayers) that another layer reports
// identically. Every later document holds the whole file, so
// a block that is the same in several of them is evaluated in each, and what
// differs between documents, the instances of an expanded block, is what
// remains. Findings of other files are left as they are.
func dropRepeatedLayerFindings(vulns []model.Vulnerability, files map[string]*model.FileMetadata) []model.Vulnerability {
	layered := layeredFilePaths(files)
	if len(layered) == 0 {
		return vulns
	}
	fileOf := func(v *model.Vulnerability) *model.FileMetadata {
		f := files[v.FileID]
		if f == nil {
			return nil
		}
		if _, ok := layered[f.FilePath]; !ok {
			return nil
		}
		return f
	}

	seen := make(map[layerFindingKey]string)
	for i := range vulns {
		if f := fileOf(&vulns[i]); f != nil && !repeatedLayerBlock(f, &vulns[i]) {
			seen[newLayerFindingKey(&vulns[i], f.FilePath)] = f.ID
		}
	}
	kept := vulns[:0]
	for i := range vulns {
		f := fileOf(&vulns[i])
		if f == nil || !repeatedLayerBlock(f, &vulns[i]) {
			kept = append(kept, vulns[i])
			continue
		}
		key := newLayerFindingKey(&vulns[i], f.FilePath)
		if layer, repeated := seen[key]; repeated && layer != vulns[i].FileID {
			continue
		}
		seen[key] = vulns[i].FileID
		kept = append(kept, vulns[i])
	}
	return kept
}

func layeredFilePaths(files map[string]*model.FileMetadata) map[string]struct{} {
	layered := make(map[string]struct{})
	for _, f := range files {
		if f != nil && (f.ExpansionLayer > 0 || len(f.ExpansionContext) > 0) {
			layered[f.FilePath] = struct{}{}
		}
	}
	return layered
}

// layerBlockKey is scan bookkeeping, not a resource address or report identity.
func layerBlockKey(typ, name string) string { return typ + "\x00" + name }

func repeatedLayerBlock(f *model.FileMetadata, v *model.Vulnerability) bool {
	if f.ExpansionLayer > 0 {
		return true
	}
	line, col := v.BlockLocation.Start.Line, v.BlockLocation.Start.Col
	if copied, ok := f.ExpansionContext[moduleAttributionKey(v.ResourceType, line, col)]; ok {
		return copied
	}
	return f.ExpansionContext[moduleAttributionKey(dataTypePrefix+v.ResourceType, line, col)]
}
