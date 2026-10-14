/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// layerFindingKey identifies a finding by everything a report shows of it.
type layerFindingKey struct {
	file, query, searchKey, searchValue string
	resourceType, resourceName          string
	remediation, value                  string
	line                                int
}

func newLayerFindingKey(v *model.Vulnerability, file string) layerFindingKey {
	key := layerFindingKey{
		file: file, query: v.QueryID, searchKey: v.SearchKey, searchValue: v.SearchValue,
		resourceType: v.ResourceType, resourceName: v.ResourceName,
		remediation: v.Remediation, line: v.Line,
	}
	if v.Value != nil {
		key.value = *v.Value
	}
	return key
}

// dropRepeatedLayerFindings removes the findings of the later documents of an
// expanded Terraform file (see converter.BuildLayers) that the file's first
// document reports identically. Every later document holds the whole file, so
// a block that is the same in several of them is evaluated in each, and what
// differs between documents, the instances of an expanded block, is what
// remains. Findings of other files are left as they are.
func dropRepeatedLayerFindings(vulns []model.Vulnerability, files map[string]*model.FileMetadata) []model.Vulnerability {
	layered := make(map[string]struct{})
	for _, f := range files {
		if f != nil && f.ExpansionLayer > 0 {
			layered[f.FilePath] = struct{}{}
		}
	}
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

	seen := make(map[layerFindingKey]struct{})
	for i := range vulns {
		if f := fileOf(&vulns[i]); f != nil && f.ExpansionLayer == 0 {
			seen[newLayerFindingKey(&vulns[i], f.FilePath)] = struct{}{}
		}
	}
	kept := vulns[:0]
	for i := range vulns {
		f := fileOf(&vulns[i])
		if f == nil || f.ExpansionLayer == 0 {
			kept = append(kept, vulns[i])
			continue
		}
		key := newLayerFindingKey(&vulns[i], f.FilePath)
		if _, repeated := seen[key]; repeated {
			continue
		}
		seen[key] = struct{}{}
		kept = append(kept, vulns[i])
	}
	return kept
}
