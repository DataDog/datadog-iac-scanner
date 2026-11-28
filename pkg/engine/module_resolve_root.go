/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// rootResourceProjection overlays evaluated root instances onto their
// original source documents, preserving same-file context and cardinality.
type rootResourceProjection map[string]*rootDocumentResources

type rootDocumentResources struct {
	resources map[string]map[string]interface{}
	data      map[string]map[string]interface{}
	instances map[model.TerraformInstanceKey]model.TerraformInstance
}

func overlayRootResources(doc map[string]interface{}, projection *rootDocumentResources) {
	if projection == nil {
		return
	}
	for _, section := range []struct {
		name   string
		blocks map[string]map[string]interface{}
	}{{"resource", projection.resources}, {"data", projection.data}} {
		if len(section.blocks) == 0 {
			continue
		}
		root := docAsMap(doc[section.name])
		if root == nil {
			root = make(map[string]interface{})
			doc[section.name] = root
		}
		for typ, names := range section.blocks {
			byName := docAsMap(root[typ])
			if byName == nil {
				byName = make(map[string]interface{})
				root[typ] = byName
			}
			for name, attrs := range names {
				byName[name] = attrs
			}
		}
	}
}

type rootSuppressedBlock struct {
	fileID string
	kind   string
	name   string
}

func projectRootResources(
	ctx context.Context,
	resources []tfeval.ResolvedResource,
	byAbsPath map[string]*model.FileMetadata,
	repoPath string,
	targets *ruleTargets,
) (projected rootResourceProjection, count int) {
	for i := range resources {
		r := &resources[i]
		if r.ModuleAddress != "" || !targets.matches(r.Type) {
			continue
		}
		fm := byAbsPath[absPath(r.DefinedIn, repoPath)]
		if fm == nil {
			continue
		}
		if projected == nil {
			projected = make(rootResourceProjection)
		}
		projection := projected[fm.ID]
		if projection == nil {
			projection = &rootDocumentResources{}
			projected[fm.ID] = projection
		}
		kind := blockKind(r)
		var section map[string]map[string]interface{}
		typ := kind
		if dataType, ok := strings.CutPrefix(kind, dataTypePrefix); ok {
			if projection.data == nil {
				projection.data = make(map[string]map[string]interface{})
			}
			section, typ = projection.data, dataType
		} else {
			if projection.resources == nil {
				projection.resources = make(map[string]map[string]interface{})
			}
			section = projection.resources
		}
		byName := section[typ]
		if byName == nil {
			byName = make(map[string]interface{})
			section[typ] = byName
		}
		byName[r.Name] = tfeval.AttributesToDocumentWithContext(ctx, r)
		base := tfeval.ResourceBaseName(r.Name)
		if r.Name != base {
			if projection.instances == nil {
				projection.instances = make(map[model.TerraformInstanceKey]model.TerraformInstance)
			}
			projection.instances[model.TerraformInstanceKey{Kind: rootSectionKind(r), Type: r.Type, Name: r.Name}] =
				model.TerraformInstance{Label: base, Suffix: strings.TrimPrefix(r.Name, base)}
		}
		count++
	}
	return projected, count
}

func collectRootSuppressed(
	blocks []*hclsyntax.Block,
	byAbsPath map[string]*model.FileMetadata,
	repoPath string,
	targets *ruleTargets,
) []rootSuppressedBlock {
	// Successful root evaluation accounts for every parsed declaration, including
	// blocks with count = 0 or an empty for_each. Those have no resource value
	// to project, but their as-written copy must not produce findings either.
	suppressed := make([]rootSuppressedBlock, 0, len(blocks))
	for _, block := range blocks {
		if len(block.Labels) != 2 || !targets.matches(block.Labels[0]) {
			continue
		}
		file := byAbsPath[absPath(block.TypeRange.Filename, repoPath)]
		if file == nil {
			continue
		}
		kind := block.Labels[0]
		if block.Type == dataRoot {
			kind = dataTypePrefix + kind
		}
		suppressed = append(suppressed, rootSuppressedBlock{
			fileID: file.ID,
			kind:   kind,
			name:   block.Labels[1],
		})
	}
	return suppressed
}

func (m *rootMerge) applyRootProjection(dir string, projected rootResourceProjection) {
	for _, f := range m.filesByDir[dir] {
		if f == nil {
			continue
		}
		replaced := m.instantiated[f.ID]
		if len(replaced) == 0 {
			continue
		}
		removeInstantiatedResources(f.Document, replaced)
		if projection := projected[f.ID]; projection != nil {
			overlayRootResources(f.Document, projection)
			f.TerraformInstances = projection.instances
		}
		m.rootApplied[f.ID] = true
	}
}

func (m *rootMerge) mergeRootProjection(projected rootResourceProjection) {
	for fileID, proj := range projected {
		existing := m.rootResources[fileID]
		if existing == nil {
			m.rootResources[fileID] = proj
			continue
		}
		for typ, names := range proj.resources {
			if existing.resources == nil {
				existing.resources = make(map[string]map[string]interface{})
			}
			if existing.resources[typ] == nil {
				existing.resources[typ] = names
				continue
			}
			for name, attrs := range names {
				existing.resources[typ][name] = attrs
			}
		}
		for typ, names := range proj.data {
			if existing.data == nil {
				existing.data = make(map[string]map[string]interface{})
			}
			if existing.data[typ] == nil {
				existing.data[typ] = names
				continue
			}
			for name, attrs := range names {
				existing.data[typ][name] = attrs
			}
		}
		for k, v := range proj.instances {
			if existing.instances == nil {
				existing.instances = make(map[model.TerraformInstanceKey]model.TerraformInstance)
			}
			existing.instances[k] = v
		}
	}
}

func rootSectionKind(r *tfeval.ResolvedResource) string {
	if r.Data {
		return "data"
	}
	return "resource"
}

func uniqueRootDeclarations(blocks []*hclsyntax.Block) bool {
	seen := make(map[model.TerraformBlock]bool, len(blocks))
	for _, block := range blocks {
		if len(block.Labels) != 2 {
			continue
		}
		key := model.TerraformBlock{Kind: block.Type, Type: block.Labels[0], Name: block.Labels[1]}
		if seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func (m *rootMerge) recordRootSuppressed(blocks []rootSuppressedBlock) {
	for _, b := range blocks {
		m.instantiated.add(b.fileID, b.kind, b.name)
	}
}
