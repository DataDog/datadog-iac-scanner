/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
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
	facts     *model.TerraformDocumentFacts
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

func (m *rootMerge) addRootResources(resources []tfeval.ResolvedResource) int {
	count := 0
	for i := range resources {
		r := &resources[i]
		if r.ModuleAddress != "" || !m.targets.matches(r.Type) {
			continue
		}
		fm := m.byAbsPath[absPath(r.DefinedIn, m.repoPath)]
		if fm == nil {
			continue
		}
		projection := m.rootResources[fm.ID]
		if projection == nil {
			projection = &rootDocumentResources{
				resources: make(map[string]map[string]interface{}),
				data:      make(map[string]map[string]interface{}),
				instances: make(map[model.TerraformInstanceKey]model.TerraformInstance),
			}
			if m.factsEnabled {
				projection.facts = &model.TerraformDocumentFacts{
					Platform: model.TerraformFactsPlatform,
					Coverage: model.TerraformCoverageUnproven,
				}
			}
			m.rootResources[fm.ID] = projection
		}
		kind := blockKind(r)
		section, typ := projection.resources, kind
		if dataType, ok := strings.CutPrefix(kind, dataTypePrefix); ok {
			section, typ = projection.data, dataType
		}
		byName := section[typ]
		if byName == nil {
			byName = make(map[string]interface{})
			section[typ] = byName
		}
		var valueFacts model.TerraformValueFacts
		byName[r.Name], valueFacts = resolvedResourceDocument(m.ctx, r, m.factsEnabled)
		if m.factsEnabled {
			projection.facts.Subjects = append(projection.facts.Subjects,
				terraformResourceSubjectFacts(r, fm.ID, kind, r.Name, valueFacts))
		}
		base := tfeval.ResourceBaseName(r.Name)
		projection.instances[model.TerraformInstanceKey{Kind: rootSectionKind(r), Type: r.Type, Name: r.Name}] =
			model.TerraformInstance{Label: base, Suffix: strings.TrimPrefix(r.Name, base)}
		count++
	}
	return count
}

func terraformResourceSubjectFacts(
	r *tfeval.ResolvedResource,
	sourceID, kind, projectedName string,
	valueFacts model.TerraformValueFacts,
) model.TerraformSubjectFacts {
	_, address, addressComplete := r.PartialAddress()
	instanceSet := model.TerraformCompletenessUnproven
	if r.InstanceSetComplete {
		instanceSet = model.TerraformCompletenessComplete
	}
	return model.TerraformSubjectFacts{
		SourceDocumentID: sourceID,
		Path:             terraformSubjectPath(rootKindForBlock(kind), strings.TrimPrefix(kind, dataTypePrefix), projectedName),
		Address:          address, AddressComplete: addressComplete,
		InstanceSet: instanceSet, Values: valueFacts.Values, ValuesTruncated: valueFacts.Truncated,
	}
}

func terraformSubjectPath(kind, typ, name string) model.TerraformFactPath {
	return model.TerraformFactPath{
		model.TerraformKeySegment(kind),
		model.TerraformKeySegment(typ),
		model.TerraformKeySegment(name),
	}
}

func documentFactCoverage(
	doc map[string]interface{}, subjects []model.TerraformSubjectFacts,
) (coverage model.TerraformFactCoverage, reasons []string) {
	keys, ok := documentSubjectKeys(doc)
	if !ok {
		return model.TerraformCoverageUnproven, []string{"document_subject_shape_unknown"}
	}
	if len(keys) == 0 {
		return model.TerraformCoverageUnproven, []string{"no_subjects_emitted"}
	}
	factKeys, ok := factSubjectKeys(subjects)
	if !ok {
		return model.TerraformCoverageUnproven, []string{"fact_subject_mapping_unproven"}
	}
	return compareFactSubjectCoverage(keys, factKeys)
}

type factSubjectKey struct{ kind, typ, name string }

func documentSubjectKeys(doc map[string]interface{}) (map[factSubjectKey]bool, bool) {
	keys := make(map[factSubjectKey]bool)
	for _, section := range []string{"resource", "data"} {
		byType, ok := asStringMap(doc[section])
		if !ok {
			if doc[section] != nil {
				return nil, false
			}
			continue
		}
		for typ, rawNames := range byType {
			names, ok := asStringMap(rawNames)
			if !ok {
				return nil, false
			}
			for name := range names {
				keys[factSubjectKey{section, typ, name}] = true
			}
		}
	}
	return keys, true
}

func factSubjectKeys(subjects []model.TerraformSubjectFacts) (map[factSubjectKey]bool, bool) {
	factKeys := make(map[factSubjectKey]bool, len(subjects))
	for _, subject := range subjects {
		if len(subject.Path) != 3 || subject.Path[0].IsIndex || subject.Path[1].IsIndex || subject.Path[2].IsIndex {
			return nil, false
		}
		key := factSubjectKey{subject.Path[0].Key, subject.Path[1].Key, subject.Path[2].Key}
		if factKeys[key] {
			return nil, false
		}
		factKeys[key] = true
	}
	return factKeys, true
}

func compareFactSubjectCoverage(
	keys, factKeys map[factSubjectKey]bool,
) (coverage model.TerraformFactCoverage, reasons []string) {
	for key := range keys {
		if !factKeys[key] {
			return model.TerraformCoverageIncomplete, []string{"document_subject_without_fact"}
		}
	}
	for key := range factKeys {
		if !keys[key] {
			return model.TerraformCoverageIncomplete, []string{"fact_subject_not_in_document"}
		}
	}
	return model.TerraformCoverageComplete, nil
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

func (m *rootMerge) recordRootDeclarations(blocks []*hclsyntax.Block) {
	// Successful root evaluation accounts for every parsed declaration, including
	// blocks with count = 0 or an empty for_each. Those have no resource value
	// to project, but their as-written copy must not produce findings either.
	for _, block := range blocks {
		if len(block.Labels) != 2 || !m.targets.matches(block.Labels[0]) {
			continue
		}
		file := m.byAbsPath[absPath(block.TypeRange.Filename, m.repoPath)]
		if file == nil {
			continue
		}
		kind := block.Labels[0]
		if block.Type == dataRoot {
			kind = dataTypePrefix + kind
		}
		m.instantiated.add(file.ID, kind, block.Labels[1])
	}
}
