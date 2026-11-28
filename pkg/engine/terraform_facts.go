/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2026 Datadog, Inc.
 */
package engine

import (
	"fmt"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
)

type terraformFactsQueryKey struct {
	platform string
	query    string
	content  string
}

type terraformFactPathNode struct {
	children    map[model.PathSegment]*terraformFactPathNode
	factIndices []int
}

func terraformFactsKey(query *model.QueryMetadata) terraformFactsQueryKey {
	return terraformFactsQueryKey{
		platform: canonicalPlatformKey(query.Platform),
		query:    query.Query,
		content:  query.Content,
	}
}

func terraformLibraryFactsNeeds(modules map[string]*ast.Module) map[string]bool {
	needs := make(map[string]bool, len(modules))
	for platform, mod := range modules {
		needs[platform] = moduleNeedsTerraformFacts(mod)
	}
	return needs
}

// TerraformFactsRequested reports whether any selected Terraform query or
// loaded Terraform library might inspect the additive evaluator facts. A
// malformed query is treated conservatively because its input use is unknown.
func (q *QueryLoader) TerraformFactsRequested(queries []model.QueryMetadata, terraformSelected bool) bool {
	for i := range queries {
		query := &queries[i]
		platform := canonicalPlatformKey(query.Platform)
		if platform != platformTerraform && (!terraformSelected || platform != platformCommon) {
			continue
		}
		if q.commonNeedsFacts || q.genericNeedsFacts[query.Platform] {
			return true
		}
		needsFacts, known := q.queryNeedsFacts[terraformFactsKey(query)]
		if !known {
			mod, err := parseQueryForPlan(query, 0)
			needsFacts = err != nil || moduleNeedsTerraformFacts(mod)
		}
		if needsFacts {
			return true
		}
	}
	return false
}

func includesTerraform(platforms []string) bool {
	for _, platform := range platforms {
		if canonicalPlatformKey(platform) == platformTerraform {
			return true
		}
	}
	return false
}

func parseQueryForPlan(query *model.QueryMetadata, index int) (*ast.Module, error) {
	rename := pkgDatadogDecl.ReplaceAllString(query.Content, fmt.Sprintf("${1}package datadog.q%d", index))
	return ast.ParseModuleWithOpts(query.Query, rename, ast.ParserOptions{RegoVersion: ast.RegoV1})
}

func terraformRuleTargets(queries []model.QueryMetadata, factsEnabled bool, libraries ...string) *ruleTargets {
	if factsEnabled {
		return nil
	}
	return ruleTargetedResourceTypes(queries, libraries...)
}

func terraformFactsForDocument(doc interface{}, filesMap map[string]*model.FileMetadata) (string, *model.FileMetadata) {
	docMap, ok := doc.(map[string]interface{})
	if !ok {
		return "", nil
	}
	id, _ := docMap["id"].(string)
	if id == "" {
		return "", nil
	}
	fm := filesMap[id]
	if fm == nil || canonicalPlatformKey(fm.Platform) != platformTerraform || fm.TerraformFacts == nil {
		return id, nil
	}
	return id, fm
}

// adjustTerraformFactsForPayloadTransform reconciles facts with shape changes
// made by the legacy payload conversion. It only updates a fact when the exact
// string at its path was transformed during conversion of this payload.
func adjustTerraformFactsForPayloadTransform(
	facts *model.TerraformDocumentFacts,
	document map[string]interface{},
	jsonencodeCache map[ast.Value]ast.Value,
) {
	if facts == nil || len(jsonencodeCache) == 0 {
		return
	}
	for subjectIndex := range facts.Subjects {
		subject := &facts.Subjects[subjectIndex]
		changedPaths := terraformJSONEncodedFactPaths(subject, document, jsonencodeCache)
		if len(changedPaths) == 0 {
			continue
		}
		pathTree := newTerraformFactPathTree(subject.Values)
		markAdaptedAncestors(pathTree, subject.Values, changedPaths)
	}
}

func newTerraformFactPathTree(values []model.TerraformValueFact) *terraformFactPathNode {
	root := &terraformFactPathNode{}
	for factIndex, fact := range values {
		node := root
		for _, segment := range fact.Path {
			if node.children == nil {
				node.children = make(map[model.PathSegment]*terraformFactPathNode)
			}
			if node.children[segment] == nil {
				node.children[segment] = &terraformFactPathNode{}
			}
			node = node.children[segment]
		}
		node.factIndices = append(node.factIndices, factIndex)
	}
	return root
}

func terraformJSONEncodedFactPaths(
	subject *model.TerraformSubjectFacts,
	document map[string]interface{},
	jsonencodeCache map[ast.Value]ast.Value,
) []model.TerraformFactPath {
	changed := make([]model.TerraformFactPath, 0)
	for _, fact := range subject.Values {
		path := make(model.TerraformFactPath, 0, len(subject.Path)+len(fact.Path))
		path = append(path, subject.Path...)
		path = append(path, fact.Path...)
		raw, ok := terraformDocumentValueAtPath(document, path)
		if !ok {
			continue
		}
		original, ok := raw.(string)
		if !ok || !terraformStringWasTransformed(original, jsonencodeCache) {
			continue
		}
		changed = append(changed, fact.Path)
	}
	return changed
}

func terraformStringWasTransformed(original string, jsonencodeCache map[ast.Value]ast.Value) bool {
	legacyValue, found := jsonencodeCache[ast.String(original)]
	if !found {
		return false
	}
	legacyString, isString := legacyValue.(ast.String)
	return !isString || legacyString != ast.String(original)
}

func markAdaptedAncestors(
	root *terraformFactPathNode,
	values []model.TerraformValueFact,
	changedPaths []model.TerraformFactPath,
) {
	for _, changedPath := range changedPaths {
		node := root
		for depth, segment := range changedPath {
			node = node.children[segment]
			if node == nil {
				break
			}
			markAdaptedFacts(node, values, depth == len(changedPath)-1)
		}
	}
}

func markAdaptedFacts(node *terraformFactPathNode, values []model.TerraformValueFact, isChangedValue bool) {
	for _, factIndex := range node.factIndices {
		fact := &values[factIndex]
		fact.Presentation = model.TerraformPresentationAdapted
		if isChangedValue {
			fact.Children = model.TerraformChildrenUnknown
		}
	}
}

func terraformDocumentValueAtPath(document map[string]interface{}, path model.TerraformFactPath) (interface{}, bool) {
	var current interface{} = document
	for _, segment := range path {
		if segment.IsIndex {
			items, ok := current.([]interface{})
			if !ok || segment.Index < 0 || segment.Index >= len(items) {
				return nil, false
			}
			current = items[segment.Index]
			continue
		}
		values, ok := asStringMap(current)
		if !ok {
			return nil, false
		}
		var exists bool
		current, exists = values[segment.Key]
		if !exists {
			return nil, false
		}
	}
	return current, true
}

func attachTerraformFacts(
	payloads platformPayloads,
	factsTerms []*ast.Term,
	docIDs []string,
	bucketsPerDoc [][]string,
	unknownDocs []int,
	neededPlatforms map[string]bool,
) platformPayloads {
	indicesByPlatform := make(map[string][]int, len(neededPlatforms))
	for i, keys := range bucketsPerDoc {
		for _, key := range keys {
			if neededPlatforms[key] {
				indicesByPlatform[key] = append(indicesByPlatform[key], i)
			}
		}
	}
	for key := range neededPlatforms {
		indices := append([]int(nil), indicesByPlatform[key]...)
		indices = append(indices, unknownDocs...)
		if hasTerraformFacts(factsTerms, indices, false) {
			payloads.byPlatform[key] = addTerraformFactsEnvelope(payloads.byPlatform[key], factsTerms, docIDs, indices)
		}
	}
	if payloads.full != nil && hasTerraformFacts(factsTerms, nil, true) {
		indices := make([]int, len(docIDs))
		for i := range indices {
			indices[i] = i
		}
		payloads.full = addTerraformFactsEnvelope(payloads.full, factsTerms, docIDs, indices)
	}
	return payloads
}

func hasTerraformFacts(factsTerms []*ast.Term, indices []int, all bool) bool {
	if all {
		for _, term := range factsTerms {
			if term != nil {
				return true
			}
		}
		return false
	}
	for _, i := range indices {
		if i >= 0 && i < len(factsTerms) && factsTerms[i] != nil {
			return true
		}
	}
	return false
}

func addTerraformFactsEnvelope(payload ast.Value, factsTerms []*ast.Term, docIDs []string, indices []int) ast.Value {
	factsByDocument := ast.NewObject()
	for _, i := range indices {
		if i < 0 || i >= len(factsTerms) || factsTerms[i] == nil || docIDs[i] == "" {
			continue
		}
		factsByDocument.Insert(ast.StringTerm(docIDs[i]), factsTerms[i])
	}
	documents := ast.NewObject()
	documents.Insert(ast.StringTerm("documents"), ast.NewTerm(factsByDocument))
	envelope := ast.NewObject()
	_ = payload.(ast.Object).Iter(func(key, value *ast.Term) error {
		envelope.Insert(key, value)
		return nil
	})
	envelope.Insert(ast.StringTerm("_dd"), ast.NewTerm(documents))
	return envelope
}
