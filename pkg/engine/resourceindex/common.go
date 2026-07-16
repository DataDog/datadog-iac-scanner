/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package resourceindex builds typed rule input from parsed documents.
package resourceindex

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	platformreg "github.com/DataDog/datadog-iac-scanner/pkg/platform"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// Resource entry field names.
const (
	EntryCanonicalResourceType  = "resource_type"
	EntryCanonicalResourceName  = "resource_name"
	EntryAttributes             = "attributes"
	EntryScope                  = "scope"
	EntryRelationships          = "relationships"
	EntryResourceType           = "resourceType"
	EntryResourceName           = "resourceName"
	EntryDD                     = "_dd"
	EntryDDID                   = "id"
	EntryDDPath                 = "path"
	EntryDDScope                = "scope"
	EntryDDPlatform             = "platform"
	EntryDDDocumentID           = "documentId"
	EntryDDResourceID           = "resourceId" // index-internal occurrence ID for relationship scopes
	EntryDDFieldMap             = "fieldMap"
	EntryDDEvaluationScopes     = "evaluationScopes"
	EntryDDRelationshipScopes   = "relationshipScopes"
	EntryRelationshipParentKey  = "parentKey"
	EntryRelationshipPodSpecKey = "podSpecKey"
	K8sPodSpecBucket            = "k8s_pod_spec"
	K8sContainerBucket          = "k8s_container"
	K8sCNIConfigBucket          = "cni_config"
	GitHubActionBucket          = "github_action"
	GitHubJobBucket             = "github_job"
	GitHubStepBucket            = "github_step"
	GitHubServiceBucket         = "github_service"
	DependabotUpdateBucket      = "dependabot_update"

	k8sLibraryID    = "k8s"
	internalKeyPath = "_path"
)

type ResourceMetadata struct {
	DocumentID   string
	ResourceType string
	ResourceName string
	BasePath     model.Path
	FieldMap     ProvenanceMap
}

// Build creates rule input.
func Build(
	docs []interface{},
	filesMap map[string]*model.FileMetadata,
) map[string]interface{} {
	return buildResourceIndex(docs, filesMap)
}

// BuildWithLookup creates rule input and scanner-only metadata lookup.
func BuildWithLookup(
	docs []interface{},
	filesMap map[string]*model.FileMetadata,
) (index map[string]interface{}, lookup map[string]ResourceMetadata) {
	index = buildResourceIndex(docs, filesMap)
	lookup = finalizeEntries(index)
	return index, lookup
}

func buildResourceIndex(
	docs []interface{},
	filesMap map[string]*model.FileMetadata,
) map[string]interface{} {
	index := make(map[string]interface{})
	platforms := make(map[string]string)

	for _, rawDoc := range docs {
		doc, ok := asMap(rawDoc)
		if !ok {
			continue
		}
		docID, _ := doc["id"].(string)
		if docID == "" {
			continue
		}
		platform := ""
		if fm := filesMap[docID]; fm != nil {
			platform = strings.ToLower(fm.Platform)
		}
		if platform == "" {
			platform = platformFromDoc(doc)
		}
		platforms[docID] = platform

		switch platform {
		case string(platformreg.Terraform):
			indexTerraformDoc(index, doc, docID, filesMap[docID])
		case string(platformreg.CloudFormation), string(platformreg.ServerlessFW):
			indexCloudFormationDoc(index, doc, docID)
		case k8sLibraryID, string(platformreg.Kubernetes), string(platformreg.Knative), string(platformreg.Crossplane):
			source := docID
			if file := filesMap[docID]; file != nil && file.FilePath != "" {
				source = file.FilePath
			}
			indexKubernetesDoc(index, doc, docID, kubernetesClusterScope(filesMap[docID]), source)
		case string(platformreg.Dockerfile):
			indexDockerfileDoc(index, doc, docID)
		case string(platformreg.CICD):
			indexCICDDoc(index, doc, docID)
		case string(platformreg.Ansible):
			indexAnsibleDoc(index, doc, docID)
		}
	}
	setResourcePlatforms(index, platforms)
	return index
}

func finalizeEntries(index map[string]interface{}) map[string]ResourceMetadata {
	lookup := make(map[string]ResourceMetadata)
	for _, rawBucket := range index {
		bucket, ok := rawBucket.(map[string]interface{})
		if !ok {
			continue
		}
		for _, rawEntry := range bucket {
			entry, ok := rawEntry.(map[string]interface{})
			if !ok {
				continue
			}
			dd, ok := entry[EntryDD].(map[string]interface{})
			if !ok {
				continue
			}
			id, _ := dd[EntryDDResourceID].(string)
			documentID, _ := dd[EntryDDDocumentID].(string)
			resourceType, _ := entry[EntryCanonicalResourceType].(string)
			resourceName, _ := entry[EntryCanonicalResourceName].(string)
			path, err := model.DecodeOPAPath(dd[EntryDDPath])
			if id == "" || err != nil {
				continue
			}
			fieldMap, _ := dd[EntryDDFieldMap].(ProvenanceMap)
			if fieldMap == nil {
				if raw, ok := dd[EntryDDFieldMap].(map[string]string); ok {
					fieldMap = raw
				}
			}
			lookup[id] = ResourceMetadata{
				DocumentID:   documentID,
				ResourceType: resourceType,
				ResourceName: resourceName,
				BasePath:     path,
				FieldMap:     fieldMap,
			}
			entry[EntryDD] = map[string]interface{}{EntryDDID: id}
		}
	}
	return lookup
}

// Documents are not always JSON round-tripped before indexing.
func asMap(v interface{}) (map[string]interface{}, bool) {
	if v == nil {
		return nil, false
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m, true
	}
	if d, ok := v.(model.Document); ok {
		return map[string]interface{}(d), true
	}
	return nil, false
}

func setResourcePlatforms(index map[string]interface{}, platforms map[string]string) {
	for _, rawBucket := range index {
		bucket, ok := rawBucket.(map[string]interface{})
		if !ok {
			continue
		}
		for _, rawEntry := range bucket {
			entry, ok := rawEntry.(map[string]interface{})
			if !ok {
				continue
			}
			metadata, ok := entry[EntryDD].(map[string]interface{})
			if !ok {
				continue
			}
			scope, _ := metadata[EntryDDScope].(string)
			if p := platforms[scope]; p != "" {
				metadata[EntryDDPlatform] = p
				if scopes, ok := entry[EntryScope].(map[string]interface{}); ok {
					scopes["platform"] = p
				}
			}
		}
	}
}

func kubernetesClusterScope(file *model.FileMetadata) string {
	if file != nil && file.ScanID != "" {
		return file.ScanID
	}
	return "scan"
}

func publicDocumentAttrs(doc map[string]interface{}) map[string]interface{} {
	attrs := make(map[string]interface{}, len(doc))
	for k, v := range doc {
		switch k {
		case "id", "file", internalKeyPath:
			continue
		default:
			attrs[k] = v
		}
	}
	return attrs
}

func platformFromDoc(doc map[string]interface{}) string {
	if classified, ok := platformreg.ClassifyDocument(doc); ok {
		return string(classified)
	}
	return ""
}

func makeEntry(attrs interface{}, documentID, resourceType, resourceName string, path []interface{}) map[string]interface{} {
	return makeEntryWithContext(attrs, documentID, resourceType, resourceName, path, authoringContext{})
}

func makeCICDEntry(attrs interface{}, documentID, resourceType, resourceName string, path []interface{}) map[string]interface{} {
	return makeEntryWithContext(attrs, documentID, resourceType, resourceName, path, authoringContext{cicd: true})
}

func makeEntryWithContext(
	attrs interface{},
	documentID, resourceType, resourceName string,
	path []interface{},
	context authoringContext,
) map[string]interface{} {
	var entry map[string]interface{}
	var provenance ProvenanceMap
	if m, ok := asMap(attrs); ok {
		entry, provenance = authoringMapWithProvenance(m, context)
	} else {
		entry = make(map[string]interface{})
	}
	attributes := cloneMap(entry)
	entry[EntryResourceType] = resourceType
	entry[EntryResourceName] = resourceName
	entry[EntryCanonicalResourceType] = resourceType
	entry[EntryCanonicalResourceName] = resourceName
	entry[EntryAttributes] = attributes
	dd := map[string]interface{}{
		EntryDDPath:               path,
		EntryDDScope:              documentID, // backward-compat alias for documentId
		EntryDDDocumentID:         documentID,
		EntryDDResourceID:         makeOccurrenceID(documentID, path),
		EntryDDEvaluationScopes:   map[string]interface{}{},
		EntryDDRelationshipScopes: map[string]interface{}{},
	}
	if len(provenance) > 0 {
		dd[EntryDDFieldMap] = provenance
	}
	entry[EntryScope] = dd[EntryDDEvaluationScopes]
	entry[EntryRelationships] = dd[EntryDDRelationshipScopes]
	entry[EntryDD] = dd
	return entry
}

// Identity includes typed path boundaries to avoid ambiguous joins.
func makeOccurrenceID(documentID string, path []interface{}) string {
	encoded, err := json.Marshal([]interface{}{documentID, path})
	if err != nil {
		panic(fmt.Sprintf("encode resource identity: %v", err))
	}
	return fmt.Sprintf("%x", sha256.Sum256(encoded))
}

func setEvalScope(entry map[string]interface{}, key, value string) {
	if dd, ok := entry[EntryDD].(map[string]interface{}); ok {
		if scopes, ok := dd[EntryDDEvaluationScopes].(map[string]interface{}); ok {
			scopes[key] = value
		}
	}
}

func setRelScope(entry map[string]interface{}, key, value string) {
	if dd, ok := entry[EntryDD].(map[string]interface{}); ok {
		if scopes, ok := dd[EntryDDRelationshipScopes].(map[string]interface{}); ok {
			scopes[key] = value
		}
	}
}

func setEntryField(entry map[string]interface{}, key string, value interface{}) {
	entry[key] = value
	if attributes, ok := entry[EntryAttributes].(map[string]interface{}); ok {
		attributes[key] = value
	}
}

// ProvenanceMap maps renamed authoring paths to source fields.
type ProvenanceMap map[string]string

type authoringContext struct {
	cicd   bool
	filter bool
}

const filterOperatorSourceKey = "_op"

func authoringMapWithProvenance(
	source map[string]interface{},
	context authoringContext,
) (map[string]interface{}, ProvenanceMap) {
	result, _, provenance := normalizeAuthoringMap(source, context, true, true)
	return result, provenance
}

func normalizeAuthoringMap(
	source map[string]interface{},
	context authoringContext,
	forceCopy, collectProvenance bool,
) (result map[string]interface{}, changed bool, provenance ProvenanceMap) {
	normalizer := authoringNormalizer{
		source:            source,
		context:           context,
		collectProvenance: collectProvenance,
	}
	if forceCopy {
		normalizer.result = cloneMap(source)
	}

	for key, value := range source {
		if normalizer.normalizeSpecialField(key, value) {
			continue
		}
		mapped, changed := normalizeAuthoringValue(value, context)
		if changed {
			normalizer.ensureCopy()
			normalizer.result[key] = mapped
		}
	}

	return normalizer.finish()
}

type authoringNormalizer struct {
	source            map[string]interface{}
	result            map[string]interface{}
	context           authoringContext
	analysis          map[string]interface{}
	expressions       map[string]interface{}
	provenance        ProvenanceMap
	collectProvenance bool
}

func (n *authoringNormalizer) ensureCopy() {
	if n.result == nil {
		n.result = cloneMap(n.source)
	}
}

func (n *authoringNormalizer) recordProvenance(path, sourceKey string) {
	if !n.collectProvenance {
		return
	}
	if n.provenance == nil {
		n.provenance = make(ProvenanceMap)
	}
	n.provenance[path] = sourceKey
}

func (n *authoringNormalizer) normalizeSpecialField(key string, value interface{}) bool {
	if key == "_dd_filter_expr" {
		n.normalizeFilterExpression(key, value)
		return true
	}
	if n.normalizeFilterField(key, value) {
		return true
	}
	if n.normalizeCICDField(key, value) {
		return true
	}
	if strings.HasPrefix(key, "_dd_") || strings.HasPrefix(key, "_kics_") || key == "EndLine" {
		n.ensureCopy()
		delete(n.result, key)
		return true
	}
	return false
}

func (n *authoringNormalizer) normalizeFilterExpression(key string, value interface{}) {
	var mapped interface{}
	var nestedProvenance ProvenanceMap
	if nested, ok := asMap(value); ok {
		mapped, _, nestedProvenance = normalizeAuthoringMap(
			nested,
			authoringContext{filter: true},
			false,
			n.collectProvenance,
		)
	} else {
		mapped, _ = normalizeAuthoringValue(value, authoringContext{filter: true})
	}
	n.ensureCopy()
	delete(n.result, key)
	n.result["filterExpression"] = mapped
	n.recordProvenance("filterExpression", key)
	for path, sourceKey := range nestedProvenance {
		n.recordProvenance(path, sourceKey)
	}
}

func (n *authoringNormalizer) normalizeFilterField(key string, value interface{}) bool {
	if !n.context.filter {
		return false
	}
	target := ""
	switch key {
	case filterOperatorSourceKey:
		target = "operator"
	case "_left":
		target = "left"
	case "_right":
		target = "right"
	case "_selector":
		target = "selector"
	case "_value":
		target = "value"
	default:
		return false
	}
	mapped, _ := normalizeAuthoringValue(value, n.context)
	n.ensureCopy()
	delete(n.result, key)
	n.result[target] = mapped
	if key == filterOperatorSourceKey {
		n.recordProvenance("filterExpression.operator", key)
	}
	return true
}

func (n *authoringNormalizer) normalizeCICDField(key string, value interface{}) bool {
	if !n.context.cicd {
		return false
	}
	if strings.HasPrefix(key, "_parsed_expressions_") {
		name := strings.TrimPrefix(key, "_parsed_expressions_")
		mapped, _ := normalizeAuthoringValue(value, n.context)
		if n.expressions == nil {
			n.expressions = make(map[string]interface{})
		}
		n.expressions[name] = mapped
		n.ensureCopy()
		delete(n.result, key)
		return true
	}
	if !strings.HasPrefix(key, "_parsed_") {
		return false
	}
	name := strings.TrimPrefix(key, "_parsed_")
	mapped, _ := normalizeAuthoringValue(value, n.context)
	if n.analysis == nil {
		n.analysis = make(map[string]interface{})
	}
	n.analysis[name] = mapped
	n.ensureCopy()
	delete(n.result, key)
	n.recordProvenance("analysis."+name, key)
	return true
}

func (n *authoringNormalizer) finish() (
	result map[string]interface{},
	changed bool,
	provenance ProvenanceMap,
) {
	if len(n.expressions) > 0 {
		if n.analysis == nil {
			n.analysis = make(map[string]interface{})
		}
		n.analysis["expressions"] = n.expressions
	}
	if len(n.analysis) > 0 {
		n.ensureCopy()
		n.result["analysis"] = n.analysis
	}
	if n.result == nil {
		return n.source, false, n.provenance
	}
	return n.result, true, n.provenance
}

func cloneMap(source map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func normalizeAuthoringValue(value interface{}, context authoringContext) (interface{}, bool) {
	if mapped, ok := asMap(value); ok {
		result, changed, _ := normalizeAuthoringMap(mapped, context, false, false)
		if changed {
			return result, true
		}
		return value, false
	}
	if values, ok := value.([]interface{}); ok {
		var result []interface{}
		for i, item := range values {
			mapped, changed := normalizeAuthoringValue(item, context)
			if !changed {
				continue
			}
			if result == nil {
				result = append([]interface{}(nil), values...)
			}
			result[i] = mapped
		}
		if result != nil {
			return result, true
		}
	}
	return value, false
}

func addEntry(index map[string]interface{}, resourceType, resourceName string, entry map[string]interface{}) string {
	occurrenceID, _ := addEntryWithKey(index, resourceType, resourceName, entry)
	return occurrenceID
}

func addEntryWithKey(
	index map[string]interface{},
	resourceType, resourceName string,
	entry map[string]interface{},
) (occurrenceID, entryKey string) {
	bucket, ok := index[resourceType]
	if !ok {
		bucket = make(map[string]interface{})
		index[resourceType] = bucket
	}
	m := bucket.(map[string]interface{})
	key := resourceName
	occID := ""
	if metadata, ok := entry[EntryDD].(map[string]interface{}); ok {
		if docID, _ := metadata[EntryDDScope].(string); docID != "" {
			key = docID
			if encodedPath, err := json.Marshal(metadata[EntryDDPath]); err == nil {
				key = docID + "#" + string(encodedPath)
			}
		}
		occID, _ = metadata[EntryDDResourceID].(string)
	}
	baseKey := key
	for occurrence := 2; m[key] != nil; occurrence++ {
		key = fmt.Sprintf("%s#%d", baseKey, occurrence)
	}
	m[key] = entry
	return occID, key
}

func isInternalKey(key string) bool {
	return key == internalKeyPath || strings.HasPrefix(key, "_dd") || strings.HasPrefix(key, "_kics")
}

func ddPath(parts ...interface{}) []interface{} {
	out := make([]interface{}, len(parts))
	copy(out, parts)
	return out
}

func appendPath(base []interface{}, parts ...interface{}) []interface{} {
	result := make([]interface{}, 0, len(base)+len(parts))
	result = append(result, base...)
	result = append(result, parts...)
	return result
}

func stringsToInterfaces(values []string) []interface{} {
	result := make([]interface{}, len(values))
	for i, value := range values {
		result[i] = value
	}
	return result
}

func mapAtPath(root map[string]interface{}, path []string) (map[string]interface{}, bool) {
	current := root
	for _, component := range path {
		next, ok := asMap(current[component])
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

type indexedMapNode struct {
	value map[string]interface{}
	path  []interface{}
}

func mapNodesAtPath(root map[string]interface{}, path []string) []indexedMapNode {
	nodes := []indexedMapNode{{value: root}}
	for _, component := range path {
		next := make([]indexedMapNode, 0)
		for _, node := range nodes {
			value := node.value[component]
			if child, ok := asMap(value); ok {
				next = append(next, indexedMapNode{value: child, path: appendPath(node.path, component)})
				continue
			}
			if children, ok := value.([]interface{}); ok {
				for idx, rawChild := range children {
					if child, ok := asMap(rawChild); ok {
						next = append(next, indexedMapNode{
							value: child,
							path:  appendPath(node.path, component, idx),
						})
					}
				}
			}
		}
		nodes = next
		if len(nodes) == 0 {
			return nil
		}
	}
	return nodes
}

// Shared by native and Terraform Kubernetes adapters.
var nativeKubernetesWorkloadKinds = map[string]struct{}{
	"Pod":                   {},
	"Deployment":            {},
	"DaemonSet":             {},
	"StatefulSet":           {},
	"ReplicaSet":            {},
	"ReplicationController": {},
	"Job":                   {},
	"CronJob":               {},
	"DeploymentConfig":      {},
	"Configuration":         {},
	"Revision":              {},
	"ContainerSource":       {},
}

func nativeKubernetesPodSpec(doc map[string]interface{}, kind string) (spec map[string]interface{}, path []interface{}, ok bool) {
	if kind == "Service" {
		apiVersion, _ := doc["apiVersion"].(string)
		if !strings.Contains(apiVersion, "knative") {
			return nil, nil, false
		}
	} else if _, ok := nativeKubernetesWorkloadKinds[kind]; !ok {
		return nil, nil, false
	}

	for _, path := range [][]string{
		{"spec", "job_template", "spec", "template", "spec"},
		{"spec", "jobTemplate", "spec", "template", "spec"},
		{"spec", "template", "spec"},
		{"spec"},
	} {
		if spec, ok := mapAtPath(doc, path); ok {
			return spec, stringsToInterfaces(path), true
		}
	}
	return nil, nil, false
}

func selectedAttrs(source map[string]interface{}, names ...string) map[string]interface{} {
	result := make(map[string]interface{})
	for _, name := range names {
		if value, ok := source[name]; ok {
			result[name] = value
		}
	}
	return result
}

func firstNonEmptyString(source map[string]interface{}, names ...string) string {
	for _, name := range names {
		if value, ok := source[name].(string); ok && value != "" {
			return value
		}
	}
	return ""
}
