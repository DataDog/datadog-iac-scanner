/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"

	platformreg "github.com/DataDog/datadog-iac-scanner/pkg/platform"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/resourceindex"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// platformPayloads holds per-platform OPA input payloads built once per scan.
type platformPayloads struct {
	byPlatform       map[string]ast.Value
	lookupByPlatform map[string]map[string]resourceindex.ResourceMetadata
	full             ast.Value
	fullLookup       map[string]resourceindex.ResourceMetadata
}

// Unknown documents are included in every platform payload to preserve coverage.
func partitionDocsByPlatform(
	filesMap map[string]*model.FileMetadata,
	combinedDocs, moduleDocs []model.Document,
) (byPlatform map[string][]interface{}, unknown, all []interface{}) {
	byPlatform = make(map[string][]interface{})
	addDoc := func(d model.Document) {
		m := map[string]interface{}(d)
		all = append(all, m)
		id, _ := d["id"].(string)
		var platform string
		if fm := filesMap[id]; fm != nil {
			platform = fm.Platform
		}
		if platform == "" {
			if classified, ok := platformreg.ClassifyDocument(m); ok {
				platform = string(classified)
			}
		}
		keys := platformBucketKeys(platform)
		if len(keys) == 0 {
			unknown = append(unknown, m)
			return
		}
		for _, key := range keys {
			byPlatform[key] = append(byPlatform[key], m)
		}
	}
	for _, d := range combinedDocs {
		addDoc(d)
	}
	for _, d := range moduleDocs {
		addDoc(d)
	}
	return byPlatform, unknown, all
}

func (c *Inspector) buildPlatformPayloads(
	ctx context.Context,
	filesMap map[string]*model.FileMetadata,
	combinedDocs, moduleDocs []model.Document,
	queries []model.QueryMetadata,
) (platformPayloads, error) {
	docsByPlatform, unknownDocs, allDocs := partitionDocsByPlatform(filesMap, combinedDocs, moduleDocs)
	fullResourceIndex, fullLookup := resourceindex.BuildWithLookup(allDocs, filesMap)

	makePayload := func(ds []interface{}, index map[string]interface{}) (ast.Value, error) {
		v, err := ast.InterfaceToValue(map[string]interface{}{
			"document":  ds,
			"resources": index,
		})
		if err != nil {
			return nil, err
		}
		return c.TransformJsonencodeInPayload(ctx, v), nil
	}

	needFullPayload := false
	neededPlatforms := make(map[string]struct{})
	for i := range queries {
		key := canonicalPlatformKey(queries[i].Platform)
		if platformreg.IsCrossPlatformRule(queries[i].Platform) {
			needFullPayload = true
			continue
		}
		neededPlatforms[key] = struct{}{}
	}

	payloads := platformPayloads{
		byPlatform:       make(map[string]ast.Value, len(neededPlatforms)),
		lookupByPlatform: make(map[string]map[string]resourceindex.ResourceMetadata, len(neededPlatforms)),
	}
	for key := range neededPlatforms {
		documents := docsByPlatform[key]
		if len(unknownDocs) > 0 {
			combined := make([]interface{}, 0, len(documents))
			combined = append(combined, documents...)
			combined = append(combined, unknownDocs...)
			documents = combined
		}
		index, lookup := resourceindex.FilterByDocumentIDs(fullResourceIndex, fullLookup, documentIDs(documents))
		payload, err := makePayload(documents, index)
		if err != nil {
			return platformPayloads{}, err
		}
		payloads.byPlatform[key] = payload
		payloads.lookupByPlatform[key] = lookup
	}

	if needFullPayload {
		payload, err := makePayload(allDocs, fullResourceIndex)
		if err != nil {
			return platformPayloads{}, err
		}
		payloads.full = payload
		payloads.fullLookup = fullLookup
	}

	return payloads, nil
}

func documentIDs(docs []interface{}) map[string]struct{} {
	ids := make(map[string]struct{}, len(docs))
	for _, rawDoc := range docs {
		doc, ok := rawDoc.(map[string]interface{})
		if !ok {
			continue
		}
		if id, ok := doc["id"].(string); ok && id != "" {
			ids[id] = struct{}{}
		}
	}
	return ids
}

func platformBucketKeys(platform string) []string {
	key := canonicalPlatformKey(platform)
	if key == "" {
		return nil
	}
	targets := platformreg.PayloadTargets(key)
	if len(targets) == 0 {
		return []string{key}
	}
	result := make([]string, len(targets))
	for i, id := range targets {
		result[i] = string(id)
	}
	return result
}
