/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import "github.com/DataDog/datadog-iac-scanner/pkg/model"

const platformCICD = "cicd"

// ciCDWalker enumerates GitHub Actions jobs, composite actions, and Dependabot
// update entries.
type ciCDWalker struct{}

func (ciCDWalker) Platform() string { return platformCICD }

func (ciCDWalker) Kinds() []model.FileKind {
	return []model.FileKind{model.KindYAML, model.KindYML}
}

func (ciCDWalker) Walk(filePath string, doc model.Document) ([]Resource, bool) {
	if jobs, ok := toMap(doc["jobs"]); ok {
		return walkCICDJobs(filePath, jobs), true
	}
	if updates, ok := doc["updates"].([]interface{}); ok {
		return walkDependabotUpdates(filePath, updates), true
	}
	if runs, ok := toMap(doc["runs"]); ok {
		if _, isAction := runs["using"]; isAction {
			return []Resource{newCompositeAction(filePath, doc)}, true
		}
	}
	return nil, false
}

func walkCICDJobs(filePath string, jobs map[string]interface{}) []Resource {
	var resources []Resource
	for _, jobID := range sortedKeys(jobs) {
		body, ok := toMap(jobs[jobID])
		if !ok {
			continue
		}
		start, end := lineBounds(body)
		resources = append(resources, Resource{
			Platform:   platformCICD,
			BlockType:  BlockJob,
			Name:       jobID,
			File:       filePath,
			StartLine:  start,
			EndLine:    end,
			Attributes: attrsFromBody(body),
		})
	}
	return resources
}

func walkDependabotUpdates(filePath string, updates []interface{}) []Resource {
	var resources []Resource
	for _, u := range updates {
		update, ok := toMap(u)
		if !ok {
			continue
		}
		ecosystem, _ := update["package-ecosystem"].(string)
		name, _ := update["directory"].(string)
		if name == "" {
			name = ecosystem
		}
		if name == "" {
			continue // skip malformed entries with neither directory nor ecosystem
		}
		start, end := lineBounds(update)
		resources = append(resources, Resource{
			Platform:   platformCICD,
			BlockType:  BlockJob,
			Type:       ecosystem,
			Name:       name,
			File:       filePath,
			StartLine:  start,
			EndLine:    end,
			Attributes: attrsFromBody(update),
		})
	}
	return resources
}

func newCompositeAction(filePath string, doc model.Document) Resource {
	name, _ := doc["name"].(string)
	start, end := lineBounds(doc)
	attrs := attrsFromBody(doc)
	deleteInjectedKeys(attrs)
	return Resource{
		Platform:   platformCICD,
		BlockType:  BlockJob,
		Type:       "composite-action",
		Name:       name,
		File:       filePath,
		StartLine:  start,
		EndLine:    end,
		Attributes: attrs,
	}
}
