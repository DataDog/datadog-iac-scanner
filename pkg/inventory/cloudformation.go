/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

const platformCloudFormation = "cloudformation"

// cloudFormationWalker enumerates the logical resources declared under a
// template's top-level `Resources` mapping.
type cloudFormationWalker struct{}

func (cloudFormationWalker) Platform() string { return platformCloudFormation }

func (cloudFormationWalker) Kinds() []model.FileKind {
	return []model.FileKind{model.KindYAML, model.KindYML, model.KindJSON}
}

func (cloudFormationWalker) Walk(filePath string, doc model.Document) ([]Resource, bool) {
	// Require a CloudFormation marker before touching the Resources map, so
	// arbitrary YAML with a "Resources" key (Helm values, K8s ResourceQuota,
	// etc.) is not misclassified.
	if !isCFNTemplate(doc) {
		return nil, false
	}
	resourcesMap, ok := toMap(doc["Resources"])
	if !ok {
		return nil, false
	}

	var resources []Resource
	for _, logicalID := range sortedKeys(resourcesMap) {
		body, ok := toMap(resourcesMap[logicalID])
		if !ok {
			continue
		}
		resType, _ := body["Type"].(string)
		start, end := lineBounds(body)
		resources = append(resources, Resource{
			Platform:   platformCloudFormation,
			BlockType:  BlockResource,
			Type:       resType,
			Name:       logicalID,
			Provider:   cfnProvider(resType),
			File:       filePath,
			StartLine:  start,
			EndLine:    end,
			Attributes: attrsFromBody(body),
		})
	}
	if len(resources) == 0 {
		return nil, false
	}
	return resources, true
}

// isCFNTemplate reports whether a document looks like a CloudFormation template.
// We require either the canonical AWSTemplateFormatVersion/Transform keys, or
// at least one resource entry with a Type field (the CFN resource shape).
func isCFNTemplate(doc model.Document) bool {
	if _, ok := doc["AWSTemplateFormatVersion"]; ok {
		return true
	}
	if _, ok := doc["Transform"]; ok {
		return true
	}
	// Fallback: at least one entry in Resources must be a map with a Type field.
	resourcesMap, ok := toMap(doc["Resources"])
	if !ok {
		return false
	}
	for _, v := range resourcesMap {
		if body, ok := toMap(v); ok {
			if _, hasType := body["Type"]; hasType {
				return true
			}
		}
	}
	return false
}

// cfnProvider derives a provider from a CloudFormation resource type, e.g.
// "AWS::S3::Bucket" -> "aws", "Custom::MyThing" -> "custom".
func cfnProvider(resType string) string {
	if resType == "" {
		return ""
	}
	if idx := strings.Index(resType, "::"); idx > 0 {
		return strings.ToLower(resType[:idx])
	}
	return strings.ToLower(resType)
}
