/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package platform

import (
	"encoding/json"
	"strings"
)

type structuralDefinition struct {
	platform        ID
	extensions      []string
	requiresContent bool
	analyzerRank    int
	matches         func(map[string]interface{}) bool
}

var structuralDefinitions = []structuralDefinition{
	{
		platform:        Kubernetes,
		extensions:      []string{".json", ".conf", ".conflist"},
		requiresContent: true,
		analyzerRank:    1,
		matches:         isCNIConfig,
	},
	{
		platform: Terraform,
		matches:  matchesTerraformDocument,
	},
	{
		platform:        CloudFormation,
		extensions:      []string{".yaml", ".yml"},
		requiresContent: true,
		analyzerRank:    20,
		matches:         hasAnyKey("Resources"),
	},
	{
		platform:        Kubernetes,
		extensions:      []string{".yaml", ".yml"},
		requiresContent: true,
		analyzerRank:    10,
		matches:         hasAllKeys("kind", "apiVersion"),
	},
	{
		platform: Dockerfile,
		matches:  hasAnyKey("command"),
	},
	{
		platform:        CICD,
		extensions:      []string{".yaml", ".yml"},
		requiresContent: true,
		analyzerRank:    30,
		matches:         hasAllKeys("jobs", "on"),
	},
	{
		platform: Ansible,
		matches:  hasAnyKey("playbooks", "groups", "all"),
	},
}

// StructuralExtensions returns extensions admitted by structural classifiers.
func StructuralExtensions() []string {
	extensions := make([]string, 0)
	seen := make(map[string]struct{})
	for _, definition := range structuralDefinitions {
		for _, extension := range definition.extensions {
			if _, ok := seen[extension]; ok {
				continue
			}
			seen[extension] = struct{}{}
			extensions = append(extensions, extension)
		}
	}
	return extensions
}

// StructuralClassificationRequiresContent reports whether an extension needs content for classification.
func StructuralClassificationRequiresContent(extension string) bool {
	for _, definition := range structuralDefinitions {
		if definition.requiresContent && containsExtension(definition.extensions, extension) {
			return true
		}
	}
	return false
}

// ClassifyStructuredContent classifies a supported structured file.
func ClassifyStructuredContent(extension string, content []byte) (ID, bool) {
	var document map[string]interface{}
	if err := json.Unmarshal(content, &document); err != nil {
		return "", false
	}
	return ClassifyStructuredDocument(extension, document)
}

// ClassifyStructuredDocument classifies an already parsed analyzer document.
func ClassifyStructuredDocument(extension string, document map[string]interface{}) (ID, bool) {
	var selected *structuralDefinition
	for _, definition := range structuralDefinitions {
		if !containsExtension(definition.extensions, extension) || !definition.matches(document) {
			continue
		}
		if selected == nil || definition.analyzerRank < selected.analyzerRank {
			definition := definition
			selected = &definition
		}
	}
	if selected == nil {
		return "", false
	}
	return selected.platform, true
}

// ClassifyDocument classifies an already parsed document.
func ClassifyDocument(document map[string]interface{}) (ID, bool) {
	for _, definition := range structuralDefinitions {
		if definition.matches(document) {
			return definition.platform, true
		}
	}
	return "", false
}

// IsRequested reports whether a platform is allowed by a requested platform filter.
func IsRequested(id ID, requested []string) bool {
	if len(requested) == 0 || (len(requested) == 1 && requested[0] == "") {
		return true
	}
	for _, name := range requested {
		if requestedID, ok := CanonicalID(name); ok && requestedID == id {
			return true
		}
	}
	return false
}

func containsExtension(extensions []string, extension string) bool {
	extension = strings.ToLower(extension)
	for _, candidate := range extensions {
		if candidate == extension {
			return true
		}
	}
	return false
}

func hasAnyKey(keys ...string) func(map[string]interface{}) bool {
	return func(document map[string]interface{}) bool {
		for _, key := range keys {
			if document[key] != nil {
				return true
			}
		}
		return false
	}
}

func hasAllKeys(keys ...string) func(map[string]interface{}) bool {
	return func(document map[string]interface{}) bool {
		for _, key := range keys {
			if document[key] == nil {
				return false
			}
		}
		return true
	}
}

func matchesTerraformDocument(document map[string]interface{}) bool {
	// Kubernetes manifests also use a top-level "data" field (ConfigMap, Secret, ...).
	if isKubernetesManifest(document) {
		return false
	}
	return hasAnyKey("resource", "data", "module", "variable", "output", "terraform")(document)
}

func isKubernetesManifest(document map[string]interface{}) bool {
	kind, _ := document["kind"].(string)
	apiVersion, _ := document["apiVersion"].(string)
	return kind != "" && apiVersion != ""
}

func isCNIConfig(document map[string]interface{}) bool {
	version, ok := document["cniVersion"].(string)
	if !ok || version == "" {
		return false
	}
	if plugins, ok := document["plugins"].([]interface{}); ok && plugins != nil {
		return true
	}
	pluginType, ok := document["type"].(string)
	return ok && pluginType != ""
}
