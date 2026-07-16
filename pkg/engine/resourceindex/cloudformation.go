/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resourceindex

import "strings"

const cfTypeUnknown = "unknown"

func indexCloudFormationDoc(index, doc map[string]interface{}, docID string) {
	templateAttrs := selectedAttrs(doc,
		"AWSTemplateFormatVersion", "Description", "Transform", "Metadata", "Conditions", "Mappings", "Outputs")
	addEntry(index, "cloudformation", "template",
		cfMakeEntry(templateAttrs, docID, "cloudformation", "template", ddPath()))

	if resources, ok := asMap(doc["Resources"]); ok {
		for logicalID, rawRes := range resources {
			if isInternalKey(logicalID) {
				continue
			}
			res, ok := asMap(rawRes)
			if !ok {
				continue
			}
			cfType, _ := res["Type"].(string)
			if cfType == "" {
				cfType = cfTypeUnknown
			}
			addEntry(index, cfType, logicalID, cfMakeEntry(res, docID, cfType, logicalID, ddPath("Resources", logicalID)))
			if cfType == cfTypeUnknown {
				for nestedName, nestedRaw := range res {
					nested, ok := asMap(nestedRaw)
					if !ok {
						continue
					}
					nestedType, _ := nested["Type"].(string)
					if !strings.HasPrefix(nestedType, "AWS::") {
						continue
					}
					addEntry(index, nestedType, logicalID,
						cfMakeEntry(nested, docID, nestedType, logicalID, ddPath("Resources", logicalID, nestedName)))
				}
			}
		}
	}

	if params, ok := asMap(doc["Parameters"]); ok {
		for parameterName, rawParameter := range params {
			if isInternalKey(parameterName) {
				continue
			}
			parameter, ok := asMap(rawParameter)
			if !ok {
				continue
			}
			addEntry(index, "Parameters", parameterName,
				cfMakeEntry(parameter, docID, "Parameter", parameterName, ddPath("Parameters", parameterName)))
		}
	}
}

func cfMakeEntry(attrs interface{}, docID, resourceType, resourceName string, path []interface{}) map[string]interface{} {
	entry := makeEntry(attrs, docID, resourceType, resourceName, path)
	setEvalScope(entry, "template", docID)
	return entry
}
