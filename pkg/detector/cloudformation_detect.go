/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package detector

import (
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// NeedsCloudFormationLoopLineInfo reports whether a legacy resource search may
// need parser provenance.
func NeedsCloudFormationLoopLineInfo(file *model.FileMetadata, searchKey string) bool {
	return file.HasCloudFormationLoopMarker() && cloudFormationResourceSearch(file.Kind, searchKey)
}

func cloudFormationResourceSearch(kind model.FileKind, searchKey string) bool {
	return (kind == model.KindYAML || kind == model.KindYML) &&
		(strings.HasPrefix(searchKey, "Resources.") || strings.HasPrefix(searchKey, "Resources["))
}

func detectCloudFormationLoopLine(file *model.FileMetadata, searchKey string, outputLines int) (model.VulnerabilityLines, bool) {
	if file.LineInfoDocument == nil || !cloudFormationResourceSearch(file.Kind, searchKey) {
		return model.VulnerabilityLines{}, false
	}
	path := cloudFormationSearchPath(searchKey)
	if len(path) < 2 {
		return model.VulnerabilityLines{}, false
	}
	resources, _ := file.LineInfoDocument["Resources"].(map[string]interface{})
	lines, _ := resources[lineInfoKey].(map[string]*model.LineObject)
	marker := lines["_dd_"+path[1]]
	// The parser gives a generated resource mapping its loop's three
	// sequence-argument markers. A written resource mapping has no such array.
	if _, mapping := resources[path[1]].(map[string]interface{}); !mapping || marker == nil || len(marker.Arr) != 3 {
		return model.VulnerabilityLines{}, false
	}
	if len(path) > 2 {
		if result, err := sourceLines(file, GetLineBySearchLine(path, file), outputLines); err == nil {
			return result, true
		}
	}
	result, err := sourceLines(file, marker.Line, outputLines)
	return result, err == nil
}

func cloudFormationSearchPath(searchKey string) []string {
	if !strings.Contains(searchKey, "{{") {
		return expandSearchKeyPath(searchKey)
	}
	// Keep wrapped keys opaque while splitting on dots, brackets and anchors.
	var substitutions []string
	for i, wrapped := range GetBracketValues(searchKey, nil, "") {
		placeholder := "\x00" + strconv.Itoa(i) + "\x00"
		searchKey = strings.ReplaceAll(searchKey, wrapped[0], placeholder)
		substitutions = append(substitutions, placeholder, wrapped[1])
	}
	path := expandSearchKeyPath(searchKey)
	unwrap := strings.NewReplacer(substitutions...)
	for i, component := range path {
		path[i] = unwrap.Replace(component)
	}
	return path
}
