/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/tidwall/gjson"
)

// searchLineDetector is the struct used to get the line from the payload with lines information
// content - payload with line information
// resolvedPath - string created from pathComponents, used to create gjson paths
// resolvedArrayPath - string created from pathComponents containing an array used to create gjson paths
// targetObj - key of the interface{}, we want the line from
type searchLineDetector struct {
	content           []byte
	resolvedPath      string
	resolvedArrayPath string
	targetObj         string
}

// GetLineBySearchLine makes use of the gjson pkg to find the line of a key in the original file
// with it's path given by a slice of strings
func GetLineBySearchLine(pathComponents []string, file *model.FileMetadata) (int, error) {
	content, err := json.Marshal(file.LineInfoDocument)
	if err != nil {
		return -1, err
	}

	detector := &searchLineDetector{
		content: content,
	}

	return detector.preparePath(pathComponents), nil
}

// preparePath resolves the path components and retrives important information
// for the creation of the paths to search
func (d *searchLineDetector) preparePath(pathItems []string) int {
	if len(pathItems) == 0 {
		return 1
	}
	// Escaping '.' in path components so it doesn't conflict with gjson pkg
	objPath := strings.ReplaceAll(pathItems[0], ".", "\\.")
	ArrPath := strings.ReplaceAll(pathItems[0], ".", "\\.")

	obj := pathItems[len(pathItems)-1]

	arrayObject := ""

	// Iterate reversely through the path components and get the key of the last array in the path
	// needed for cases where the fields in the array are <"key": "value"> type and not <object>
	foundArrayIdx := false
	for i := len(pathItems) - 1; i >= 0; i-- {
		if _, err := strconv.Atoi(pathItems[i]); err == nil {
			foundArrayIdx = true
			continue
		}
		if foundArrayIdx {
			arrayObject = pathItems[i]
			break
		}
	}

	if arrayObject == objPath {
		ArrPath = "_dd_lines._dd_" + arrayObject + "._dd_arr"
	}

	var treatedPathItems []string
	if len(pathItems) > 1 {
		treatedPathItems = pathItems[1 : len(pathItems)-1]
	}

	// Create a string based on the path components so it can be later transformed in a gjson path
	for _, pathItem := range treatedPathItems {
		// In case of an array present
		if pathItem == arrayObject {
			ArrPath += "._dd_lines._dd_" + strings.ReplaceAll(pathItem, ".", "\\.") + "._dd_arr"
		} else {
			ArrPath += "." + strings.ReplaceAll(pathItem, ".", "\\.")
		}
		objPath += "." + strings.ReplaceAll(pathItem, ".", "\\.")
	}

	d.resolvedPath = objPath
	d.resolvedArrayPath = ArrPath
	d.targetObj = obj

	return d.getResult()
}

// getResult creates the paths to be used by gjson pkg to find the line in the content
func (d *searchLineDetector) getResult() int {
	// Escape '.' like preparePath does for every other path segment, so a dotted
	// targetObj isn't misread by gjson as nested path segments.
	targetObj := strings.ReplaceAll(d.targetObj, ".", "\\.")
	pathObjects := []string{
		d.resolvedPath + "._dd_lines._dd_" + targetObj + "._dd_line",
		d.resolvedPath + "." + targetObj + "._dd_lines._dd__default._dd_line",
		d.resolvedArrayPath + "." + targetObj + "._dd__default._dd_line",
		d.resolvedArrayPath + "._dd_" + targetObj + "._dd_line",
	}

	result := -1
	// run gjson pkg
	for _, pathItem := range pathObjects {
		if tmpResult := gjson.GetBytes(d.content, pathItem); int(tmpResult.Int()) > 0 {
			result = int(tmpResult.Int())
			break
		}
	}
	return result
}
