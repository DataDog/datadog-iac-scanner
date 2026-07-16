/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// GetLineBySearchLine resolves the source line of a value identified by a
// structured path (a slice of keys and array indices) against the line metadata
// embedded in the parsed document.
func GetLineBySearchLine(pathComponents []string, file *model.FileMetadata) (int, error) {
	path := make(model.Path, len(pathComponents))
	for i, component := range pathComponents {
		path[i] = model.PathElement{Key: component}
		if i > 0 {
			if index, err := strconv.Atoi(component); err == nil && index >= 0 {
				path[i] = model.PathElement{Index: index, IsIndex: true}
			}
		}
	}
	return GetLineByPath(path, file)
}

func GetLineByPath(path model.Path, file *model.FileMetadata) (int, error) {
	line, _, err := GetLineByPathWithResolution(path, file)
	return line, err
}

func GetLineByPathWithResolution(path model.Path, file *model.FileMetadata) (int, PathResolution, error) {
	pathComponents := resolutionComponents(path)
	if len(pathComponents) == 0 {
		return 1, PathResolution{StructuralExact: true}, nil
	}

	line, remaining, stoppedStr, jsonAnchor := lineFromPath(file.LineInfoDocument, pathComponents)
	resolution := PathResolution{
		MatchedElements: len(pathComponents) - len(remaining),
		TotalElements:   len(pathComponents),
		StructuralExact: len(remaining) == 0 && stoppedStr == "",
	}
	if len(remaining) > 0 && stoppedStr != "" && line > 0 && file.LinesOriginalData != nil {
		// The walk stopped on a JSON-encoded string (e.g. an IAM policy
		// in a heredoc). Try to resolve the remaining path within the JSON.
		if offset := jsonPathLineOffset(stoppedStr, remaining); offset >= 0 {
			// For a heredoc ("= <<EOF\n{...}"), the content begins on the
			// line *after* the attribute declaration; inline strings start
			// on the same line.
			fileLines := *file.LinesOriginalData
			attrLine := terraformPlanJSONAnchorLine(line, jsonAnchor, stoppedStr) // 1-based
			contentStartLine := attrLine
			if attrLine > 0 && attrLine <= len(fileLines) {
				if strings.Contains(fileLines[attrLine-1], "<<") {
					contentStartLine = attrLine + 1
				}
			}
			resolution.MatchedElements = len(pathComponents)
			resolution.StructuralExact = true
			return contentStartLine + offset, resolution, nil
		}
	}
	return line, resolution, nil
}

const numericKeyPrefix = "\x00key:"

func resolutionComponents(path model.Path) []string {
	components := make([]string, len(path))
	for i, element := range path {
		if element.IsIndex {
			components[i] = strconv.Itoa(element.Index)
			continue
		}
		components[i] = element.Key
		if _, err := strconv.Atoi(element.Key); err == nil {
			components[i] = numericKeyPrefix + element.Key
		}
	}
	return components
}

// terraformPlanJSONAnchorLine picks the 1-based line at which to start resolving the
// remaining path inside a JSON-encoded string. Terraform plan JSON stores each
// policy attribute twice: minified in planned_values (single line, so any
// in-string offset resolves to 0) and pretty-printed in the configuration
// section's expressions.<attr>.constant_value. The configuration declaration
// line (jsonAnchor) is always the more precise anchor when available; it is
// only skipped for genuinely different values, such as multi-line heredoc
// strings, which carry their own real line breaks and no constant_value anchor.
func terraformPlanJSONAnchorLine(line, jsonAnchor int, stoppedStr string) int {
	trimmed := strings.TrimSpace(stoppedStr)
	if jsonAnchor > 0 && strings.HasPrefix(trimmed, "{") && !strings.Contains(stoppedStr, "\n") {
		return jsonAnchor
	}
	return line
}

// jsonPathLineOffset traverses a JSON string following path and returns the
// 0-based line number (within the JSON string) of the target value.
// Path components are object keys (case-insensitive) or array indices as strings.
// Returns -1 on any failure.
func jsonPathLineOffset(jsonStr string, path []string) int {
	if len(path) == 0 {
		return -1
	}

	dec := json.NewDecoder(strings.NewReader(jsonStr))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return -1
	}

	return walkJSONPath(dec, jsonStr, tok, int(dec.InputOffset())-1, path, false)
}

func walkJSONPath(
	dec *json.Decoder,
	jsonStr string,
	tok json.Token,
	tokenOffset int,
	path []string,
	statementObject bool,
) int {
	delim, ok := tok.(json.Delim)
	if !ok {
		return -1
	}

	if statementObject && delim == '{' && isVirtualStatementIndex(path[0]) {
		if len(path) == 1 {
			return jsonTokenLineOffset(jsonStr, tokenOffset)
		}
		return walkJSONPath(dec, jsonStr, tok, tokenOffset, path[1:], false)
	}

	var (
		nextTok    json.Token
		nextOffset int
		err        error
	)
	switch delim {
	case '{':
		nextTok, nextOffset, err = jsonObjectValue(dec, path[0])
	case '[':
		nextTok, nextOffset, err = jsonArrayValue(dec, path[0])
	default:
		return -1
	}
	if err != nil {
		return -1
	}
	if len(path) == 1 {
		return jsonTokenLineOffset(jsonStr, nextOffset)
	}

	return walkJSONPath(
		dec,
		jsonStr,
		nextTok,
		nextOffset,
		path[1:],
		delim == '{' && strings.EqualFold(path[0], "Statement"),
	)
}

func jsonObjectValue(dec *json.Decoder, component string) (json.Token, int, error) {
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, 0, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, 0, fmt.Errorf("invalid JSON object key")
		}
		if strings.EqualFold(key, component) {
			return jsonValueToken(dec)
		}
		if err := jsonSkipValue(dec); err != nil {
			return nil, 0, err
		}
	}
	return nil, 0, fmt.Errorf("JSON object key %q not found", component)
}

func jsonArrayValue(dec *json.Decoder, component string) (json.Token, int, error) {
	index, err := strconv.Atoi(component)
	if err != nil || index < 0 {
		return nil, 0, fmt.Errorf("invalid JSON array index %q", component)
	}

	for i := 0; dec.More(); i++ {
		if i == index {
			return jsonValueToken(dec)
		}
		if err := jsonSkipValue(dec); err != nil {
			return nil, 0, err
		}
	}
	return nil, 0, fmt.Errorf("JSON array index %d out of bounds", index)
}

func jsonValueToken(dec *json.Decoder) (json.Token, int, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, 0, err
	}
	return tok, int(dec.InputOffset()) - 1, nil
}

func isVirtualStatementIndex(component string) bool {
	index, err := strconv.Atoi(component)
	return err == nil && index == 0
}

func jsonTokenLineOffset(jsonStr string, tokenOffset int) int {
	if tokenOffset < 0 || tokenOffset >= len(jsonStr) {
		return -1
	}
	return countNewlinesBefore(jsonStr, tokenOffset)
}

// countNewlinesBefore counts the number of '\n' characters in s before position pos.
func countNewlinesBefore(s string, pos int) int {
	if pos > len(s) {
		pos = len(s)
	}
	count := 0
	for i := 0; i < pos; i++ {
		if s[i] == '\n' {
			count++
		}
	}
	return count
}

// jsonSkipValue consumes one complete JSON value from the decoder using Token.
func jsonSkipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if _, ok := tok.(json.Delim); !ok {
		return nil // scalar consumed
	}
	depth := 1
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}
