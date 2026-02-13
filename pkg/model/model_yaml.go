/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	json "encoding/json"
	"errors"
	"strconv"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"gopkg.in/yaml.v3"
)

// UnmarshalYAML is a custom yaml parser that places line information in the payload
func (m *Document) UnmarshalYAML(ctx context.Context, value *yaml.Node) error {
	dpc := unmarshal(ctx, value)
	if mapDcp, ok := dpc.(map[string]interface{}); ok {
		// set line information for root level objects
		mapDcp["_kics_lines"] = getLines(value, 0)

		// place the payload in the Document struct
		tmp, _ := json.Marshal(mapDcp)
		_ = json.Unmarshal(tmp, m)
		return nil
	}
	return errors.New("failed to parse yaml content")
}

/*
	YAML Node TYPES

	SequenceNode -> array
	ScalarNode -> generic (except for arrays, objects and maps)
	MappingNode -> map

*/
// unmarshal is the function that will parse the yaml elements and call the functions needed
// to place their line information in the payload
func unmarshal(ctx context.Context, val *yaml.Node) interface{} {
	return unmarshalWithDepth(ctx, val, make(map[*yaml.Node]bool))
}

// unmarshalWithDepth handles recursive unmarshaling with circular reference detection
func unmarshalWithDepth(ctx context.Context, val *yaml.Node, visited map[*yaml.Node]bool) interface{} { //nolint:gocyclo
	if visited[val] {
		return nil
	}
	visited[val] = true
	defer func() { delete(visited, val) }()
	tmp := make(map[string]interface{})
	ignoreCommentsYAML(val)

	// if Yaml Node is an Array than we are working with ansible
	// which need to be placed inside "playbooks"
	// nolint:staticcheck
	if val.Kind == yaml.SequenceNode {
		contentArray := make([]interface{}, 0)
		for _, contentEntry := range val.Content {
			contentArray = append(contentArray, unmarshalWithDepth(ctx, contentEntry, visited))
		}
		tmp["playbooks"] = contentArray
	} else if val.Kind == yaml.ScalarNode {
		return scalarNodeResolver(ctx, val)
	} else {
		// iterate two by two, since first iteration is the key and the second is the value
		for i := 0; i < len(val.Content); i += 2 {
			if val.Content[i].Kind == yaml.ScalarNode {
				switch val.Content[i+1].Kind {
				case yaml.ScalarNode:
					tmp[val.Content[i].Value] = scalarNodeResolver(ctx, val.Content[i+1])
				// in case value iteration is a map
				case yaml.MappingNode:
					// unmarshall map value and get its line information
					result := unmarshalWithDepth(ctx, val.Content[i+1], visited)
					if tt, ok := result.(map[string]interface{}); ok {
						tt["_kics_lines"] = getLines(val.Content[i+1], val.Content[i].Line)
						tmp[val.Content[i].Value] = tt
					} else {
						tmp[val.Content[i].Value] = result
					}
				// in case value iteration is an array
				case yaml.SequenceNode:
					contentArray := make([]interface{}, 0)
					// unmarshall each iteration of the array
					for _, contentEntry := range val.Content[i+1].Content {
						contentArray = append(contentArray, unmarshalWithDepth(ctx, contentEntry, visited))
					}
					tmp[val.Content[i].Value] = contentArray
				case yaml.AliasNode:
					if val.Content[i+1].Alias != nil {
						result := unmarshalWithDepth(ctx, val.Content[i+1].Alias, visited)
						if tt, ok := result.(map[string]interface{}); ok {
							tt["_kics_lines"] = getLines(val.Content[i+1], val.Content[i].Line)
							utils.MergeMaps(tmp, tt)
						}
						if v, ok := result.(string); ok {
							tmp[val.Content[i].Value] = v
						}
					}
				}
			}
		}
	}
	return tmp
}

// getLines creates the map containing the line information for the yaml Node
// def is the line to be used as "_kics__default"
func getLines(val *yaml.Node, def int) map[string]*LineObject {
	lineMap := make(map[string]*LineObject)

	// line information map
	lineMap["_kics__default"] = &LineObject{
		Line: def,
		Arr:  []map[string]*LineObject{},
	}

	// if yaml Node is an Array use func getSeqLines
	if val.Kind == yaml.SequenceNode {
		return getSeqLines(val, def)
	}

	// iterate two by two, since first iteration is the key and the second is the value
	for i := 0; i < len(val.Content); i += 2 {
		lineArr := make([]map[string]*LineObject, 0)
		// in case the value iteration is an array call getLines for each iteration of the array
		if val.Content[i+1].Kind == yaml.SequenceNode {
			for _, contentEntry := range val.Content[i+1].Content {
				defaultLine := val.Content[i].Line
				if contentEntry.Kind == yaml.ScalarNode {
					defaultLine = contentEntry.Line
				} else if contentEntry.Kind == yaml.MappingNode && len(contentEntry.Content) > 0 {
					defaultLine = contentEntry.Content[0].Line
				}
				lineArr = append(lineArr, getLines(contentEntry, defaultLine))
			}
		}

		// line information map of each key of the yaml Node
		lineMap["_kics_"+val.Content[i].Value] = &LineObject{
			Line: val.Content[i].Line,
			Arr:  lineArr,
		}
	}

	return lineMap
}

// getSeqLines iterates through the elements of an Array
// creating a map with each iteration lines information
func getSeqLines(val *yaml.Node, def int) map[string]*LineObject {
	lineMap := make(map[string]*LineObject)
	lineArr := make([]map[string]*LineObject, 0)

	// get line information slice of every element in the array
	for _, cont := range val.Content {
		lineArr = append(lineArr, getLines(cont, cont.Line))
	}

	// create line information of array with its line and elements line information
	lineMap["_kics__default"] = &LineObject{
		Line: def,
		Arr:  lineArr,
	}
	return lineMap
}

// scalarNodeResolver transforms a ScalarNode value in its correct type
func scalarNodeResolver(ctx context.Context, val *yaml.Node) interface{} {
	contextLogger := logger.FromContext(ctx)
	var transformed interface{} = val.Value
	switch val.Tag {
	case "!!bool":
		transformed = transformBoolScalarNode(val.Value)
	case "!!int":
		v, err := strconv.Atoi(val.Value)
		if err != nil {
			contextLogger.Error().Msgf("failed to convert integer in yaml parser")
			return val.Value
		}
		transformed = v
	case "!!null":
		transformed = nil
	}

	return transformed
}

// transformBoolScalarNode transforms a string value to its boolean representation
func transformBoolScalarNode(value string) bool {
	switch value {
	case "true", "True":
		return true
	default:
		return false
	}
}
