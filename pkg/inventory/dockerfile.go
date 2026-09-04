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

const platformDockerfile = "dockerfile"

// dockerfileWalker enumerates the build stages of a Dockerfile. The parser
// groups instructions per FROM into a "command" map keyed by the FROM value, so
// each entry is one stage and its base image.
type dockerfileWalker struct{}

func (dockerfileWalker) Platform() string { return platformDockerfile }

func (dockerfileWalker) Kinds() []model.FileKind { return []model.FileKind{model.KindDOCKER} }

func (dockerfileWalker) Walk(filePath string, doc model.Document) ([]Resource, bool) {
	stages, ok := toMap(doc["command"])
	if !ok {
		return nil, false
	}

	var resources []Resource
	for _, from := range sortedKeys(stages) {
		instructions, ok := toList(stages[from])
		if !ok {
			continue
		}
		image, alias := parseDockerFrom(from)
		name := alias
		if name == "" {
			name = image
		}
		start, end := dockerStageLines(instructions)
		attrs := map[string]interface{}{"from": from}
		if cleaned := cleanAttrs(instructions); cleaned != nil {
			attrs["instructions"] = cleaned
		}
		resources = append(resources, Resource{
			Platform:   platformDockerfile,
			BlockType:  BlockStage,
			Type:       image,
			Name:       name,
			File:       filePath,
			StartLine:  start,
			EndLine:    end,
			Attributes: attrs,
		})
	}
	return resources, true
}

// parseDockerFrom splits a FROM value into its base image and optional stage
// alias, e.g. "node:18 AS builder" -> ("node:18", "builder").
func parseDockerFrom(from string) (image, alias string) {
	fields := strings.Fields(from)
	if len(fields) == 0 {
		return from, ""
	}
	image = fields[0]
	for i := 1; i+1 < len(fields); i++ {
		if strings.EqualFold(fields[i], "AS") {
			alias = fields[i+1]
			break
		}
	}
	return image, alias
}

// dockerStageLines derives a stage's line span from its instruction nodes, each
// of which carries a "_dd_line" start and an "EndLine".
func dockerStageLines(instructions []interface{}) (start, end int) {
	for _, c := range instructions {
		m, ok := toMap(c)
		if !ok {
			continue
		}
		if l, ok := genericLine(m); ok {
			if start == 0 || l < start {
				start = l
			}
			if l > end {
				end = l
			}
		}
		if e, ok := intFromNumber(m["EndLine"]); ok && e > end {
			end = e
		}
	}
	return start, end
}

// intFromNumber reads an int from the int/float64 forms JSON decoding produces.
func intFromNumber(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		return int(n), true
	}
	return 0, false
}
