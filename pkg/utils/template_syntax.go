/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import (
	"bytes"
	"regexp"
)

// yamlBreakingTemplatePattern matches a template action that opens a line, a
// list item or a mapping value.
var yamlBreakingTemplatePattern = regexp.MustCompile(`^\s*(?:-\s+)*(?:[^\s#][^#]*?:\s+)?\{\{`)

// HasYAMLBreakingTemplate reports a template action placed where YAML reads
// "{{" as the start of a flow mapping, so the file cannot parse until it is
// rendered. Expressions inside a value (`echo ${{ x }}`, `"{{ x }}"`) and in
// comments are plain text to YAML and do not count.
func HasYAMLBreakingTemplate(content []byte) bool {
	for _, line := range bytes.Split(content, []byte("\n")) {
		if yamlBreakingTemplatePattern.Match(line) {
			return true
		}
	}
	return false
}
