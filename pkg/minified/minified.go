/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package minified

import (
	"bytes"
	"strings"
)

func IsMinified(filename string, content []byte) bool {
	if strings.HasSuffix(filename, ".json") {
		return isMinifiedJSON(content)
	}
	return false
}

func isMinifiedJSON(content []byte) bool {
	// Count the number of non-whitespace characters (the ASCII whitespace of
	// a regexp \s)
	nonWhitespaceCount := len(content)
	for _, c := range []byte("\t\n\f\r ") {
		nonWhitespaceCount -= bytes.Count(content, []byte{c})
	}

	// 80% of non-whitespace characters
	minifiedThreshold := 0.8

	return float64(nonWhitespaceCount)/float64(len(content)) > minifiedThreshold
}
