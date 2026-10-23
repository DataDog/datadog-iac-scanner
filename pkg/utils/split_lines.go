/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import "strings"

// SplitLines splits the document by line
func SplitLines(content string) *[]string {
	text := StripCarriageReturns(content)
	split := strings.Split(text, "\n")

	return &split
}

// StripCarriageReturns applies the scanner's physical source-display policy.
// Logical source views use this too so cached and fresh locations have the same
// bytes as FileMetadata.Lines, including legacy files with lone CR characters.
func StripCarriageReturns(content string) string { return strings.ReplaceAll(content, "\r", "") }
