/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */

// Package names holds the default Docker Compose file names as a leaf
// package, shared by the Compose parser and the analyzer's classifier (which
// sit on opposite sides of an import cycle through pkg/parser/yaml), so both
// agree on which files are base files and which are auto-merged overrides.
package names

import (
	"path/filepath"
	"strings"
)

// FileNames are the default base file names Compose looks for.
var FileNames = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

// OverrideFileNames are the default override file names Compose merges into
// the base file when no -f flags are given.
var OverrideFileNames = []string{
	"compose.override.yaml", "compose.override.yml",
	"docker-compose.override.yaml", "docker-compose.override.yml",
}

// IsOverrideFileName reports whether path is one of the default Compose
// override file names. These files are merged into their base file at parse
// time and must not be classified/scanned standalone (they would duplicate
// findings with wrong attribution).
func IsOverrideFileName(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	for _, name := range OverrideFileNames {
		if base == name {
			return true
		}
	}
	return false
}

// IsDefaultBaseFileName reports whether path is one of the default Compose
// base file names (the only files an override file is auto-merged into).
func IsDefaultBaseFileName(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	for _, name := range FileNames {
		if base == name {
			return true
		}
	}
	return false
}

// OverrideNameFor returns the default override file name paired with the given
// path ("", when path is not a default base file name). Compose merges each
// base only with its own override variant: compose.yaml with
// compose.override.yaml, docker-compose.yaml with docker-compose.override.yaml
// — never across variants.
func OverrideNameFor(path string) string {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "compose.yaml":
		return "compose.override.yaml"
	case "compose.yml":
		return "compose.override.yml"
	case "docker-compose.yaml":
		return "docker-compose.override.yaml"
	case "docker-compose.yml":
		return "docker-compose.override.yml"
	}
	return ""
}
