/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import (
	"path/filepath"
	"strings"
)

var testFixtureDirs = map[string]struct{}{
	"testdata": {}, "fixtures": {}, "__fixtures__": {},
}

// IsTestFixturePath reports whether path sits under a test fixture directory,
// where invalid or incomplete files are deliberate and not worth a warning.
func IsTestFixturePath(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if _, ok := testFixtureDirs[part]; ok {
			return true
		}
	}
	return false
}
