/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/rs/zerolog"
)

var testFixtureDirs = map[string]struct{}{
	"testdata": {}, "fixtures": {}, "__fixtures__": {},
}

// IsTestFixturePath reports whether path sits under a test fixture directory,
// where invalid or incomplete files are deliberate and not worth a warning.
// Only directories inside the repository count: a checkout that itself lives
// under a directory named fixtures is not a fixture.
func IsTestFixturePath(path string) bool {
	if filepath.IsAbs(path) {
		if root, ok := vfs.RepositoryRoot(vfs.DiskFS{}, filepath.Dir(path)); ok {
			if rel, err := filepath.Rel(root, path); err == nil {
				path = rel
			}
		}
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if _, ok := testFixtureDirs[part]; ok {
			return true
		}
	}
	return false
}

// WarnUnlessFixture returns a Debug event for test fixture paths and a Warn event otherwise.
func WarnUnlessFixture(ctx context.Context, path string) *zerolog.Event {
	contextLogger := logger.FromContext(ctx)
	if IsTestFixturePath(path) {
		return contextLogger.Debug()
	}
	return contextLogger.Warn()
}
