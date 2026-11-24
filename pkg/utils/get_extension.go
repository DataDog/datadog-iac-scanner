/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

const tfvarsName = "tfvars"

// dockerfileExtension recognizes Dockerfile and <name>.Dockerfile in any case.
// Dockerfile.<name> is a content-checked candidate only after registered formats
// have had precedence. Auxiliary files use the same configured path filters as
// other scanner inputs; arbitrary variant names cannot identify their purpose.
func dockerfileExtension(path, ext string) (string, bool) {
	lower := strings.ToLower(filepath.Base(path))
	switch {
	case lower == "dockerfile":
		return dockerfileName, true
	case strings.HasSuffix(lower, dockerfileExt):
		return dockerfileExt, true
	case strings.HasPrefix(lower, "dockerfile."):
		format, registered := supportedFileTypes[strings.ToLower(ext)]
		if !registered || format.platform == platforms.Dockerfile {
			return PossibleDockerfile, true
		}
	}
	return "", false
}

// ExtensionFromPath returns the extension from path alone (no stat/read).
func ExtensionFromPath(path string) string {
	ext := tfpath.Extension(path)
	if dockerExt, ok := dockerfileExtension(path, ext); ok {
		return dockerExt
	}
	if ext != "" {
		return ext
	}
	if strings.HasSuffix(filepath.Base(path), tfvarsName) {
		return tfvarsName
	}
	return ""
}

// GetExtension gets the extension of a file path on the real filesystem.
func GetExtension(ctx context.Context, path string) (string, error) {
	return GetExtensionWithFS(ctx, vfs.DiskFS{}, path)
}

// GetExtensionWithFS gets the extension of a file path, reading file metadata
// and content through fsys. The HTTP server passes an in-memory FS so extension
// detection works for pushed content that never touches disk; the CLI passes the
// real disk (the default, via GetExtension), preserving existing behavior.
func GetExtensionWithFS(ctx context.Context, fsys vfs.FS, path string) (string, error) {
	contextLogger := logger.FromContext(ctx)

	// Get file information
	fileInfo, err := fsys.Stat(path)
	if err != nil {
		err = fmt.Errorf("file %s not found", path)
		contextLogger.Error().Msg(err.Error())
		return "", err
	}

	if fileInfo.IsDir() {
		err = fmt.Errorf("the path %s is a directory", path)
		return "", err
	}

	return ExtensionFromPath(path), nil
}
