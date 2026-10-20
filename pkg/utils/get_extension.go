/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"golang.org/x/tools/godoc/util"
)

var extensionNameTargets = []string{"tfvars", PossibleDockerfile}

// dockerfileExtension recognizes Dockerfile and <name>.Dockerfile in any case.
// Dockerfile.<name> is a content-checked candidate only after registered formats
// have had precedence. Backup, template and archive files are auxiliary inputs.
func dockerfileExtension(path, ext string) (string, bool) {
	lower := strings.ToLower(filepath.Base(path))
	switch {
	case lower == "dockerfile":
		return "Dockerfile", true
	case strings.HasSuffix(lower, ".dockerfile"):
		return ".dockerfile", true
	case strings.HasPrefix(lower, "dockerfile."):
		if isDockerfileAuxiliary(lower) {
			return "", false
		}
		format, registered := supportedFileTypes[strings.ToLower(ext)]
		if !registered || format.platform == platforms.Dockerfile {
			return PossibleDockerfile, true
		}
	}
	return "", false
}

// dockerfileAuxiliarySuffixes describes generated, backup and packaged inputs,
// not scanner formats. Format precedence comes only from supportedFileTypes.
var dockerfileAuxiliarySuffixes = []string{
	".bak", ".orig", ".save", ".swp", ".tmp", ".rej", ".patch", ".diff",
	".gz", ".tgz", ".tar", ".zip", ".xz", ".bz2",
	".j2", ".tpl", ".template", ".erb", ".gotmpl", ".tmpl", ".in", ".jinja2", ".mustache",
	".old", ".backup", ".example", ".swo", ".dockerignore", "~",
	".jinja", ".sample", ".dist", ".bk", ".disabled", ".hbs", ".njk",
}

func isDockerfileAuxiliary(lower string) bool {
	for _, suffix := range dockerfileAuxiliarySuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
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
	base := filepath.Base(path)
	if Contains(base, extensionNameTargets) {
		return base
	}
	if strings.HasSuffix(base, "tfvars") {
		return "tfvars"
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
	targets := extensionNameTargets

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

	ext := tfpath.Extension(path)
	if dockerExt, ok := dockerfileExtension(path, ext); ok {
		return dockerExt, nil
	}
	if ext == "" {
		base := filepath.Base(path)

		if Contains(base, targets) {
			ext = base
		} else {
			isText, err := isTextFile(ctx, fsys, path)

			if err != nil {
				return "", err
			}

			if isText {
				err := fmt.Errorf("file %s does not have a supported extension", path)
				contextLogger.Debug().Msg(err.Error())
				return "", err
			}
		}
	}

	return ext, nil
}

func isTextFile(ctx context.Context, fsys vfs.FS, path string) (bool, error) {
	contextLogger := logger.FromContext(ctx)
	info, err := fsys.Stat(path)
	if err != nil {
		contextLogger.Error().Msgf("failed to get file info: %s", err)
		return false, err
	}

	if info.IsDir() {
		return false, nil
	}

	content, err := fsys.ReadFile(filepath.Clean(path))
	if err != nil {
		contextLogger.Error().Msgf("failed to analyze file: %s", err)
		return false, err
	}

	content = bytes.ReplaceAll(content, []byte("\r"), []byte(""))

	isText := util.IsText(content)

	return isText, nil
}
