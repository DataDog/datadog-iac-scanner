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

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"golang.org/x/tools/godoc/util"
)

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
	targets := []string{"tfvars", "Dockerfile", "possibleDockerfile"}

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

	ext := filepath.Ext(path)
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
