/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package utils contains various utility functions to use in other packages
package utils

import (
	"bufio"
	"context"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
)

// LineCounter get the number of lines of a given file
func LineCounter(ctx context.Context, path string) (int, error) {
	contextLogger := logger.FromContext(ctx)
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			contextLogger.Err(err).Msgf("failed to close '%s'", filepath.Clean(path))
		}
	}()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return lineCount, nil
}
