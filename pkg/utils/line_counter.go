/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package utils contains various utility functions to use in other packages
package utils

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
)

const lineCountChunkSize = 64 * 1024

// CountLines returns the number of lines in content: a trailing fragment with no
// newline still counts as a line, and empty content has none.
func CountLines(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	lines := bytes.Count(content, []byte{'\n'})
	if content[len(content)-1] != '\n' {
		lines++
	}
	return lines
}

// LineCounter get the number of lines of a given file. Prefer CountLines when
// the content is already in memory. Counting newlines in chunks rather than
// scanning line by line also lifts the previous 64KB-per-line ceiling, which
// silently truncated the count for files holding very long (e.g. minified) lines.
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

	buf := make([]byte, lineCountChunkSize)
	lineCount := 0
	endsWithNewline := true
	for {
		n, readErr := file.Read(buf)
		if chunk := buf[:n]; len(chunk) > 0 {
			lineCount += bytes.Count(chunk, []byte{'\n'})
			endsWithNewline = chunk[len(chunk)-1] == '\n'
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return 0, readErr
		}
	}
	if !endsWithNewline {
		lineCount++
	}

	return lineCount, nil
}
