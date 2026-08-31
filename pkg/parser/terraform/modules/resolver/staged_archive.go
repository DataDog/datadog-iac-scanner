/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"fmt"
	"os"
	"strings"
)

const stagedArchiveUmask = 0o077

// ExtractModuleArchive expands a staged module archive with the resolver's package limits.
func ExtractModuleArchive(
	ctx context.Context,
	sourcePath string,
	destinationPath string,
	format string,
	limits ResourceLimits,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	format = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(format), "."))
	if !isDirectoryArchiveFormat(format) {
		return fmt.Errorf("unsupported module archive format %q", format)
	}
	decompressor := limitedDecompressors(limits, limits.MaxPackageBytes)[format]
	if decompressor == nil {
		return fmt.Errorf("unsupported module archive format %q", format)
	}
	if err := decompressor.Decompress(destinationPath, sourcePath, true, stagedArchiveUmask); err != nil {
		_ = os.RemoveAll(destinationPath)
		return err
	}
	if err := ctx.Err(); err != nil {
		_ = os.RemoveAll(destinationPath)
		return err
	}
	return nil
}

func isDirectoryArchiveFormat(format string) bool {
	switch format {
	case "tar", "tar.bz2", "tar.gz", "tar.xz", "tar.zst", "tbz2", "tgz", "txz", "tzst", "zip":
		return true
	default:
		return false
	}
}
