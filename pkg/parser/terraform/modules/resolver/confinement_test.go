/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfineResolutionPreservesSiblingModulesInPackage(t *testing.T) {
	packageRoot := t.TempDir()
	selected := filepath.Join(packageRoot, "modules", "selected")
	sibling := filepath.Join(packageRoot, "modules", "shared")
	require.NoError(t, os.MkdirAll(selected, 0o755))
	require.NoError(t, os.MkdirAll(sibling, 0o755))

	resolution, err := ConfineResolution(Resolution{
		LocalPath:   selected,
		PackageRoot: packageRoot,
	})
	require.NoError(t, err)
	require.Equal(t, selected, resolution.LocalPath)
	require.Equal(t, packageRoot, resolution.PackageRoot)

	resolvedSibling, err := ResolvePathWithinRoot(resolution.PackageRoot, sibling)
	require.NoError(t, err)
	require.Equal(t, sibling, resolvedSibling)
}

func TestConfineResolutionRejectsPathOutsidePackage(t *testing.T) {
	packageRoot := t.TempDir()
	outside := t.TempDir()

	_, err := ConfineResolution(Resolution{
		LocalPath:   outside,
		PackageRoot: packageRoot,
	})
	require.ErrorContains(t, err, "escapes package root")
}

func TestConfineResolutionRejectsSymlinkEscape(t *testing.T) {
	packageRoot := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(packageRoot, "linked")
	require.NoError(t, os.Symlink(outside, link))

	_, err := ConfineResolution(Resolution{
		LocalPath:   link,
		PackageRoot: packageRoot,
	})
	require.ErrorContains(t, err, "escapes package root")
}
