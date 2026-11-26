/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2026 Datadog, Inc.
 */
package model

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDocumentPathUsesSuppliedCoordinatesWithoutRepositoryLocation(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "workspace")
	external := filepath.Join(parent, "external", "main.tf")
	require.Equal(t, "infra/main.tf", DocumentPath("infra/main.tf", "", nil))
	require.Equal(t, filepath.ToSlash(external), DocumentPath(external, "", nil))
	require.Equal(t, "../external/main.tf", DocumentPath(external, root, nil))
}

func TestDocumentPathKeepsFetchedModuleRefs(t *testing.T) {
	root := t.TempDir()
	first, second, third := t.TempDir(), t.TempDir(), t.TempDir()
	extracted := map[string]ExtractedPathObject{
		first:  {Path: "git::https://example.invalid/module//network?ref=v1"},
		second: {Path: "git::https://example.invalid/module//network?ref=v2"},
		third:  {Path: "git::https://example.invalid/module//network?ref=v1"},
	}
	firstPath := DocumentPath(filepath.Join(first, "main.tf"), root, extracted)
	secondPath := DocumentPath(filepath.Join(second, "main.tf"), root, extracted)
	thirdPath := DocumentPath(filepath.Join(third, "main.tf"), root, extracted)
	require.NotEqual(t, firstPath, secondPath)
	require.Equal(t, firstPath, thirdPath)

	extracted[second] = ExtractedPathObject{Path: "git::https://example.invalid/module//storage?ref=v1"}
	require.NotEqual(t, firstPath, DocumentPath(filepath.Join(second, "main.tf"), root, extracted))
}

func TestDocumentPathRetainsLocalModuleInstallation(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first", ".terraform", "modules", "network")
	second := filepath.Join(root, "second", ".terraform", "modules", "network")
	extracted := map[string]ExtractedPathObject{
		first:  {Path: "registry.example.invalid/example/network/aws@1.0.0"},
		second: {Path: "registry.example.invalid/example/network/aws@1.0.0"},
	}
	require.Equal(t, "first/.terraform/modules/network/main.tf", DocumentPath(filepath.Join(first, "main.tf"), root, extracted))
	require.Equal(t, "second/.terraform/modules/network/main.tf", DocumentPath(filepath.Join(second, "main.tf"), root, extracted))

	local := t.TempDir()
	extracted[local] = ExtractedPathObject{Path: filepath.Join(root, "module"), LocalPath: true}
	require.Equal(t, "module\x00/main.tf", DocumentPath(filepath.Join(local, "main.tf"), root, extracted))
}
