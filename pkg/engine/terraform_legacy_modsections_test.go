/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"fmt"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/stretchr/testify/require"
)

// Indexing written files by directory keeps addModuleSections linear in the
// number of module instances, with the same documents as the quadratic scan.
func TestAddModuleSectionsMatchesDirectoryIndex(t *testing.T) {
	written := map[string]*model.FileMetadata{}
	for r := 0; r < 20; r++ {
		for f := 0; f < 5; f++ {
			p := fmt.Sprintf("/repo/envs/r%d/f%d.tf", r, f)
			written[p] = &model.FileMetadata{ID: p, FilePath: p, Kind: model.KindTerraform}
		}
	}
	for m := 0; m < 10; m++ {
		p := fmt.Sprintf("/repo/modules/m%d/main.tf", m)
		written[p] = &model.FileMetadata{
			ID: p, FilePath: p, Kind: model.KindTerraform,
			Document: model.Document{"terraform": map[string]any{}},
		}
	}
	id := func(s string, _ *tfmodel.Module) string { return s }
	root := &tfmodel.Root{ID: "envs/r0"}
	for m := 0; m < 10; m++ {
		root.Modules = append(root.Modules, &tfmodel.Module{
			Root: root, Address: fmt.Sprintf("module.m%d", m), Dir: fmt.Sprintf("/repo/modules/m%d", m),
		})
	}
	scan := &tfmodel.Scan{Roots: []*tfmodel.Root{root}}
	byDir := writtenByDir(written)
	got := addModuleSectionsIndexed(nil, scan, written, byDir, id)
	require.Len(t, got, 10)
	require.Equal(t, pathsOf(got), pathsOf(addModuleSectionsIndexed(nil, scan, written, byDir, id)))
}

func pathsOf(docs []*project.LegacyDoc) []string {
	out := make([]string, len(docs))
	for i, d := range docs {
		out[i] = d.Path
	}
	return out
}
