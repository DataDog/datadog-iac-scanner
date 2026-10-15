/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package provider

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/stretchr/testify/require"
)

// A glob only-path naming templates that exist only after a packaged dependency
// renders keeps its parent chart in scope on the server, as it does on disk.
func TestMemoryPartitionChartRootsGlobReachesRenderedTemplates(t *testing.T) {
	pushed := []string{"app/Chart.yaml", "app/values.yaml", "lib/Chart.yaml"}
	roots := []string{"app", "lib"}

	only := NewMemorySourceProvider(nil, pushed, nil, []string{"app/charts/*/templates/*.yaml"})
	inScope, outOfScope := only.partitionChartRoots(roots)
	require.Equal(t, []string{"app"}, inScope)
	require.Equal(t, []string{"lib"}, outOfScope)

	ignored := NewMemorySourceProvider(nil, pushed, []string{"lib"}, nil)
	inScope, outOfScope = ignored.partitionChartRoots(roots)
	require.Equal(t, []string{"app"}, inScope)
	require.Equal(t, []string{"lib"}, outOfScope)
}

// A dot-slash ignore names the directory the same way on the server as on disk:
// the chart is left out of the render, and its other files are left out too.
func TestMemoryDotSlashIgnoreDropsChartFiles(t *testing.T) {
	m := NewMemorySourceProvider(nil, []string{
		"app/Chart.yaml", "app/templates/cm.yaml", "app/main.tf", "apps/main.tf",
	}, []string{"./app"}, nil)
	files, err := m.WalkInventory(context.Background(), model.Extensions{".tf": {}, ".yaml": {}}, utils.PoolOptions{},
		func(_ context.Context, root string) bool {
			t.Errorf("chart %s rendered although ./app is ignored", root)
			return true
		})
	require.NoError(t, err)
	require.Equal(t, []InventoryFile{{Path: "apps/main.tf", Ext: ".tf"}}, files)
}
