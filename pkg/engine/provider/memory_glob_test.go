/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package provider

import (
	"testing"

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
