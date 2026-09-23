/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package server

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// chartDependencies must not record a missing parent Chart.yaml when mapping
// archive_files for a stray packaged chart next to other pushed files.
func TestChartDependenciesAbsentParentDoesNotRecordMissing(t *testing.T) {
	memfs := vfs.NewMemFS(map[string][]byte{
		"vendor/charts/dep.tgz": {},
	})
	if deps := chartDependencies(memfs, "vendor"); deps != nil {
		t.Fatalf("expected nil deps without vendor/Chart.yaml, got %#v", deps)
	}
	if got := memfs.MissingFiles(); len(got) != 0 {
		t.Errorf("MissingFiles = %v, want none (Stat before ReadFile)", got)
	}
}
