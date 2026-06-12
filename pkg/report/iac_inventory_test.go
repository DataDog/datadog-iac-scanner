/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package report

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestPrintIaCInventoryReport(t *testing.T) {
	cases := []struct {
		name         string
		filename     string
		wantFilename string
	}{
		{"explicit filename", "results", "iac-inventory-results.json"},
		{"filename with extension", "results.sarif", "iac-inventory-results.json"},
		{"empty filename falls back to results", "", "iac-inventory-results.json"},
	}

	files := model.FileMetadatas{} // no parsed files — just tests file I/O and naming

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			err := PrintIaCInventoryReport(context.Background(), dir, tc.filename, "/repo", files, nil)
			require.NoError(t, err)

			outPath := filepath.Join(dir, tc.wantFilename)
			raw, err := os.ReadFile(outPath)
			require.NoError(t, err, "expected output file %s to exist", tc.wantFilename)

			var inv inventory.Inventory
			require.NoError(t, json.Unmarshal(raw, &inv))
			require.Equal(t, inventory.SchemaVersion, inv.SchemaVersion)
			require.Equal(t, "Datadog", inv.Tool.Vendor)
			require.Equal(t, "/repo", inv.RootPath)
			require.Equal(t, 0, inv.ResourceCount)

			// Verify HTML escaping is disabled (ampersands must not be escaped).
			require.NotContains(t, string(raw), `\u0026`)
		})
	}
}
