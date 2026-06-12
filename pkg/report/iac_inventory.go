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
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// PrintIaCInventoryReport builds the IaC resource inventory from the parsed
// files and writes it as JSON to path/filename. The output filename is prefixed
// with "iac-inventory-" and forced to a .json extension. Only resources for the
// enabledPlatforms are inventoried; an empty list enables every platform.
func PrintIaCInventoryReport(
	ctx context.Context, path, filename, rootPath string,
	files model.FileMetadatas, enabledPlatforms []string,
) error {
	resources := inventory.WalkFiles(files, enabledPlatforms)
	inv := inventory.BuildInventory(resources, rootPath)

	base := strings.TrimSuffix(filename, filepath.Ext(filename))
	if base == "" {
		base = "results"
	}
	outName := "iac-inventory-" + base + ".json"
	fullPath := filepath.Join(path, outName)

	f, err := os.OpenFile(filepath.Clean(fullPath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePerms)
	if err != nil {
		return err
	}
	defer closeFile(ctx, fullPath, outName, f)

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(inv)
}
