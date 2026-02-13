/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package provider

import (
	"context"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/kuberneter"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
)

// ExtractedPath is a struct that contains the paths, temporary paths to remove
// and extraction map path of the sources
// Path is the slice of paths to scan
// ExtractionMap is a map that correlates the temporary path to the given path
// RemoveTmp is the slice containing temporary paths to be removed
type ExtractedPath struct {
	Path          []string
	ExtractionMap map[string]model.ExtractedPathObject
}

// GetKuberneterSources uses Kubernetes API to download runtime resources
// After Downloaded files kics scan the files as normal local files
func GetKuberneterSources(ctx context.Context, source []string, destinationPath string) (ExtractedPath, error) {
	contextLogger := logger.FromContext(ctx)
	extrStruct := ExtractedPath{
		Path:          []string{},
		ExtractionMap: make(map[string]model.ExtractedPathObject),
	}

	for _, path := range source {
		exportedPath, err := kuberneter.Import(ctx, path, destinationPath)
		if err != nil {
			contextLogger.Error().Msgf("failed to import %s: %s", path, err)
		}

		extrStruct.ExtractionMap[exportedPath] = model.ExtractedPathObject{
			Path:      exportedPath,
			LocalPath: true,
		}

		extrStruct.Path = append(extrStruct.Path, exportedPath)
	}

	return extrStruct, nil
}

// GetSources goes through the source slice, and determines the of source type (ex: zip, git, local).
// It than extracts the files to be scanned. If the source given is not local, a temp dir
// will be created where the files will be stored.
func GetSources(ctx context.Context, source []string, downloadDir string) (ExtractedPath, error) {
	extrStruct := ExtractedPath{
		Path:          []string{},
		ExtractionMap: make(map[string]model.ExtractedPathObject),
	}
	for _, path := range source {
		destination := filepath.Join(downloadDir, utils.NextRandom())

		extrStruct.ExtractionMap[destination] = model.ExtractedPathObject{
			Path:      path,
			LocalPath: true,
		}

		extrStruct.Path = append(extrStruct.Path, path)
	}
	return extrStruct, nil
}
