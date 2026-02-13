/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	consoleHelpers "github.com/DataDog/datadog-iac-scanner/internal/console/helpers"
	"github.com/DataDog/datadog-iac-scanner/pkg/analyzer"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/pkg/errors"
)

var (
	kuberneterRegex = regexp.MustCompile(`^kuberneter::`)
)

func (c *Client) prepareAndAnalyzePaths(ctx context.Context) (provider.ExtractedPath, error) {
	contextLogger := logger.FromContext(ctx)
	queryExPaths, libExPaths, err := c.preparePaths(ctx)
	if err != nil {
		return provider.ExtractedPath{}, err
	}

	regularPaths, kuberneterPaths := extractPathType(c.ScanParams.Path)

	kuberneterExPaths, err := provider.GetKuberneterSources(ctx, kuberneterPaths, c.ScanParams.OutputPath)
	if err != nil {
		return provider.ExtractedPath{}, err
	}

	regularExPaths, err := provider.GetSources(ctx, regularPaths, c.ScanParams.OutputPath)
	if err != nil {
		return provider.ExtractedPath{}, err
	}

	allPaths := combinePaths(kuberneterExPaths, regularExPaths, queryExPaths, libExPaths)
	if len(allPaths.Path) == 0 {
		return provider.ExtractedPath{}, nil
	}
	contextLogger.Info().Msgf("Total files in the project: %d", getTotalFiles(ctx, allPaths.Path))

	a := &analyzer.Analyzer{
		Paths:             allPaths.Path,
		Types:             c.ScanParams.Platform,
		ExcludeTypes:      c.ScanParams.ExcludePlatform,
		Exc:               c.ScanParams.ExcludePaths,
		GitIgnoreFileName: ".gitignore",
		ExcludeGitIgnore:  c.ScanParams.ExcludeGitIgnore,
		MaxFileSize:       c.ScanParams.MaxFileSizeFlag,
		NumWorkers:        c.ScanParams.ParallelScanFlag,
	}

	pathTypes, errAnalyze := analyzePaths(ctx, a)

	if errAnalyze != nil {
		return provider.ExtractedPath{}, errAnalyze
	}

	if len(pathTypes.Types) == 0 {
		return provider.ExtractedPath{}, nil
	}

	c.ScanParams.Platform = pathTypes.Types
	c.ScanParams.PreAnalysisExcludePaths = c.ScanParams.ExcludePaths
	c.ScanParams.ExcludePaths = pathTypes.Exc

	return allPaths, nil
}

func combinePaths(kuberneter, regular, query, library provider.ExtractedPath) provider.ExtractedPath {
	var combinedPaths provider.ExtractedPath
	paths := make([]string, 0)
	combinedPathsEx := make(map[string]model.ExtractedPathObject)
	paths = append(paths, kuberneter.Path...)
	paths = append(paths, regular.Path...)
	combinedPaths.Path = paths
	for k, v := range regular.ExtractionMap {
		combinedPathsEx[k] = v
	}
	for k, v := range kuberneter.ExtractionMap {
		combinedPathsEx[k] = v
	}
	for k, v := range query.ExtractionMap {
		combinedPathsEx[k] = v
	}
	for k, v := range library.ExtractionMap {
		combinedPathsEx[k] = v
	}

	combinedPaths.ExtractionMap = combinedPathsEx
	return combinedPaths
}

func (c *Client) preparePaths(ctx context.Context) (queryExtPath, libExtPath provider.ExtractedPath, err error) {
	queryExtPath, err = c.GetQueryPath(ctx)
	if err != nil {
		return provider.ExtractedPath{}, provider.ExtractedPath{}, err
	}

	libExtPath, err = c.getLibraryPath(ctx)
	if err != nil {
		return queryExtPath, provider.ExtractedPath{}, err
	}

	return queryExtPath, libExtPath, nil
}

// GetQueryPath gets all the queries paths
func (c *Client) GetQueryPath(ctx context.Context) (provider.ExtractedPath, error) {
	contextLogger := logger.FromContext(ctx)
	queriesPath := make([]string, 0)
	extPath := provider.ExtractedPath{
		Path:          []string{},
		ExtractionMap: make(map[string]model.ExtractedPathObject),
	}
	if c.ScanParams.ChangedDefaultQueryPath {
		for _, queryPath := range c.ScanParams.QueriesPath {
			extractedPath, errExtractQueries := resolvePath(ctx, queryPath, "queries-path", c.ScanParams.OutputPath)
			if errExtractQueries != nil {
				return extPath, errExtractQueries
			}
			extPath = extractedPath
			queriesPath = append(queriesPath, extractedPath.Path[0])
		}
	} else {
		contextLogger.Debug().Msgf("Looking for queries in executable path and in current work directory")
		defaultQueryPath, errDefaultQueryPath := consoleHelpers.GetDefaultQueryPath(c.ScanParams.QueriesPath[0])
		if errDefaultQueryPath != nil {
			contextLogger.Error().Msgf("%v\n", errDefaultQueryPath)
			return extPath, errors.Wrap(errDefaultQueryPath, "unable to find queries")
		}
		queriesPath = append(queriesPath, defaultQueryPath)
	}
	c.ScanParams.QueriesPath = queriesPath
	contextLogger.Info().Msgf("%v\n", c.ScanParams.QueriesPath)
	return extPath, nil
}

func (c *Client) getLibraryPath(ctx context.Context) (provider.ExtractedPath, error) {
	extPath := provider.ExtractedPath{
		Path:          []string{},
		ExtractionMap: make(map[string]model.ExtractedPathObject),
	}
	if c.ScanParams.ChangedDefaultLibrariesPath {
		extractedLibrariesPath, errExtractLibraries := resolvePath(ctx, c.ScanParams.LibrariesPath, "libraries-path", c.ScanParams.OutputPath)
		if errExtractLibraries != nil {
			return extPath, errExtractLibraries
		}

		extPath = extractedLibrariesPath
		c.ScanParams.LibrariesPath = extractedLibrariesPath.Path[0]
	}
	return extPath, nil
}

func resolvePath(ctx context.Context, flagContent, flagName, downloadDir string) (provider.ExtractedPath, error) {
	contextLogger := logger.FromContext(ctx)
	extractedPath, errExtractPath := provider.GetSources(ctx, []string{flagContent}, downloadDir)
	if errExtractPath != nil {
		return extractedPath, errExtractPath
	}
	if len(extractedPath.Path) != 1 {
		err := fmt.Errorf("could not find a valid path (--%s) on %s", flagName, flagContent)
		contextLogger.Error().Msg(err.Error())
		return extractedPath, err
	}
	contextLogger.Debug().Msgf("Trying to load path (--%s) from %s", flagName, flagContent)
	return extractedPath, nil
}

// analyzePaths will analyze the paths to scan to determine which type of queries to load
// and which files should be ignored, it then updates the types and exclude flags variables
// with the results found
func analyzePaths(ctx context.Context, a *analyzer.Analyzer) (model.AnalyzedPaths, error) {
	contextLogger := logger.FromContext(ctx)
	var err error
	var pathsFlag model.AnalyzedPaths
	excluded := make([]string, 0)

	pathsFlag, err = analyzer.Analyze(ctx, a)
	if err != nil {
		contextLogger.Err(err).Msgf("failed analyze %v", err)
		return model.AnalyzedPaths{}, err
	}

	logLoadingQueriesType(ctx, pathsFlag.Types)

	excluded = append(excluded, a.Exc...)
	excluded = append(excluded, pathsFlag.Exc...)
	pathsFlag.Exc = excluded
	return pathsFlag, nil
}

func logLoadingQueriesType(ctx context.Context, types []string) {
	contextLogger := logger.FromContext(ctx)
	if len(types) == 0 {
		contextLogger.Info().Msg("No queries were loaded")
		return
	}

	contextLogger.Info().Msgf("Loading queries of type: %s", strings.Join(types, ", "))
}

func extractPathType(paths []string) (regular, kuberneter []string) {
	for _, path := range paths {
		if kuberneterRegex.MatchString(path) {
			kuberneter = append(kuberneter, kuberneterRegex.ReplaceAllString(path, ""))
		} else {
			regular = append(regular, path)
		}
	}
	return
}

func usingCustomQueries(queriesPath []string) bool {
	return !utils.ContainsInString(filepath.Join("assets", "queries"), queriesPath)
}

func getTotalFiles(ctx context.Context, paths []string) int {
	contextLogger := logger.FromContext(ctx)
	files := 0
	for _, path := range paths {
		if err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if !info.IsDir() {
				files++
			}

			return nil
		}); err != nil {
			contextLogger.Error().Msgf("failed to walk path %s: %s", path, err)
		}
	}
	return files
}
