/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
// Package source (go:generate go run -mod=mod github.com/golang/mock/mockgen -package mock -source=./$GOFILE -destination=../mock/$GOFILE)
package source

import (
	"context"
	"encoding/json"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/pkg/errors"
)

// QueryInspectorParameters is a struct that represents the optionn to select queries to be executed
type QueryInspectorParameters struct {
	// IncludeQueries specifies the queries that will be used
	IncludeQueries QueryFilter
	// ExcludeQueries specifies the queries that will not be used
	ExcludeQueries      QueryFilter
	ExperimentalQueries bool
	InputDataPath       string
	BomQueries          bool
	FlagEvaluator       featureflags.FlagEvaluator
}

// QueryFilter is a struct that represents the option to exclude queries by ids or by categories
type QueryFilter struct {
	ByIDs        []string
	ByCategories []string
	BySeverities []string
}

// RegoLibraries is a struct that contains the library code and its input data
type RegoLibraries struct {
	LibraryCode      string
	LibraryInputData string
}

// QueriesSource wraps an interface that contains basic methods: GetQueries and GetQueryLibrary
// GetQueries gets all queries from a QueryMetadata list
// GetQueryLibrary gets a library of rego functions given a plataform's name
type QueriesSource interface {
	GetQueries(ctx context.Context, querySelection *QueryInspectorParameters) ([]model.QueryMetadata, error)
	GetQueryLibrary(ctx context.Context, platform string) (RegoLibraries, error)
}

// MergeInputData merges default input data with custom input data user defined
func MergeInputData(defaultInputData, customInputData string) (string, error) {
	if checkEmptyInputdata(customInputData) && checkEmptyInputdata(defaultInputData) {
		return emptyInputData, nil
	}
	if checkEmptyInputdata(defaultInputData) {
		if _, err := parseInputDataObject(customInputData); err != nil {
			return "", err
		}
		return customInputData, nil
	}
	if checkEmptyInputdata(customInputData) {
		if _, err := parseInputDataObject(defaultInputData); err != nil {
			return "", err
		}
		return defaultInputData, nil
	}

	dataJSON, err := parseInputDataObject(defaultInputData)
	if err != nil {
		return "", err
	}
	customDataJSON, err := parseInputDataObject(customInputData)
	if err != nil {
		return "", err
	}

	for key, value := range customDataJSON {
		dataJSON[key] = value
	}
	mergedJSON, mergeErr := json.Marshal(dataJSON)
	if mergeErr != nil {
		return "", errors.Wrapf(mergeErr, "failed to merge query input data")
	}
	return string(mergedJSON), nil
}

func MergeModulesData(modules []tfmodules.ParsedModule, inputData string) (string, error) {
	if checkEmptyInputdata(inputData) {
		inputData = emptyInputData
	}

	dataJSON, err := parseInputDataObject(inputData)
	if err != nil {
		return "", err
	}
	// Ensure "common_lib" exists and is a map.
	commonLib, ok := dataJSON["common_lib"].(map[string]any)
	if !ok || commonLib == nil {
		commonLib = make(map[string]any)
		dataJSON["common_lib"] = commonLib
	}

	// Ensure "modules" within "common_lib" exists and is a map.
	commonModules, ok := commonLib["modules"].(map[string]any)
	if !ok || commonModules == nil {
		commonModules = make(map[string]any)
		commonLib["modules"] = commonModules
	}

	instanceCounts := moduleInstanceCounts(modules)
	// Iterate through generated module mappings and merge their data.
	for i := range modules {
		module := &modules[i]
		for provider, attrData := range module.AttributesData {
			providersMap, ok := commonModules[provider].(map[string]any)
			if !ok || providersMap == nil {
				providersMap = map[string]any{}
				commonModules[provider] = providersMap
			}

			providersMap[moduleEquivalentKey(module.Source, module.Version)] = attrData
			if instanceCounts[provider+"\x00"+module.Source] <= 1 {
				providersMap[module.Source] = attrData
			}
		}
	}

	mergedJSON, mergeErr := json.Marshal(dataJSON)
	if mergeErr != nil {
		return "", errors.Wrapf(mergeErr, "failed to merge query input data")
	}
	return string(mergedJSON), nil
}

func parseInputDataObject(inputData string) (map[string]any, error) {
	data := map[string]any{}
	if err := json.Unmarshal([]byte(inputData), &data); err != nil {
		return nil, errors.Wrap(err, "failed to merge query input data")
	}
	if data == nil {
		return nil, errors.New("failed to merge query input data: expected a JSON object")
	}
	return data, nil
}

func moduleEquivalentKey(source, version string) string {
	if version == "" {
		return source
	}
	return source + "@" + version
}

func moduleInstanceCounts(modules []tfmodules.ParsedModule) map[string]int {
	counts := make(map[string]int)
	for i := range modules {
		module := &modules[i]
		for provider := range module.AttributesData {
			key := provider + "\x00" + module.Source
			counts[key]++
		}
	}
	return counts
}

func checkEmptyInputdata(inputData string) bool {
	return inputData == emptyInputData || inputData == ""
}

// IsEmptyInputData reports whether inputData carries no custom data (empty or "{}").
func IsEmptyInputData(inputData string) bool {
	return checkEmptyInputdata(inputData)
}
