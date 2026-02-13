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
	IncludeQueries      IncludeQueries
	ExcludeQueries      ExcludeQueries
	ExperimentalQueries bool
	InputDataPath       string
	BomQueries          bool
	FlagEvaluator       featureflags.FlagEvaluator
}

// ExcludeQueries is a struct that represents the option to exclude queries by ids or by categories
type ExcludeQueries struct {
	ByIDs        []string
	ByCategories []string
	BySeverities []string
}

// IncludeQueries is a struct that represents the option to include queries by ID taking precedence over exclusion
type IncludeQueries struct {
	ByIDs []string
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

// MergeInputData merges KICS input data with custom input data user defined
func MergeInputData(defaultInputData, customInputData string) (string, error) {
	if checkEmptyInputdata(customInputData) && checkEmptyInputdata(defaultInputData) {
		return emptyInputData, nil
	}
	if checkEmptyInputdata(defaultInputData) {
		return customInputData, nil
	}
	if checkEmptyInputdata(customInputData) {
		return defaultInputData, nil
	}

	dataJSON := map[string]interface{}{}
	customDataJSON := map[string]interface{}{}
	if unmarshalError := json.Unmarshal([]byte(defaultInputData), &dataJSON); unmarshalError != nil {
		return "", errors.Wrapf(unmarshalError, "failed to merge query input data")
	}
	if unmarshalError := json.Unmarshal([]byte(customInputData), &customDataJSON); unmarshalError != nil {
		return "", errors.Wrapf(unmarshalError, "failed to merge query input data")
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

	dataJSON := map[string]any{}
	if unmarshalError := json.Unmarshal([]byte(inputData), &dataJSON); unmarshalError != nil {
		return "", errors.Wrapf(unmarshalError, "failed to merge query input data")
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

	// Iterate through generated module mappings and merge their data.
	for _, module := range modules {
		for provider, attrData := range module.AttributesData {
			providersMap, ok := commonModules[provider].(map[string]any)
			if !ok || providersMap == nil {
				providersMap = map[string]any{}
				commonModules[provider] = providersMap
			}

			providersMap[module.Source] = attrData
		}
	}

	mergedJSON, mergeErr := json.Marshal(dataJSON)
	if mergeErr != nil {
		return "", errors.Wrapf(mergeErr, "failed to merge query input data")
	}
	return string(mergedJSON), nil
}

func checkEmptyInputdata(inputData string) bool {
	return inputData == emptyInputData || inputData == ""
}
