/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"
	"time"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/rs/zerolog/log"
)

// Parameters represents all available scan parameters
type Parameters struct {
	CloudProvider               []string
	ExcludeCategories           []string
	ExcludePaths                []string
	ExcludeQueries              []string
	ExcludeResults              []string
	ExcludeSeverities           []string
	ExperimentalQueries         bool
	IncludeQueries              []string
	InputData                   string
	OutputName                  string
	OutputPath                  string
	Path                        []string
	PayloadPath                 string
	PreviewLines                int
	QueriesPath                 []string
	LibrariesPath               string
	ReportFormats               []string
	Platform                    []string
	ExcludePlatform             []string
	TerraformVarsPath           string
	QueryExecTimeout            int
	LineInfoPayload             bool
	DisableSecrets              bool
	SecretsRegexesPath          string
	ChangedDefaultQueryPath     bool
	ChangedDefaultLibrariesPath bool
	ScanID                      string
	BillOfMaterials             bool
	ExcludeGitIgnore            bool
	OpenAPIResolveReferences    bool
	ParallelScanFlag            int
	MaxFileSizeFlag             int
	UseOldSeverities            bool
	MaxResolverDepth            int
	KicsComputeNewSimID         bool
	PreAnalysisExcludePaths     []string
	SCIInfo                     model.SCIInfo
	FlagEvaluator               featureflags.FlagEvaluator
}

// Client represents a scan client
type Client struct {
	ScanParams        *Parameters
	ScanStartTime     time.Time
	Tracker           *tracker.CITracker
	Storage           *storage.MemoryStorage
	ExcludeResultsMap map[string]bool
	Printer           *consolePrinter.Printer
	FlagEvaluator     featureflags.FlagEvaluator
}

func GetDefaultParameters(ctx context.Context, rootPath string) (*Parameters, context.Context) {
	// check for config file and load in relevant params if present
	configParams, logCtx, err := initializeConfig(ctx, rootPath)
	contextLogger := log.Ctx(logCtx)
	if err != nil {
		contextLogger.Err(err).Msgf("failed to initialize config %v", err)
		return nil, logCtx
	}

	return &Parameters{
		CloudProvider:               []string{""},
		ExcludeCategories:           configParams.ExcludeCategories,
		ExcludeQueries:              configParams.ExcludeQueries,
		ExcludeResults:              configParams.ExcludeResults,
		ExcludeSeverities:           configParams.ExcludeSeverities,
		ExcludePaths:                configParams.ExcludePaths,
		ExperimentalQueries:         false,
		IncludeQueries:              configParams.IncludeQueries,
		InputData:                   "",
		OutputName:                  "kics-result.sarif",
		PayloadPath:                 "",
		PreviewLines:                3,
		QueriesPath:                 []string{"./assets/queries"},
		LibrariesPath:               "./assets/libraries",
		ReportFormats:               []string{"sarif"},
		Platform:                    []string{"CICD", "Terraform", "Kubernetes", "CloudFormation"},
		TerraformVarsPath:           "",
		QueryExecTimeout:            60,
		LineInfoPayload:             false,
		DisableSecrets:              true,
		SecretsRegexesPath:          "",
		ChangedDefaultQueryPath:     false,
		ChangedDefaultLibrariesPath: false,
		ScanID:                      "console",
		BillOfMaterials:             false,
		ExcludeGitIgnore:            false,
		OpenAPIResolveReferences:    false,
		ParallelScanFlag:            0,
		MaxFileSizeFlag:             5,
		UseOldSeverities:            false,
		MaxResolverDepth:            15,
		ExcludePlatform:             []string{""},
	}, logCtx
}

// NewClient initializes the client with all the required parameters
func NewClient(ctx context.Context, params *Parameters, customPrint *consolePrinter.Printer) (*Client, error) {
	contextLogger := logger.FromContext(ctx)
	t, err := tracker.NewTracker(params.PreviewLines)
	if err != nil {
		contextLogger.Err(err).Msgf("failed to create tracker %v", err)
		return nil, err
	}

	store := storage.NewMemoryStorage()

	excludeResultsMap := getExcludeResultsMap(params.ExcludeResults)

	return &Client{
		ScanParams:        params,
		Tracker:           t,
		Storage:           store,
		ExcludeResultsMap: excludeResultsMap,
		Printer:           customPrint,
		FlagEvaluator:     params.FlagEvaluator,
	}, nil
}

// PerformScan executes executeScan and postScan
func (c *Client) PerformScan(ctx context.Context) (ScanMetadata, error) {
	contextLogger := logger.FromContext(ctx)
	c.ScanStartTime = time.Now()

	scanResults, err := c.executeScan(ctx)

	if err != nil {
		contextLogger.Err(err).Msgf("failed to execute scan %v", err)
		return ScanMetadata{}, err
	}

	scanMetadata, postScanError := c.postScan(ctx, scanResults)

	if postScanError != nil {
		contextLogger.Err(postScanError)
		return ScanMetadata{}, postScanError
	}

	return scanMetadata, nil
}
