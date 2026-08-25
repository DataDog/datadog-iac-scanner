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
	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfresolver "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/rs/zerolog/log"
)

const (
	DefaultRemoteModuleMaxDepth        = 8
	DefaultRemoteModuleMaxTotalBytes   = tfresolver.DefaultMaxTotalBytes
	DefaultRemoteModuleMaxPackageBytes = tfresolver.DefaultMaxPackageBytes
	DefaultRemoteModuleMaxFileBytes    = tfresolver.DefaultMaxFileBytes
	DefaultRemoteModuleMaxPackageFiles = tfresolver.DefaultMaxPackageFiles
	DefaultRemoteModuleMaxCacheBytes   = tfresolver.DefaultMaxCacheBytes
)

// Parameters represents all available scan parameters
type Parameters struct {
	CloudProvider               []string
	ExperimentalQueries         bool
	InputData                   string
	OutputName                  string
	OutputPath                  string
	RepoPath                    string
	Path                        []string
	PayloadPath                 string
	PreviewLines                int
	QueriesPath                 []string
	LibrariesPath               string
	ReportFormats               []string
	Platform                    []string
	TerraformVarsPath           string
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
	PreAnalysisExcludePaths     []string
	SCIInfo                     model.SCIInfo
	FlagEvaluator               featureflags.FlagEvaluator
	Config                      config.IacConfig
	ShouldScanTfPlans           bool
	DisableRuleIsolation        bool
	UseRulesCache               bool
	EnableRemoteModules         bool
	RemoteModulesManifestPath   string
	RemoteModulesHostAllowlist  []string
	// ModuleMaxDepth caps the BFS depth of the remote-module graph walker (0 disables traversal entirely).
	ModuleMaxDepth        int
	ModuleFetchTimeout    time.Duration
	MaxModuleBytesTotal   int64
	MaxModulePackageBytes int64
	MaxModuleFileBytes    int64
	MaxModulePackageFiles int
	MaxModuleParseBytes   int64
	RemoteModulesCacheDir string
	MaxModuleCacheBytes   int64
}

func (p *Parameters) GetEffectivePlatforms() []string {
	return ApplyPlatformFilters(p.Platform, p.Config.OnlyPlatforms, p.Config.IgnorePlatforms)
}

// Client represents a scan client
type Client struct {
	ScanParams    *Parameters
	ScanStartTime time.Time
	Tracker       *tracker.CITracker
	Storage       *storage.MemoryStorage
	Printer       *consolePrinter.Printer
	FlagEvaluator featureflags.FlagEvaluator
	// querySourceFactory overrides createQuerySource; set in tests and custom scans.
	querySourceFactory func(ctx context.Context, platforms []string) (source.QueriesSource, error)
	// analyzerOverride skips the file-extension analyzer and returns a pre-known platform list.
	// Set when the platform is already known (e.g. RunCustomRegoQuery) so the temp file name
	// does not need to encode platform information.
	analyzerOverride func(ctx context.Context) (model.AnalyzedPaths, error)
	// fsys is the filesystem used for cross-file resolution. Defaults to the real
	// disk (CLI); the HTTP server injects an in-memory FS built from pushed
	// content via WithFS.
	fsys vfs.FS
	// inMemory marks a server (content-push) scan: initScan builds its file set
	// from inMemoryPaths instead of walking the disk via the analyzer.
	inMemory      bool
	inMemoryPaths []string
	walkInventory []string
	chartRoots    []string
	contentCache  map[string][]byte
}

// ClientOption customizes a Client at construction time.
type ClientOption func(*Client)

// WithQuerySourceFactory injects a factory that supplies the engine's queries,
// bypassing the default Datadog/filesystem source. The HTTP server uses this to
// serve rules pushed in the request body. Promotes the previously test-only
// querySourceFactory seam to a first-class production option.
func WithQuerySourceFactory(f func(ctx context.Context, platforms []string) (source.QueriesSource, error)) ClientOption {
	return func(c *Client) { c.querySourceFactory = f }
}

// WithFS sets the filesystem used for cross-file resolution. The CLI uses the
// default (real disk); the HTTP server injects an in-memory FS built from pushed
// content. A nil fsys is ignored.
func WithFS(fsys vfs.FS) ClientOption {
	return func(c *Client) {
		if fsys != nil {
			c.fsys = fsys
		}
	}
}

// WithInMemoryScan marks the scan as content-push: initScan builds its file set
// from the given paths (the keys of the pushed content) instead of walking the
// disk. Used together with WithFS.
func WithInMemoryScan(paths []string) ClientOption {
	return func(c *Client) {
		c.inMemory = true
		c.inMemoryPaths = paths
	}
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
		Config:                      *configParams,
		CloudProvider:               []string{""},
		ExperimentalQueries:         false,
		InputData:                   "",
		OutputName:                  "kics-result.sarif",
		PayloadPath:                 "",
		PreviewLines:                3,
		QueriesPath:                 []string{"./assets/queries"},
		LibrariesPath:               "./assets/libraries",
		ReportFormats:               []string{"sarif"},
		Platform:                    platforms.Supported,
		TerraformVarsPath:           "",
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
		ModuleMaxDepth:              DefaultRemoteModuleMaxDepth,
		ModuleFetchTimeout:          30 * time.Second,
		MaxModuleBytesTotal:         DefaultRemoteModuleMaxTotalBytes,
		MaxModulePackageBytes:       DefaultRemoteModuleMaxPackageBytes,
		MaxModuleFileBytes:          DefaultRemoteModuleMaxFileBytes,
		MaxModulePackageFiles:       DefaultRemoteModuleMaxPackageFiles,
		MaxModuleCacheBytes:         DefaultRemoteModuleMaxCacheBytes,
	}, logCtx
}

// NewClient initializes the client with all the required parameters. Optional
// ClientOptions (WithFS, WithQuerySourceFactory, WithInMemoryScan) configure the
// HTTP server's content-push path; the CLI passes none.
func NewClient(ctx context.Context, params *Parameters, customPrint *consolePrinter.Printer, opts ...ClientOption) (*Client, error) {
	contextLogger := logger.FromContext(ctx)
	t, err := tracker.NewTracker(params.PreviewLines)
	if err != nil {
		contextLogger.Err(err).Msgf("failed to create tracker %v", err)
		return nil, err
	}

	store := storage.NewMemoryStorage()

	client := &Client{
		ScanParams:    params,
		Tracker:       t,
		Storage:       store,
		Printer:       customPrint,
		FlagEvaluator: params.FlagEvaluator,
		fsys:          vfs.DiskFS{},
	}
	for _, opt := range opts {
		opt(client)
	}
	return client, nil
}

// Scan runs the scan pipeline in memory and returns the results without writing
// SARIF, reading git, or calling the network. It is the entry point used by the
// HTTP server; the CLI uses PerformScan (which additionally produces reports).
func (c *Client) Scan(ctx context.Context) (*Results, error) {
	c.ScanStartTime = time.Now()
	return c.executeScan(ctx)
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
