package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	cli "github.com/urfave/cli/v3"
)

const (
	bundleConfigFileName    = "config.yaml"
	bundleRulesFileName     = "rules.json"
	bundleLibrariesFileName = "libraries.json"
	bundleManifestFileName  = "manifest.json"
)

// bundleManifest records when and for which repository an offline bundle was
// fetched, so that `scan --offline-bundle-path` can warn about a stale bundle
// instead of silently running against outdated rules.
type bundleManifest struct {
	RepoURL        string    `json:"repo_url"`
	FetchedAt      time.Time `json:"fetched_at"`
	ScannerVersion string    `json:"scanner_version"`
}

var fetchBundleAction = &cli.Command{
	Name: "fetch-bundle",
	Usage: "Fetches the default and custom rulesets, Rego libraries, and merged remote " +
		"configuration for a repository and writes them to local files, for " +
		"later use with `scan --offline-bundle-path` in a network-isolated environment",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "repo-path",
			Usage: "repository root path, used to discover a local configuration file",
			Value: ".",
		},
		&cli.StringFlag{
			Name:     "repo-url",
			Usage:    "repository URL, used to request repository-specific server-side configuration",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "output-dir",
			Usage:    "directory to write the bundle files to",
			Required: true,
		},
	},
	Action: fetchBundle,
}

func fetchBundle(ctx context.Context, c *cli.Command) error {
	repoPath, err := getAbsolutePath(c.String("repo-path"))
	if err != nil {
		return err
	}
	outputDir, err := getAbsolutePath(c.String("output-dir"))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outputDir, dirPerms); err != nil {
		return errorWithExitCode(fmt.Errorf("could not create output directory: %w", err), constants.EngineErrorCode)
	}

	client := datadog.NewDatadogClient()

	_, cfgBytes, err := config.ReadConfiguration(ctx, repoPath, config.WithDatadog(client, c.String("repo-url")))
	if err != nil {
		return configurationReadError(err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, bundleConfigFileName), cfgBytes, filePerms); err != nil {
		return errorWithExitCode(fmt.Errorf("error writing the configuration bundle: %w", err), constants.EngineErrorCode)
	}

	defaultRuleset, err := client.GetDefaultRuleset(ctx)
	if err != nil {
		return errorWithExitCode(fmt.Errorf("error fetching the default ruleset: %w", err), constants.EngineErrorCode)
	}
	customRuleset, err := client.GetCustomRuleset(ctx)
	if err != nil {
		return errorWithExitCode(fmt.Errorf("error fetching the custom ruleset: %w", err), constants.EngineErrorCode)
	}
	ruleset := datadog.MergeRulesets(defaultRuleset, customRuleset)
	rulesetBytes, err := json.Marshal(ruleset)
	if err != nil {
		return errorWithExitCode(fmt.Errorf("error marshaling the default ruleset: %w", err), constants.EngineErrorCode)
	}
	if err := os.WriteFile(filepath.Join(outputDir, bundleRulesFileName), rulesetBytes, filePerms); err != nil {
		return errorWithExitCode(fmt.Errorf("error writing the ruleset bundle: %w", err), constants.EngineErrorCode)
	}

	libraries, err := client.GetLibraries(ctx)
	if err != nil {
		return errorWithExitCode(fmt.Errorf("error fetching libraries: %w", err), constants.EngineErrorCode)
	}
	librariesBytes, err := json.Marshal(libraries)
	if err != nil {
		return errorWithExitCode(fmt.Errorf("error marshaling libraries: %w", err), constants.EngineErrorCode)
	}
	if err := os.WriteFile(filepath.Join(outputDir, bundleLibrariesFileName), librariesBytes, filePerms); err != nil {
		return errorWithExitCode(fmt.Errorf("error writing the libraries bundle: %w", err), constants.EngineErrorCode)
	}

	manifest := bundleManifest{
		RepoURL:        c.String("repo-url"),
		FetchedAt:      time.Now().UTC(),
		ScannerVersion: constants.Version,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return errorWithExitCode(fmt.Errorf("error marshaling the bundle manifest: %w", err), constants.EngineErrorCode)
	}
	if err := os.WriteFile(filepath.Join(outputDir, bundleManifestFileName), manifestBytes, filePerms); err != nil {
		return errorWithExitCode(fmt.Errorf("error writing the bundle manifest: %w", err), constants.EngineErrorCode)
	}

	fmt.Printf("Wrote offline bundle (%d rules, %d libraries) to %s\n", len(ruleset.Rules), len(libraries), outputDir)
	return nil
}

func configurationReadError(err error) error {
	outErr := fmt.Errorf("error reading the configuration: %w", err)
	if te := (*config.InvalidLocalConfigError)(nil); errors.As(err, &te) {
		return errorWithExitCode(outErr, constants.InvalidConfigErrorCode)
	}
	return errorWithExitCode(outErr, constants.EngineErrorCode)
}

// readBundleManifest reads and parses the manifest written by fetchBundle,
// used by `scan --offline-bundle-path` to warn about a stale bundle.
func readBundleManifest(bundleDir string) (*bundleManifest, error) {
	b, err := os.ReadFile(filepath.Clean(filepath.Join(bundleDir, bundleManifestFileName)))
	if err != nil {
		return nil, err
	}
	var manifest bundleManifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}
