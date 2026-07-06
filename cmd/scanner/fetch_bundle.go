package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	cli "github.com/urfave/cli/v3"
)

const (
	bundleConfigFileName    = "config.yaml"
	bundleRulesFileName     = "rules.json"
	bundleLibrariesFileName = "libraries.json"
)

var fetchBundleAction = &cli.Command{
	Name: "fetch-bundle",
	Usage: "Fetches the default ruleset, Rego libraries, and merged remote " +
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
		return errorWithExitCode(fmt.Errorf("error reading the configuration: %w", err), constants.EngineErrorCode)
	}
	if err := os.WriteFile(filepath.Join(outputDir, bundleConfigFileName), cfgBytes, filePerms); err != nil {
		return errorWithExitCode(fmt.Errorf("error writing the configuration bundle: %w", err), constants.EngineErrorCode)
	}

	ruleset, err := client.GetDefaultRuleset(ctx)
	if err != nil {
		return errorWithExitCode(fmt.Errorf("error fetching the default ruleset: %w", err), constants.EngineErrorCode)
	}
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

	fmt.Printf("Wrote offline bundle (%d rules, %d libraries) to %s\n", len(ruleset.Rules), len(libraries), outputDir)
	return nil
}
