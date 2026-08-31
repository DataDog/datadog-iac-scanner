package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/moduleprepare"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	cli "github.com/urfave/cli/v3"
)

const privateDirectoryMode = 0o750

var prepareModulesAction = &cli.Command{
	Name:  "prepare-modules",
	Usage: "Prepares a staged Terraform module graph without network access",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:     "path",
			Aliases:  []string{"p"},
			Usage:    "Terraform files or directories to inspect",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "module-root",
			Usage:    "task-scoped root containing staged module artifacts",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "output-response",
			Usage:    "path to the module preparation response",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "output-manifest",
			Usage:    "path to the final manifest written after complete resolution",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "staged-modules",
			Usage: "JSON descriptor for staged module archives and directories",
		},
		&cli.BoolFlag{
			Name:  "staged-only",
			Usage: "disable all outbound module resolvers",
			Value: true,
		},
		&cli.IntFlag{
			Name:  "terraform-modules-max-depth",
			Usage: "maximum remote module graph depth",
			Value: scan.DefaultRemoteModuleMaxDepth,
		},
		&cli.IntFlag{
			Name:  "terraform-modules-max-count",
			Usage: "maximum number of remote module calls in one graph",
			Value: scan.DefaultRemoteModuleMaxModules,
		},
		&cli.DurationFlag{
			Name:  "module-resolution-timeout",
			Usage: "timeout for one module preparation phase",
			Value: scan.DefaultModuleResolutionTimeout,
		},
		&cli.Int64Flag{
			Name:  "terraform-modules-max-bytes",
			Usage: "maximum aggregate bytes admitted from remote modules",
			Value: scan.DefaultRemoteModuleMaxTotalBytes,
		},
		&cli.Int64Flag{
			Name:  "terraform-modules-max-package-bytes",
			Usage: "maximum expanded bytes admitted from one module package",
			Value: scan.DefaultRemoteModuleMaxPackageBytes,
		},
		&cli.Int64Flag{
			Name:  "terraform-modules-max-file-bytes",
			Usage: "maximum expanded size of one module file",
			Value: scan.DefaultRemoteModuleMaxFileBytes,
		},
		&cli.IntFlag{
			Name:  "terraform-modules-max-package-files",
			Usage: "maximum file count in one module package",
			Value: scan.DefaultRemoteModuleMaxPackageFiles,
		},
		&cli.Int64Flag{
			Name:  "terraform-modules-max-parse-bytes",
			Usage: "target bytes admitted for repository and module parsing",
		},
	},
	Action: prepareModules,
}

func prepareModules(ctx context.Context, command *cli.Command) error {
	if !command.Bool("staged-only") {
		return fmt.Errorf("prepare-modules requires --staged-only")
	}
	moduleRoot, err := prepareModuleRoot(command.String("module-root"))
	if err != nil {
		return err
	}
	limits := resolver.ResourceLimits{
		MaxPackageBytes: command.Int64("terraform-modules-max-package-bytes"),
		MaxFileBytes:    command.Int64("terraform-modules-max-file-bytes"),
		MaxPackageFiles: command.Int("terraform-modules-max-package-files"),
		MaxTotalBytes:   command.Int64("terraform-modules-max-bytes"),
	}
	stagedManifestPath, cleanup, err := prepareStagedModuleManifest(
		ctx,
		command.String("staged-modules"),
		moduleRoot,
		limits,
	)
	if err != nil {
		return err
	}
	defer cleanup()

	files, roots, err := loadModuleDiscoveryFiles(command.StringSlice("path"))
	if err != nil {
		return err
	}
	discoveryPaths := make([]string, 0, len(files))
	for _, file := range files {
		if file != nil {
			discoveryPaths = append(discoveryPaths, file.FilePath)
		}
	}
	params := &scan.Parameters{
		TerraformModules:          scan.TerraformModulesOn,
		NetworkIsolation:          true,
		RemoteModulesManifestPath: stagedManifestPath,
		ModuleMaxDepth:            command.Int("terraform-modules-max-depth"),
		ModuleMaxModules:          command.Int("terraform-modules-max-count"),
		MaxModuleBytesTotal:       limits.MaxTotalBytes,
		MaxModulePackageBytes:     limits.MaxPackageBytes,
		MaxModuleFileBytes:        limits.MaxFileBytes,
		MaxModulePackageFiles:     limits.MaxPackageFiles,
		MaxModuleParseBytes:       command.Int64("terraform-modules-max-parse-bytes"),
		ModuleResolutionTimeout:   command.Duration("module-resolution-timeout"),
	}
	result, err := scan.PrepareTerraformModules(ctx, params, roots, discoveryPaths)
	if err != nil {
		return err
	}
	defer result.Cleanup()
	_, err = moduleprepare.WriteResult(
		ctx,
		command.String("output-response"),
		command.String("output-manifest"),
		moduleRoot,
		roots,
		&result,
		command.Int("terraform-modules-max-count"),
	)
	return err
}

func prepareStagedModuleManifest(
	ctx context.Context,
	stagedModulesPath string,
	moduleRoot string,
	limits resolver.ResourceLimits,
) (manifestPath string, cleanup func(), err error) {
	if stagedModulesPath == "" {
		return "", func() {}, nil
	}
	temp, err := os.CreateTemp(moduleRoot, ".staged-modules-*.json")
	if err != nil {
		return "", func() {}, fmt.Errorf("creating staged module manifest: %w", err)
	}
	manifestPath = temp.Name()
	cleanup = func() { _ = os.Remove(manifestPath) }
	if err := temp.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("closing staged module manifest: %w", err)
	}
	if err := os.Remove(manifestPath); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("preparing staged module manifest: %w", err)
	}
	if err := moduleprepare.WriteStagedManifest(ctx, stagedModulesPath, manifestPath, moduleRoot, limits); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return manifestPath, cleanup, nil
}

func prepareModuleRoot(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving module root: %w", err)
	}
	if err := os.MkdirAll(absolute, privateDirectoryMode); err != nil {
		return "", fmt.Errorf("creating module root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolving module root: %w", err)
	}
	return resolved, nil
}
