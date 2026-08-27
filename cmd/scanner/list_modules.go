package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	cli "github.com/urfave/cli/v3"
)

var listModulesAction = &cli.Command{
	Name:  "list-modules",
	Usage: "Lists declared Terraform modules without fetching them",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:     "path",
			Aliases:  []string{"p"},
			Usage:    "Terraform files or directories to inspect",
			Required: true,
		},
		&cli.BoolFlag{
			Name:  "include-local",
			Usage: "include local module declarations",
		},
	},
	Action: listModules,
}

func listModules(ctx context.Context, command *cli.Command) error {
	entries, err := moduleEntriesFromPaths(ctx, command.StringSlice("path"), command.Bool("include-local"))
	if err != nil {
		return err
	}
	return writeModuleEntries(os.Stdout, entries)
}

func moduleEntriesFromPaths(
	ctx context.Context, paths []string, includeLocal bool,
) ([]tfmodules.ListModuleEntry, error) {
	files, roots, err := loadModuleDiscoveryFiles(paths)
	if err != nil {
		return nil, err
	}
	modules, err := tfmodules.ParseTerraformModules(ctx, vfs.DiskFS{}, files, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing Terraform modules: %w", err)
	}
	entries := tfmodules.ListModuleEntries(modules, includeLocal)
	for i := range entries {
		entries[i].FileName = modulePathRelativeToRoots(entries[i].FileName, roots)
	}
	return entries, nil
}

func loadModuleDiscoveryFiles(paths []string) (model.FileMetadatas, []string, error) {
	files := make(model.FileMetadatas, 0)
	roots := make([]string, 0, len(paths))
	seen := make(map[string]bool)
	for _, input := range paths {
		absolute, err := filepath.Abs(input)
		if err != nil {
			return nil, nil, fmt.Errorf("resolving path %q: %w", input, err)
		}
		info, err := os.Stat(absolute)
		if err != nil {
			return nil, nil, fmt.Errorf("reading path %q: %w", input, err)
		}
		root := absolute
		if !info.IsDir() {
			root = filepath.Dir(absolute)
		}
		roots = append(roots, root)
		err = filepath.WalkDir(absolute, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if path != absolute && (entry.Name() == ".git" || entry.Name() == ".terraform") {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Type()&fs.ModeSymlink != 0 || !strings.HasSuffix(strings.ToLower(entry.Name()), ".tf") {
				return nil
			}
			clean := filepath.Clean(path)
			if seen[clean] {
				return nil
			}
			data, err := os.ReadFile(clean) //nolint:gosec
			if err != nil {
				return err
			}
			seen[clean] = true
			files = append(files, &model.FileMetadata{
				FilePath:     clean,
				OriginalData: string(data),
			})
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("walking path %q: %w", input, err)
		}
	}
	return files, roots, nil
}

func modulePathRelativeToRoots(path string, roots []string) string {
	for _, root := range roots {
		relative, err := filepath.Rel(root, path)
		if err == nil && filepath.IsLocal(relative) {
			return filepath.ToSlash(relative)
		}
	}
	return filepath.ToSlash(path)
}

func writeModuleEntries(writer io.Writer, entries []tfmodules.ListModuleEntry) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(entries)
}
