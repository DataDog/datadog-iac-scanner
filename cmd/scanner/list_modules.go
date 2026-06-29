package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	cli "github.com/urfave/cli/v3"
)

var listModulesAction = &cli.Command{
	Name:  "list-modules",
	Usage: "Prints the remote Terraform modules referenced in the scanned directory as JSON",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:     "path",
			Aliases:  []string{"p"},
			Usage:    "directory to scan for Terraform files",
			Required: true,
		},
		&cli.BoolFlag{
			Name:  "all",
			Usage: "include local modules in the output (default: remote only)",
			Value: false,
		},
	},
	Action: listModules,
}

func listModules(ctx context.Context, c *cli.Command) error {
	paths, err := getAbsolutePaths(c.StringSlice("path"))
	if err != nil {
		return err
	}
	includeLocal := c.Bool("all")

	files, err := collectTerraformFiles(paths)
	if err != nil {
		return fmt.Errorf("collecting Terraform files: %w", err)
	}

	parsedModules, err := tfmodules.ParseTerraformModulesFromFiles(ctx, files, allowedModuleFiles(paths, files))
	if err != nil {
		return fmt.Errorf("parsing Terraform modules: %w", err)
	}

	entries := tfmodules.ListModuleEntries(parsedModules, includeLocal)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func allowedModuleFiles(paths []string, files model.FileMetadatas) map[string]bool {
	allowed := make(map[string]bool)
	for _, rootPath := range paths {
		absRoot, err := filepath.Abs(rootPath)
		if err != nil {
			continue
		}
		info, err := os.Stat(absRoot)
		if err != nil {
			continue
		}
		if info.IsDir() {
			for _, file := range files {
				if pathContainsFile(absRoot, file.FilePath) {
					allowed[file.FilePath] = true
				}
			}
			continue
		}
		if strings.HasSuffix(strings.ToLower(filepath.Base(absRoot)), ".tf") {
			allowed[absRoot] = true
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

func pathContainsFile(root, filePath string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(filePath))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func collectTerraformFiles(paths []string) (model.FileMetadatas, error) {
	var files model.FileMetadatas
	for _, rootPath := range paths {
		absRoot, err := filepath.Abs(rootPath)
		if err != nil {
			return nil, fmt.Errorf("terraform root path: %w", err)
		}
		info, err := os.Stat(absRoot)
		if err != nil {
			return nil, fmt.Errorf("stat path %q: %w", absRoot, err)
		}
		if !info.IsDir() {
			if !strings.HasSuffix(strings.ToLower(filepath.Base(absRoot)), ".tf") {
				continue
			}
			dirFiles, err := collectTopLevelTerraformFiles(filepath.Dir(absRoot))
			if err != nil {
				return nil, err
			}
			files = append(files, dirFiles...)
			continue
		}
		dirFiles, err := walkTerraformDir(absRoot)
		if err != nil {
			return nil, err
		}
		files = append(files, dirFiles...)
	}
	return files, nil
}

func walkTerraformDir(absRoot string) (model.FileMetadatas, error) {
	root, err := os.OpenRoot(absRoot)
	if err != nil {
		return nil, fmt.Errorf("open root %q: %w", absRoot, err)
	}
	fsys := root.FS()
	var files model.FileMetadatas
	walkErr := fs.WalkDir(fsys, ".", func(rel string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if rel != "." {
				switch path.Base(rel) {
				case ".terraform", ".git", "vendor":
					return fs.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path.Base(rel)), ".tf") {
			return nil
		}
		data, err := fs.ReadFile(fsys, rel)
		if err != nil {
			return err
		}
		absPath := filepath.Join(absRoot, filepath.FromSlash(rel))
		files = append(files, &model.FileMetadata{
			FilePath:     absPath,
			OriginalData: string(data),
		})
		return nil
	})
	closeErr := root.Close()
	if walkErr != nil {
		return nil, walkErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return files, nil
}

func collectTopLevelTerraformFiles(dir string) (model.FileMetadatas, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := make(model.FileMetadatas, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".tf") {
			continue
		}
		absPath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(filepath.Clean(absPath))
		if err != nil {
			return nil, err
		}
		files = append(files, &model.FileMetadata{
			FilePath:     absPath,
			OriginalData: string(data),
		})
	}
	return files, nil
}
