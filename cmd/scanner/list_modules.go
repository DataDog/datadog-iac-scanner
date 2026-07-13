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
	Usage: "Prints Terraform module calls as JSON",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:     "path",
			Aliases:  []string{"p"},
			Usage:    "names of files or directories to inspect",
			Required: true,
		},
		&cli.BoolFlag{
			Name:  "all",
			Usage: "include local module calls",
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
	files, err := collectTerraformFiles(paths)
	if err != nil {
		return fmt.Errorf("collecting Terraform files: %w", err)
	}
	parsed, err := tfmodules.ParseTerraformModulesFromFiles(ctx, nil, files, allowedModuleFiles(paths, files))
	if err != nil {
		return fmt.Errorf("parsing Terraform modules: %w", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(tfmodules.ListModuleEntries(parsed, c.Bool("all")))
}

func allowedModuleFiles(paths []string, files model.FileMetadatas) map[string]bool {
	allowed := make(map[string]bool)
	for _, rootPath := range paths {
		info, err := os.Stat(rootPath)
		if err != nil {
			continue
		}
		if info.IsDir() {
			for _, file := range files {
				if pathContainsFile(rootPath, file.FilePath) {
					allowed[file.FilePath] = true
				}
			}
			continue
		}
		if strings.EqualFold(filepath.Ext(rootPath), ".tf") {
			allowed[rootPath] = true
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
		info, err := os.Stat(rootPath)
		if err != nil {
			return nil, fmt.Errorf("stat path %q: %w", rootPath, err)
		}
		if !info.IsDir() {
			if !strings.EqualFold(filepath.Ext(rootPath), ".tf") {
				continue
			}
			dirFiles, err := collectTopLevelTerraformFiles(filepath.Dir(rootPath))
			if err != nil {
				return nil, err
			}
			files = append(files, dirFiles...)
			continue
		}
		dirFiles, err := walkTerraformDir(rootPath)
		if err != nil {
			return nil, err
		}
		files = append(files, dirFiles...)
	}
	return files, nil
}

func walkTerraformDir(rootPath string) (model.FileMetadatas, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open root %q: %w", rootPath, err)
	}

	var files model.FileMetadatas
	walkErr := fs.WalkDir(root.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if rel != "." {
				switch path.Base(rel) {
				case ".terraform", ".git", "vendor":
					return fs.SkipDir
				}
			}
			return nil
		}
		if !strings.EqualFold(path.Ext(rel), ".tf") {
			return nil
		}
		data, err := fs.ReadFile(root.FS(), rel)
		if err != nil {
			return err
		}
		files = append(files, &model.FileMetadata{
			FilePath:     filepath.Join(rootPath, filepath.FromSlash(rel)),
			OriginalData: string(data),
		})
		return nil
	})
	closeErr := root.Close()
	if walkErr != nil {
		return nil, walkErr
	}
	return files, closeErr
}

func collectTopLevelTerraformFiles(dir string) (model.FileMetadatas, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files model.FileMetadatas
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".tf") {
			continue
		}
		filePath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(filepath.Clean(filePath))
		if err != nil {
			return nil, err
		}
		files = append(files, &model.FileMetadata{
			FilePath:     filePath,
			OriginalData: string(data),
		})
	}
	return files, nil
}
