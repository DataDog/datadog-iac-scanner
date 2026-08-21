package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
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
		&cli.BoolFlag{
			Name:  "direct",
			Usage: "inspect top-level Terraform files and reachable local modules only",
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
	files, allowedFiles, err := collectModuleDiscoveryFiles(ctx, paths, c.Bool("direct"))
	if err != nil {
		return fmt.Errorf("collecting Terraform files: %w", err)
	}
	parsed, err := tfmodules.ParseTerraformModulesFromFiles(ctx, nil, files, allowedFiles)
	if err != nil {
		return fmt.Errorf("parsing Terraform modules: %w", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(tfmodules.ListModuleEntriesRelativeTo(
		parsed, c.Bool("all"), moduleRepositoryRoot(paths),
	))
}

func collectModuleDiscoveryFiles(
	ctx context.Context, paths []string, direct bool,
) (model.FileMetadatas, map[string]bool, error) {
	files, err := collectTerraformFiles(paths, direct)
	if err != nil {
		return nil, nil, err
	}
	allowed := allowedModuleFiles(paths, files)
	if !direct {
		return files, allowed, nil
	}
	return collectReachableModuleDiscoveryFiles(ctx, paths, files, allowed)
}

func collectReachableModuleDiscoveryFiles(
	ctx context.Context,
	paths []string,
	files model.FileMetadatas,
	allowed map[string]bool,
) (model.FileMetadatas, map[string]bool, error) {
	return collectReachableModuleDiscoveryFilesWithParser(
		paths,
		files,
		allowed,
		func(frontier model.FileMetadatas, frontierAllowed map[string]bool) (map[string]tfmodules.ParsedModule, error) {
			return tfmodules.ParseTerraformModulesFromFiles(ctx, nil, frontier, frontierAllowed)
		},
	)
}

func collectReachableModuleDiscoveryFilesWithParser(
	paths []string,
	files model.FileMetadatas,
	allowed map[string]bool,
	parse func(model.FileMetadatas, map[string]bool) (map[string]tfmodules.ParsedModule, error),
) (model.FileMetadatas, map[string]bool, error) {
	repositoryRoot := moduleRepositoryRoot(paths)
	resolvedRoot, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving repository root: %w", err)
	}
	seenDirs := make(map[string]bool)
	for _, file := range files {
		dir, resolveErr := filepath.EvalSymlinks(filepath.Dir(file.FilePath))
		if resolveErr != nil {
			return nil, nil, resolveErr
		}
		seenDirs[dir] = true
	}
	frontierFiles := make(model.FileMetadatas, 0, len(files))
	for _, file := range files {
		if allowed == nil || allowed[file.FilePath] {
			frontierFiles = append(frontierFiles, file)
		}
	}
	for len(frontierFiles) > 0 {
		childDirs, expandErr := nextLocalModuleDiscoveryDirs(
			frontierFiles, resolvedRoot, seenDirs, parse,
		)
		if expandErr != nil {
			return nil, nil, expandErr
		}
		if len(childDirs) == 0 {
			return files, allowed, nil
		}
		sort.Strings(childDirs)
		frontierFiles = nil
		for _, childDir := range childDirs {
			childFiles, collectErr := collectTopLevelTerraformFiles(childDir)
			if collectErr != nil {
				return nil, nil, collectErr
			}
			files = append(files, childFiles...)
			frontierFiles = append(frontierFiles, childFiles...)
			if allowed == nil {
				allowed = make(map[string]bool)
			}
			for _, file := range childFiles {
				allowed[file.FilePath] = true
			}
		}
	}
	return files, allowed, nil
}

func nextLocalModuleDiscoveryDirs(
	frontierFiles model.FileMetadatas,
	resolvedRoot string,
	seenDirs map[string]bool,
	parse func(model.FileMetadatas, map[string]bool) (map[string]tfmodules.ParsedModule, error),
) ([]string, error) {
	frontierAllowed := make(map[string]bool, len(frontierFiles))
	for _, file := range frontierFiles {
		frontierAllowed[file.FilePath] = true
	}
	modules, parseErr := parse(frontierFiles, frontierAllowed)
	if parseErr != nil {
		return nil, parseErr
	}
	var childDirs []string
	for key := range modules {
		module := modules[key]
		childDir := filepath.Clean(module.AbsSource)
		if !module.IsLocal || childDir == "." {
			continue
		}
		resolvedChild, resolveErr := filepath.EvalSymlinks(childDir)
		if resolveErr != nil || seenDirs[resolvedChild] ||
			!pathContainsFile(resolvedRoot, resolvedChild) {
			continue
		}
		seenDirs[resolvedChild] = true
		childDirs = append(childDirs, resolvedChild)
	}
	return childDirs, nil
}

func moduleRepositoryRoot(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	start := paths[0]
	if info, err := os.Stat(start); err == nil && !info.IsDir() {
		start = filepath.Dir(start)
	}
	for dir := filepath.Clean(start); ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil && pathsWithinRoot(dir, paths) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	return commonPathRoot(paths)
}

func pathsWithinRoot(root string, paths []string) bool {
	for _, candidate := range paths {
		if !pathContainsFile(root, candidate) {
			return false
		}
	}
	return true
}

func commonPathRoot(paths []string) string {
	root := filepath.Clean(paths[0])
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		root = filepath.Dir(root)
	}
	for _, candidate := range paths[1:] {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			candidate = filepath.Dir(candidate)
		}
		for !pathContainsFile(root, candidate) {
			parent := filepath.Dir(root)
			if parent == root {
				return root
			}
			root = parent
		}
	}
	return root
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

func collectTerraformFiles(paths []string, direct bool) (model.FileMetadatas, error) {
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
		var dirFiles model.FileMetadatas
		if direct {
			dirFiles, err = collectTopLevelTerraformFiles(rootPath)
		} else {
			dirFiles, err = walkTerraformDir(rootPath)
		}
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
