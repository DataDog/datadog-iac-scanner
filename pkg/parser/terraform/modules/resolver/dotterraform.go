/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

const dotTerraformMaxResolveKeys = 4

type dotTerraformModulesJSON struct {
	Modules []dotTerraformModuleRecord `json:"Modules"`
}

type dotTerraformModuleRecord struct {
	Key     string `json:"Key"`
	Source  string `json:"Source"`
	Version string `json:"Version"`
	Dir     string `json:"Dir"`
}

type installedModulePath struct {
	localPath   string
	packageRoot string
	scanRoot    string
	version     string
}

// DotTerraformResolver reads terraform init output: .terraform/modules/modules.json.
type DotTerraformResolver struct {
	RootDirs []string

	once  sync.Once
	index map[string]installedModulePath
}

func (r *DotTerraformResolver) load() {
	r.index = make(map[string]installedModulePath)
	for _, root := range r.RootDirs {
		installRoot := filepath.Join(root, ".terraform", "modules")
		path := filepath.Join(installRoot, "modules.json")
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			continue
		}
		var mj dotTerraformModulesJSON
		if err := json.Unmarshal(data, &mj); err != nil {
			continue
		}
		for _, rec := range mj.Modules {
			if rec.Source == "" {
				continue
			}
			absDir := rec.Dir
			if !filepath.IsAbs(absDir) {
				absDir = filepath.Join(root, absDir)
			}
			resolvedPath, ok := installedModulePaths(root, installRoot, absDir)
			if !ok {
				continue
			}
			resolvedPath.version = strings.TrimSpace(rec.Version)
			r.index[dotTerraformKey(root, rec.Source, rec.Version)] = resolvedPath
			if rec.Key != "" {
				for _, key := range dotTerraformLoadCallKeys(root, rec.Source, rec.Version, moduleNameFromKey(rec.Key)) {
					r.index[key] = resolvedPath
				}
			}
			if _, exists := r.index[dotTerraformKey(root, rec.Source, "")]; !exists {
				r.index[dotTerraformKey(root, rec.Source, "")] = resolvedPath
			}
		}
	}
}

func installedModulePaths(scanRoot, installRoot, localPath string) (installedModulePath, bool) {
	scanRoot = filepath.Clean(scanRoot)
	installRoot = filepath.Clean(installRoot)
	localPath = filepath.Clean(localPath)
	scanRel, err := filepath.Rel(scanRoot, localPath)
	if err != nil || scanRel == "." || pathEscapesDir(scanRel) {
		return installedModulePath{}, false
	}
	packageRoot := localPath
	if installRel, relErr := filepath.Rel(installRoot, localPath); relErr == nil &&
		installRel != "." && !pathEscapesDir(installRel) {
		first, _, _ := strings.Cut(installRel, string(os.PathSeparator))
		packageRoot = filepath.Join(installRoot, first)
	}
	return installedModulePath{
		localPath:   localPath,
		packageRoot: packageRoot,
		scanRoot:    scanRoot,
	}, true
}

func (r *DotTerraformResolver) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	if mod.IsLocal {
		return Resolution{}, &tfmodules.UnresolvedError{Reason: "local modules are handled by LocalResolver"}
	}
	r.once.Do(r.load)
	path, ok := installedModulePath{}, false
	for _, root := range r.rootsFor(mod.FileName) {
		for _, key := range dotTerraformResolveKeys(root, mod.Source, mod.Version, mod.Name) {
			if path, ok = r.index[key]; ok {
				break
			}
		}
		if ok {
			break
		}
	}
	if !ok {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("module %q not found in .terraform/modules (run terraform init)", mod.Source),
		}
	}
	packageRoot, err := ResolvePathWithinRoot(ctx, path.scanRoot, path.packageRoot)
	if err != nil {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("module %q has unsafe .terraform/modules package root %q: %v", mod.Source, path.packageRoot, err),
		}
	}
	resolution, err := ConfineResolution(ctx, Resolution{
		LocalPath:       path.localPath,
		PackageRoot:     packageRoot,
		ResolvedVersion: path.version,
	})
	if err != nil {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("module %q has unsafe .terraform/modules dir %q: %v", mod.Source, path.localPath, err),
		}
	}
	return resolution, nil
}

func (r *DotTerraformResolver) rootsFor(fileName string) []string {
	if fileName == "" {
		return r.RootDirs
	}
	fileDir := filepath.Clean(filepath.Dir(fileName))
	roots := make([]string, 0, len(r.RootDirs))
	for _, root := range r.RootDirs {
		cleanRoot := filepath.Clean(root)
		if rel, err := filepath.Rel(cleanRoot, fileDir); err == nil && !pathEscapesDir(rel) {
			roots = append(roots, cleanRoot)
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		return len(roots[i]) > len(roots[j])
	})
	return roots
}

func dotTerraformKey(root, source, version string) string {
	return filepath.Clean(root) + "\x00" + strings.TrimSpace(source) + "\x00" + strings.TrimSpace(version)
}

func dotTerraformCallKey(root, source, version, moduleName string) string {
	return dotTerraformKey(root, source, version) + "\x00" + strings.TrimSpace(moduleName)
}

func dotTerraformLoadCallKeys(root, source, version, moduleName string) []string {
	return []string{
		dotTerraformCallKey(root, source, version, moduleName),
		dotTerraformCallKey(root, source, "", moduleName),
	}
}

func dotTerraformResolveKeys(root, source, version, moduleName string) []string {
	keys := make([]string, 0, dotTerraformMaxResolveKeys)
	if moduleName != "" {
		keys = append(keys, dotTerraformLoadCallKeys(root, source, version, moduleName)...)
	}
	keys = append(keys, dotTerraformKey(root, source, version))
	if version != "" {
		keys = append(keys, dotTerraformKey(root, source, ""))
	}
	return keys
}

func moduleNameFromKey(key string) string {
	parts := strings.Split(key, ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}
