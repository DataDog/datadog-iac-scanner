/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

func (c *Inspector) buildRemoteResolver() tfeval.RemoteResolver {
	if len(c.remoteModuleDirs) == 0 {
		return nil
	}
	dirs := c.remoteModuleDirs
	return func(source, version, callerFile, moduleName string) (string, string, bool) {
		root := remoteModuleRoot(callerFile, c.repoPath)
		resolved, ok := lookupRemoteDir(dirs, root, source, version, moduleName)
		return resolved.Path, resolved.PackageRoot, ok
	}
}

type RemoteModuleDirectory struct {
	Path        string
	PackageRoot string
}

func lookupRemoteDir(
	dirs map[string]RemoteModuleDirectory,
	root, source, version, name string,
) (RemoteModuleDirectory, bool) {
	if d, ok := dirs[RemoteModuleCallKey(root, source, version, name)]; ok {
		return d, true
	}
	if d, ok := dirs[RemoteModuleCallKey(root, source, "", name)]; ok {
		return d, true
	}
	if d, ok := dirs[RemoteModuleKey(root, source, version)]; ok {
		return d, true
	}
	if version != "" {
		if d, ok := dirs[RemoteModuleKey(root, source, "")]; ok {
			return d, true
		}
	}
	return RemoteModuleDirectory{}, false
}

func RemoteModuleKey(root, source, version string) string {
	return filepath.Clean(root) + "\x00" + strings.TrimSpace(source) + "\x00" + strings.TrimSpace(version)
}

func RemoteModuleCallKey(root, source, version, moduleName string) string {
	return RemoteModuleKey(root, source, version) + "\x00" + strings.TrimSpace(moduleName)
}

func remoteModuleRoot(fileName, repoPath string) string {
	if fileName == "" {
		return filepath.Clean(repoPath)
	}
	return filepath.Clean(filepath.Dir(absPath(fileName, repoPath)))
}

func moduleCallChainKey(chain []tfeval.CallSite, moduleAddress, repoPath string) string {
	if len(chain) == 0 {
		return moduleAddress
	}
	root := absPath(chain[0].CalledFrom, repoPath)
	rel := root
	if rp, err := filepath.Rel(repoPath, root); err == nil {
		rel = rp
	}
	return filepath.ToSlash(rel) + "|" + moduleAddress
}

// legacyModuleCallChainKey keeps the spelling used by the original scanner
// for persisted legacy finding identities. The evaluator now stores valid,
// HCL-escaped module addresses; re-render their indexes with the historical
// raw string quoting only at this compatibility boundary.
func legacyModuleCallChainKey(chain []tfeval.CallSite, moduleAddress, repoPath string) string {
	return moduleCallChainKey(chain, legacyModuleAddress(moduleAddress), repoPath)
}

func legacyModuleAddress(moduleAddress string) string {
	if moduleAddress == "" {
		return ""
	}
	if !strings.Contains(moduleAddress, `\`) && !strings.Contains(moduleAddress, `$${`) && !strings.Contains(moduleAddress, `%%{`) {
		return moduleAddress
	}
	traversal, diags := hclsyntax.ParseTraversalAbs([]byte(moduleAddress), "<module-address>", hcl.InitialPos)
	if diags.HasErrors() {
		return moduleAddress
	}
	var b strings.Builder
	for _, step := range traversal {
		switch s := step.(type) {
		case hcl.TraverseRoot:
			b.WriteString(s.Name)
		case hcl.TraverseAttr:
			b.WriteByte('.')
			b.WriteString(s.Name)
		case hcl.TraverseIndex:
			key, _ := s.Key.Unmark()
			switch key.Type() {
			case cty.String:
				b.WriteString(`["`)
				b.WriteString(key.AsString())
				b.WriteString(`"]`)
			case cty.Number:
				b.WriteByte('[')
				b.WriteString(key.AsBigFloat().Text('f', -1))
				b.WriteByte(']')
			default:
				return moduleAddress
			}
		default:
			return moduleAddress
		}
	}
	return b.String()
}

// absPath returns a cleaned path. Relative paths are resolved against base
// (typically the scan repo root), not the process working directory.
func absPath(p, base string) string {
	// A path rooted without a volume ("/repo" on Windows) is not filepath.IsAbs
	// but must not be joined under base.
	if filepath.IsAbs(p) || path.IsAbs(filepath.ToSlash(p)) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(base, p))
}

// asStringMap accepts either shape a parsed document uses for an object.
func asStringMap(value interface{}) (map[string]interface{}, bool) {
	switch m := value.(type) {
	case model.Document:
		return m, true
	case map[string]interface{}:
		return m, true
	default:
		return nil, false
	}
}
