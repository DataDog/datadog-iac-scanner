/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

const resourceBlockKind = "resource"
const lineMetadataKey = "_dd_lines"

func isTerraformFile(f *model.FileMetadata) bool {
	return f != nil && (f.Kind == model.KindTerraform || f.Kind == model.KindTerraformPlan || strings.EqualFold(f.Platform, "terraform"))
}

func assignGraphRootModuleDirs(files model.FileMetadatas, roots []string, repoPath string) {
	if roots == nil {
		return
	}
	index := newRootIndex(roots)
	for _, f := range files {
		if isTerraformFile(f) && f.Kind != model.KindTerraformPlan && !index[moduleFileDir(f.FilePath, repoPath)] {
			f.RootModuleDir = ""
			f.ResourceAddresses = nil
		}
	}
}

func relativeModuleDir(dir, repoPath string) string {
	if rel, err := filepath.Rel(repoPath, dir); err == nil {
		return filepath.ToSlash(rel)
	}
	return ""
}

// captureResourceAddresses runs before module suppression and document release.
// The base-named keys remain unchanged for rules and original source lookup.
func captureResourceAddresses(files model.FileMetadatas, repoPath string) {
	for _, f := range files {
		if !isTerraformFile(f) {
			continue
		}
		// A standalone plan has no source-root path; use its containing directory.
		// Configuration ownership is refined from the module call graph below.
		f.RootModuleDir = relativeModuleDir(moduleFileDir(f.FilePath, repoPath), repoPath)
		f.ResourceAddresses = documentAddresses(f.Document)
	}
	// Layers share copied context maps, so remove metadata only after all layers
	// have captured it. It must never be visible as a resource attribute to rules.
	for _, f := range files {
		if f != nil && f.ResourceAddresses != nil {
			for _, kind := range []string{resourceBlockKind, dataRoot, moduleCallRoot} {
				for _, raw := range docAsMap(f.Document[kind]) {
					if kind == moduleCallRoot {
						delete(docAsMap(raw), converter.InstanceAddressesKey)
						continue
					}
					for _, block := range docAsMap(raw) {
						delete(docAsMap(block), converter.InstanceAddressesKey)
					}
				}
			}
		}
	}
}

func documentAddresses(doc model.Document) map[string][]string {
	out := make(map[string][]string)
	for _, kind := range []string{resourceBlockKind, dataRoot, moduleCallRoot} {
		for typ, raw := range docAsMap(doc[kind]) {
			if typ == lineMetadataKey {
				continue
			}
			blocks := docAsMap(raw)
			if kind == moduleCallRoot {
				blocks = map[string]interface{}{typ: raw}
			}
			for name, block := range blocks {
				attrs := docAsMap(block)
				if attrs == nil || name == lineMetadataKey {
					continue
				}
				keyType := typ
				switch kind {
				case dataRoot:
					keyType = dataTypePrefix + typ
				case moduleCallRoot:
					keyType = moduleCallRoot
				}
				out[layerBlockKey(keyType, name)] = blockAddresses(doc, kind, typ, name, attrs)
			}
		}
	}
	return out
}

// blockAddresses gives plans precedence over configuration-derived identities.
func blockAddresses(doc model.Document, kind, typ, name string, attrs map[string]interface{}) []string {
	base := address.Resource("", kind, typ, name)
	addresses := []string{base}
	if suffixes, ok := instanceSuffixes(attrs[converter.InstanceAddressesKey]); ok {
		addresses = make([]string, len(suffixes))
		for i, suffix := range suffixes {
			if suffix != "" {
				addresses[i] = base + suffix
			}
		}
	} else if attrs["count"] != nil || attrs[forEachAttribute] != nil {
		addresses = []string{""} // Unknown keys or refused expansion.
	}
	// Plans already provide authoritative, fully qualified addresses.
	meta := docAsMap(docAsMap(docAsMap(doc["_dd_tfplan_meta"])[typ])[name])
	if planned, ok := meta["address"].(string); ok && planned != "" {
		addresses = []string{planned}
	}
	if kind == dataRoot {
		if planned, ok := docAsMap(docAsMap(doc["_dd_tfplan_data_addresses"])[typ])[name].(string); ok {
			addresses = []string{planned}
		}
	}
	return addresses
}

// findingAddresses matches the rule's document key, rather than resourceName
// (which many rules fill with a provider attribute). Match complete known keys
// to preserve dots, brackets, quotes and empty keys in flattened plan names.
func findingAddresses(file *model.FileMetadata, v *model.Vulnerability) []string {
	search := v.SearchKey
	var best []string
	longest := 0
	for key, addresses := range file.ResourceAddresses {
		typ, name, _ := strings.Cut(key, "\x00")
		prefixes := []string{
			typ + "." + name, typ + "[" + name + "]",
			"resource." + typ + "." + name, "resource." + typ + "[" + name + "]",
			typ + "[{{" + name + "}}]", "resource." + typ + ".{{" + name + "}}",
		}
		for _, prefix := range prefixes {
			if len(prefix) > longest && (search == prefix || strings.HasPrefix(search, prefix+".") || strings.HasPrefix(search, prefix+"[")) {
				best, longest = addresses, len(prefix)
			}
		}
	}
	return best
}

func appendAddressedFindings(
	out []model.Vulnerability, v *model.Vulnerability, files map[string]*model.FileMetadata,
) []model.Vulnerability {
	f := files[v.FileID]
	if v.Platform == "" && isTerraformFile(f) {
		v.Platform = "Terraform"
	}
	if !strings.EqualFold(v.Platform, "terraform") {
		return append(out, *v)
	}
	var addresses []string
	if f != nil {
		v.RootModuleDir = f.RootModuleDir
		addresses = findingAddresses(f, v)
	}
	if len(addresses) == 0 {
		addresses = []string{""}
	}
	for _, addr := range addresses {
		finding := *v
		finding.ResourceAddress = addr
		setAddressFallback(&finding)
		out = append(out, finding)
	}
	return out
}

func setAddressFallback(v *model.Vulnerability) {
	v.ResourceAddressFallback = ""
	if v.ResourceAddress == "" {
		v.ResourceAddressFallback = "resource_address_unresolved"
	} else if v.RootModuleDir == "" {
		v.ResourceAddressFallback = "root_module_unresolved"
	}
}

// Runner preparation normalizes []string metadata to JSON-compatible slices.
func instanceSuffixes(raw interface{}) ([]string, bool) {
	switch suffixes := raw.(type) {
	case []string:
		return suffixes, true
	case []interface{}:
		out := make([]string, len(suffixes))
		for i, item := range suffixes {
			suffix, ok := item.(string)
			if !ok {
				return nil, false
			}
			out[i] = suffix
		}
		return out, true
	default:
		return nil, false
	}
}

// resourceRootModuleDir uses the evaluated call graph, never the child file's
// filesystem position. Extra callers carry their own root through deduplication.
func resourceRootModuleDir(r *tfeval.ResolvedResource, repoPath string) string {
	if len(r.CallChain) == 0 {
		return ""
	}
	return relativeModuleDir(moduleFileDir(r.CallChain[0].CalledFrom, repoPath), repoPath)
}

func resolvedResourceAddress(r *tfeval.ResolvedResource) string {
	if !resolvedModuleInstanceKeys(r) {
		return ""
	}
	// Unresolved count/for_each and truncated as-written fallbacks have a base
	// name despite carrying meta-arguments. They must not claim a singleton.
	if r.Name == tfeval.ResourceBaseName(r.Name) && r.Body != nil {
		if r.Body.Attributes["count"] != nil || r.Body.Attributes["for_each"] != nil {
			return ""
		}
	}
	kind := resourceBlockKind
	if r.Data {
		kind = dataRoot
	}
	return address.Resource(r.ModuleAddress, kind, r.Type, r.Name)
}

// An unindexed module hop with count/for_each is an as-written placeholder,
// not an actual singleton module. Keep that uncertainty on descendant findings.
func resolvedModuleInstanceKeys(r *tfeval.ResolvedResource) bool {
	if r.ModuleAddress == "" {
		return true
	}
	traversal, diags := hclsyntax.ParseTraversalAbs([]byte(r.ModuleAddress), "", hcl.InitialPos)
	if diags.HasErrors() {
		return false
	}
	cursor := 0
	for _, site := range r.CallChain {
		cursor += 2 // module.<label>
		indexed := false
		if cursor < len(traversal) {
			_, indexed = traversal[cursor].(hcl.TraverseIndex)
			if indexed {
				cursor++
			}
		}
		if site.Body != nil && (site.Body.Attributes["count"] != nil || site.Body.Attributes["for_each"] != nil) && !indexed {
			return false
		}
	}
	return true
}
