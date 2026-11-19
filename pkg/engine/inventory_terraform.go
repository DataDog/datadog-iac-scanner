/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"cmp"
	"encoding/json"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// InventorySink receives the resources a scan's inventory lists.
type InventorySink interface {
	AddResource(r *inventory.Resource)
}

// SetInventory makes the inspector report every Terraform resource and data
// source it evaluates to sink. Reporting changes nothing in the scan.
func (c *Inspector) SetInventory(sink InventorySink) {
	c.inventory = sink
}

// terraformInventory turns evaluated Terraform resources into inventory rows.
type terraformInventory struct {
	sink     InventorySink
	repoPath string
	lookup   moduleProvenanceLookup
	// external reports a fetched module, which is not a root of the
	// repository even when nothing in the scan calls it.
	external func(string) bool
}

// newTerraformInventory returns nil when the scan has no inventory.
func (c *Inspector) newTerraformInventory(lookup moduleProvenanceLookup, external func(string) bool) *terraformInventory {
	if c.inventory == nil {
		return nil
	}
	return &terraformInventory{sink: c.inventory, repoPath: c.repoPath, lookup: lookup, external: external}
}

// addRoot reports the resources of one evaluated root module, once per
// address. It keeps its own attribution cache so that it cannot change what
// the findings are attributed to.
func (inv *terraformInventory) addRoot(dir string, resources []tfeval.ResolvedResource) {
	if inv == nil || (inv.external != nil && inv.external(dir)) {
		return
	}
	attributions := newModuleAttributionCache()
	seen := make(map[string]bool, len(resources))
	for i := range resources {
		row := inv.row(dir, &resources[i], attributions)
		// An override file restates a block of the same module.
		if seen[row.ResourcePath] {
			continue
		}
		seen[row.ResourcePath] = true
		inv.sink.AddResource(&row)
	}
}

func (inv *terraformInventory) row(
	root string, r *tfeval.ResolvedResource, attributions *moduleAttributionCache,
) inventory.Resource {
	moduleCall, path, complete := inventoryAddress(r)
	row := inventory.Resource{
		RootModule:   root,
		ResourcePath: path,
		Platform:     inventory.PlatformTerraform,
		ResourceType: r.Type,
		ResourceName: tfeval.ResourceBaseName(r.Name),
		Provider:     terraformProvider(r),
		File:         absPath(r.DefinedIn, inv.repoPath),
		LineStart:    r.DefLine,
		ModuleCall:   moduleCall,
		Completeness: inventory.CompletenessComplete,
	}
	if !complete {
		row.Completeness = inventory.CompletenessInstanceUnresolved
	}
	// In JSON configuration every block of a type shares the range of the
	// type's key, so only the start line says anything.
	if !strings.HasSuffix(r.DefinedIn, ".json") {
		row.LineEnd = max(r.DefEndLine, r.DefLine)
		row.ColumnStart = r.DefColumn
		row.ColumnEnd = r.DefEndColumn
	}
	inv.addModuleFields(&row, attributions.attribution(r, inv.repoPath, inv.lookup))
	return row
}

// addModuleFields fills the module fields of a module resource from the
// attribution its findings carry in SARIF.
func (inv *terraformInventory) addModuleFields(row *inventory.Resource, attr *model.ModuleAttribution) {
	sarif := model.ModuleAttributionForSARIF(attr)
	if sarif == nil || len(sarif.ModulePath) == 0 {
		return
	}
	hops := sarif.ModulePath
	for i := range hops {
		hops[i].Source = inventory.SanitizeSource(hops[i].Source)
	}
	// A remote module is named by its package; a local one by its directory.
	row.ModuleSource = inventory.SanitizeSource(cmp.Or(sarif.Source, hops[len(hops)-1].Source))
	row.ModuleSourceType = sarif.SourceType
	row.ModuleVersion = sarif.Version
	row.ModuleDependencyType = sarif.DependencyType
	callSite := hops[0].CodeLocation
	row.CallSiteFile = callSite.Filename
	row.CallSiteLineStart = callSite.LineStart
	row.CallSiteLineEnd = callSite.LineEnd
	if encoded, err := json.Marshal(hops); err == nil {
		row.ModulePath = string(encoded)
	}
}

// inventoryAddress returns the Terraform address of r and of its module call.
// An instance key that could not be evaluated is left out rather than
// invented, and complete reports whether any was.
func inventoryAddress(r *tfeval.ResolvedResource) (moduleCall, path string, complete bool) {
	complete = true
	for i := range r.CallChain {
		call := &r.CallChain[i]
		segment := "module." + call.ModuleName
		if call.InstanceKey != cty.NilVal {
			if key, ok := address.FormatIndexKey(call.InstanceKey); ok {
				segment += key
			} else {
				complete = false
			}
		}
		if moduleCall != "" {
			moduleCall += "."
		}
		moduleCall += segment
	}
	if r.ModuleAddress != "" && len(r.CallChain) == 0 {
		moduleCall, complete = r.ModuleAddress, false
	}
	var suffix string
	if r.InstanceKey != cty.NilVal {
		key, ok := address.FormatIndexKey(r.InstanceKey)
		if ok {
			suffix = key
		} else {
			complete = false
		}
	} else if r.Body != nil && (r.Body.Attributes["count"] != nil || r.Body.Attributes["for_each"] != nil) {
		complete = false
	}
	kind := address.KindResource
	if r.Data {
		kind = address.KindData
	}
	block := address.Block{Kind: kind, Type: r.Type, Name: tfeval.ResourceBaseName(r.Name)}
	return moduleCall, address.Instance(moduleCall, block, suffix), complete
}

// terraformProvider returns the provider a resource declares with its
// provider argument, else the provider its type is named after.
func terraformProvider(r *tfeval.ResolvedResource) string {
	if r.Body != nil {
		if attr, ok := r.Body.Attributes["provider"]; ok {
			if traversal, diags := hcl.AbsTraversalForExpr(attr.Expr); !diags.HasErrors() && len(traversal) > 0 {
				return traversal.RootName()
			}
		}
	}
	name, _, _ := strings.Cut(r.Type, "_")
	return name
}
