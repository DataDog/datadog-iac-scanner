/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"cmp"
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// InventorySink receives the resources a scan's inventory lists.
type InventorySink interface {
	AddResource(r *inventory.Resource)
	// Fail marks the inventory as unusable: some resources may be missing.
	Fail(reason string)
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

// fail marks the inventory as unusable.
func (inv *terraformInventory) fail(reason string) {
	if inv != nil {
		inv.sink.Fail(reason)
	}
}

// evaluateAllRoots evaluates every root module for the inventory only, when
// the scan evaluates none because no rule can match what they declare.
func (inv *terraformInventory) evaluateAllRoots(
	ctx context.Context, fsys vfs.FS, mergeAllow map[string]struct{}, resolver tfeval.RemoteResolver,
	filesByDir map[string][]*model.FileMetadata, dirsWithTf map[string]bool,
) {
	if inv == nil {
		return
	}
	inv.withEvaluator(ctx, fsys, mergeAllow, resolver, func(evaluator *tfeval.Evaluator) {
		called, _ := discoverStaticCalls(ctx, evaluator, filesByDir, dirsWithTf, inv.repoPath, resolver, false)
		roots := make([]string, 0, len(dirsWithTf))
		for dir := range dirsWithTf {
			if !called[dir] {
				roots = append(roots, dir)
			}
		}
		sort.Strings(roots)
		inv.evaluate(ctx, evaluator, roots)
	})
}

// evaluateSkippedRoots evaluates for the inventory only the roots the scan
// did not evaluate, because no rule can match what they declare.
func (inv *terraformInventory) evaluateSkippedRoots(
	ctx context.Context, fsys vfs.FS, mergeAllow map[string]struct{}, resolver tfeval.RemoteResolver,
	roots, evaluated []string,
) {
	if inv == nil || len(evaluated) == len(roots) {
		return
	}
	skipped := rootsOutside(roots, evaluated)
	inv.withEvaluator(ctx, fsys, mergeAllow, resolver, func(evaluator *tfeval.Evaluator) {
		inv.evaluate(ctx, evaluator, skipped)
	})
}

// withEvaluator runs fn on an evaluator of the inventory's own, so that
// nothing the findings depend on changes. A panic fails the inventory.
func (inv *terraformInventory) withEvaluator(
	ctx context.Context, fsys vfs.FS, mergeAllow map[string]struct{}, resolver tfeval.RemoteResolver,
	fn func(*tfeval.Evaluator),
) {
	defer func() {
		if r := recover(); r != nil {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Error().Interface("panic", r).Msg("inventory: recovered from panic while evaluating Terraform")
			inv.fail(inventory.FailureTerraformPanic)
		}
	}()
	evaluator := tfeval.NewWithFS(fsys)
	evaluator.SetMergeAllow(mergeAllow)
	if resolver != nil {
		evaluator.SetRemoteResolver(resolver)
	}
	defer evaluator.ReleaseCaches()
	fn(evaluator)
}

// evaluate evaluates each root and reports its resources.
func (inv *terraformInventory) evaluate(ctx context.Context, evaluator *tfeval.Evaluator, roots []string) {
	for _, dir := range roots {
		if ctx.Err() != nil {
			return
		}
		resources, _, _, err := evaluator.EvaluateModule(ctx, dir, evaluator.LoadRootVarsWithContext(ctx, dir))
		evaluator.ReleaseEvalCache()
		evaluator.ForgetRootParse(dir)
		if err == nil {
			inv.addRoot(dir, resources)
		}
	}
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
		// As findings name the module calls, to link them to the row.
		ModuleCallChain: callChainKey(r, inv.repoPath),
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
	// The module calls and the module's package, as the SARIF module property
	// gives them, without the per-finding locations and arguments.
	attr := callAttribution(r.CallChain, absPath(r.DefinedIn, inv.repoPath), inv.repoPath, inv.lookup, attributions)
	inv.addModuleFields(&row, attr)
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
