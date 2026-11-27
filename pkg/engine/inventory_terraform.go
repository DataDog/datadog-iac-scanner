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
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"

	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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
	mu        sync.Mutex
	sink      InventorySink
	repoPath  string
	lookup    moduleProvenanceLookup
	rootVars  map[string]cty.Value
	files     map[string]*model.FileMetadata
	documents documentOccurrenceIndex
	// external reports a fetched module, which is not a root of the
	// repository even when nothing in the scan calls it.
	external func(string) bool
	// modulePaths keeps one copy of each module path: every instance of a
	// module, in every root that calls it, has the same.
	modulePaths map[string]string
}

// newTerraformInventory returns nil when the scan has no inventory.
func (c *Inspector) newTerraformInventory(
	lookup moduleProvenanceLookup, external func(string) bool, documents documentOccurrenceIndex,
) *terraformInventory {
	if c.inventory == nil {
		return nil
	}
	return &terraformInventory{
		sink: c.inventory, repoPath: c.repoPath, lookup: lookup, external: external,
		rootVars: c.terraformRootVars, documents: documents,
	}
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
		inv.evaluate(ctx, evaluator, terraformRootDirs(dirsWithTf, called, inv.external))
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
	evaluator.SetExplicitRootVars(inv.rootVars)
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
			inv.addRoot(dir, resources, false, nil)
		}
	}
}

// addRoot reports the resources of one evaluated root module, once per
// address. It runs inside the module evaluation findings depend on, so it
// keeps its own attribution cache and a panic in it fails the inventory only.
type terraformRootOccurrences struct {
	moduleInstances map[*tfeval.ResolvedResource]*model.ResourceOccurrence
	byAddress       map[string]*model.ResourceOccurrence
}

func (inv *terraformInventory) addRoot(
	dir string, resources []tfeval.ResolvedResource, associateModuleDocuments bool, targets *ruleTargets,
) (occurrences terraformRootOccurrences) {
	if inv == nil || (inv.external != nil && inv.external(dir)) {
		return occurrences
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			inv.fail(inventory.FailureTerraformPanic)
		}
	}()
	attributions := newModuleAttributionCache()
	seen := make(map[string]bool, len(resources))
	for i := range resources {
		r := &resources[i]
		moduleCall, address, complete := r.PartialAddress()
		// Guard against duplicate addresses in invalid configurations, such
		// as two ordinary files declaring the same resource.
		if seen[address] {
			continue
		}
		seen[address] = true
		occurrence := inv.occurrence(dir, r, moduleCall, address, complete, attributions)
		if occurrences.byAddress == nil {
			occurrences.byAddress = make(map[string]*model.ResourceOccurrence, len(resources))
		}
		occurrences.byAddress[address] = occurrence
		row := inventory.ProjectResource(occurrence)
		inv.addModuleFields(&row, occurrence.Terraform.Attribution)
		inv.sink.AddResource(&row)
		if inv.documents == nil {
			continue
		}
		switch {
		case r.ModuleAddress == "":
			inv.associateWrittenOccurrence(r, occurrence)
		case !associateModuleDocuments:
			continue
		case targets.matches(r.Type):
			if occurrences.moduleInstances == nil {
				occurrences.moduleInstances = make(map[*tfeval.ResolvedResource]*model.ResourceOccurrence)
			}
			occurrences.moduleInstances[r] = occurrence
		default:
			inv.associateWrittenOccurrence(r, occurrence)
		}
	}
	return occurrences
}

// associateWrittenOccurrence indexes root declarations and external module
// resources that generic rules can still match in the original document.
func (inv *terraformInventory) associateWrittenOccurrence(r *tfeval.ResolvedResource, occurrence *model.ResourceOccurrence) {
	id := occurrence.DocumentID
	if id == "" {
		return
	}
	if r.ModuleAddress != "" {
		if inv.external == nil || !inv.external(occurrence.File) {
			return
		}
		occurrence.Terraform.CallChainKey = callChainKey(r, inv.repoPath)
	}
	inv.documents[id] = append(inv.documents[id], occurrence)
}

func (inv *terraformInventory) occurrence(
	root string, r *tfeval.ResolvedResource, moduleCall, address string, complete bool,
	attributions *moduleAttributionCache,
) *model.ResourceOccurrence {
	file := absPath(r.DefinedIn, inv.repoPath)
	kind, name := terraformResourceBlock, tfeval.ResourceBaseName(r.Name)
	if r.Data {
		kind = dataRoot
	}
	o := &model.ResourceOccurrence{
		StructuralPath: model.SourcePath{{Key: kind}, {Key: r.Type}, {Key: name}},
		Platform:       platforms.Terraform,
		ResourceType:   r.Type,
		ResourceName:   name,
		Provider:       terraformProvider(r),
		File:           file,
		Terraform: &model.TerraformResourceOccurrence{
			Root:        root,
			Address:     address,
			ModuleCall:  moduleCall,
			Complete:    complete,
			CallChain:   occurrenceCallChain(r.CallChain),
			Attribution: callAttribution(r.CallChain, file, inv.repoPath, inv.lookup, attributions),
		},
	}
	if document := inv.files[file]; document != nil {
		o.DocumentID = document.ID
	}
	start := model.ResourceLine{Line: r.DefLine, Col: r.DefColumn}
	end := model.ResourceLine{Line: max(r.DefEndLine, r.DefLine), Col: r.DefEndColumn}
	if strings.HasSuffix(r.DefinedIn, ".json") {
		first, last := jsonBlockLines(r)
		start, end = model.ResourceLine{Line: first}, model.ResourceLine{Line: last}
	}
	o.Source = model.ResourceLocation{Start: start, End: end}
	return o
}

func occurrenceCallChain(chain []tfeval.CallSite) []model.TerraformCallSite {
	if len(chain) == 0 {
		return nil
	}
	hops := make([]model.TerraformCallSite, len(chain))
	for i := range chain {
		call := &chain[i]
		hops[i] = model.TerraformCallSite{
			Name: call.ModuleName, Source: call.Source, Version: call.Version,
			InstanceKey: call.InstanceKey, File: call.CalledFrom,
			Range: model.ResourceLocation{
				Start: model.ResourceLine{Line: call.CalledLine, Col: call.CalledColumn},
				End:   model.ResourceLine{Line: call.CalledEndLine, Col: call.CalledEndColumn},
			},
		}
	}
	return hops
}

// jsonBlockLines returns the lines of a block of JSON configuration. Every
// block of a type shares the range of the type's key, so a block starts at
// the brace of its own object, which its body's range gives, and ends at its
// last attribute.
func jsonBlockLines(r *tfeval.ResolvedResource) (start, end int) {
	body := r.Body
	if r.DeclarationBody != nil {
		body = r.DeclarationBody
	}
	if body == nil || body.SrcRange.Start.Line < 1 {
		return r.DefLine, 0
	}
	start = body.SrcRange.Start.Line
	end = start
	for _, attr := range body.Attributes {
		end = max(end, attr.SrcRange.End.Line)
	}
	for _, block := range body.Blocks {
		end = max(end, block.Range().End.Line)
	}
	return start, end
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
		row.ModulePath = inv.intern(string(encoded))
	}
}

func (inv *terraformInventory) intern(s string) string {
	if shared, ok := inv.modulePaths[s]; ok {
		return shared
	}
	if inv.modulePaths == nil {
		inv.modulePaths = make(map[string]string)
	}
	inv.modulePaths[s] = s
	return s
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
