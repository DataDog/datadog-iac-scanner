/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/localdata"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
)

const (
	blockTypeVariable    = "variable"
	blockTypeLifecycle   = "lifecycle"
	blockTypeDynamic     = "dynamic"
	blockTypeConnection  = "connection"
	blockTypeProvisioner = "provisioner"
	metaArgDependsOn     = "depends_on"
)

// ResourceOverride retains the declaration and every matching override in
// application order. Effective keeps the declaration's header and body range,
// and each effective argument and nested block retains its own source range.
type ResourceOverride struct {
	Declaration       *hclsyntax.Block
	Effective         *hclsyntax.Block
	Contributions     []*hclsyntax.Block
	certificateSource string
}

func attachDeclarationBodies(resources []ResolvedResource, declarations map[*hclsyntax.Body]*hclsyntax.Body) {
	if len(declarations) == 0 {
		return
	}
	for i := range resources {
		resources[i].DeclarationBody = declarations[resources[i].Body]
	}
}

// ResourceOverrides returns the resource and data overrides of a scanned
// directory, including blocks that expand to zero instances.
func (e *Evaluator) ResourceOverrides(ctx context.Context, dir string) []ResourceOverride {
	return e.parseDir(ctx, dir, "").overrides
}

// StandaloneOverrideScope prepares the block-level context of a module for
// which the scan has no instance. It does not follow calls or expand resources.
func (e *Evaluator) StandaloneOverrideScope(ctx context.Context, dir string) *ModuleScope {
	parsed := e.parseDir(ctx, dir, "")
	if parsed.err != nil || ctx.Err() != nil {
		return nil
	}
	inputs := e.LoadRootVarsWithContext(ctx, dir)
	scope := e.newModuleScope(ctx, dir, dir, &parsed, inputs)
	e.loadOverrideFileInputs(ctx, &parsed, inputs, scope)
	e.populateStandaloneData(ctx, &parsed, scope)
	return scope
}

func (e *Evaluator) populateStandaloneData(ctx context.Context, parsed *dirParse, scope *ModuleScope) {
	data := newModuleData(e, parsed, "", nil, scope.overrideInputs)
	data.refresh(ctx, scope.evalCtx)
	data.resolved(scope)
	scope.Local = scope.evalCtx.Variables["local"]
}

// An effective block can combine expressions from files with different tfvars
// selections. Bind each expression using its written file, including meta
// arguments, rather than letting a selection leak to another file's fields.
type overrideInputs struct {
	parsed       *dirParse
	scope        *ModuleScope
	files        map[string]cty.Value
	directedData map[*hclsyntax.Body]bool
}

func (o *overrideInputs) forBody(body *hclsyntax.Body) *overrideInputs {
	if o != nil && o.parsed.declarations[body] != nil {
		return o
	}
	return nil
}

func (e *Evaluator) loadOverrideFileInputs(
	ctx context.Context, parsed *dirParse, inputs map[string]cty.Value, scope *ModuleScope,
) {
	if e.explicitRootVars != nil || len(parsed.overrides) == 0 {
		return
	}
	files := make(map[string]cty.Value)
	for _, override := range parsed.overrides {
		files[override.Declaration.TypeRange.Filename] = cty.NilVal
		for _, fragment := range override.Contributions {
			files[fragment.TypeRange.Filename] = cty.NilVal
		}
	}
	for filename := range files {
		selected := terraform.ReadFileVariables(ctx, e.fsys, filename, parsed.sources[filename])
		if len(selected) == 0 {
			delete(files, filename)
			continue
		}
		combined := make(map[string]cty.Value, len(inputs)+len(selected))
		maps.Copy(combined, inputs)
		maps.Copy(combined, selected)
		files[filename] = objectOrEmpty(e.resolveVariables(parsed.varDecls, combined))
	}
	if len(files) != 0 {
		scope.overrideInputs = &overrideInputs{
			parsed: parsed, scope: scope, files: files, directedData: directedDataBodies(parsed.overrides, files),
		}
	}
}

func directedDataBodies(overrides []ResourceOverride, files map[string]cty.Value) map[*hclsyntax.Body]bool {
	var directed map[*hclsyntax.Body]bool
	for _, override := range overrides {
		if override.Effective.Type != blockTypeData {
			continue
		}
		for _, body := range append([]*hclsyntax.Block{override.Declaration}, override.Contributions...) {
			if _, ok := files[body.TypeRange.Filename]; ok {
				if directed == nil {
					directed = make(map[*hclsyntax.Body]bool)
				}
				directed[override.Effective.Body] = true
				break
			}
		}
	}
	return directed
}

// OverrideDocument renders an effective declaration at block granularity.
// The module scope has no resource-specific count or for_each iteration.
func (e *Evaluator) OverrideDocument(
	ctx context.Context, override *ResourceOverride, scope *ModuleScope,
) map[string]interface{} {
	r := ResolvedResource{Body: override.Effective.Body, Scope: scope}
	evalCtx := &hcl.EvalContext{}
	if scope != nil {
		evalCtx = scope.evalCtx
	}
	state := &bodyState{dynamic: &dynamicRecorder{}}
	if scope != nil {
		state.setFileInputs(e.fileViews(ctx, evalCtx, r.Body, scope.overrideInputs))
	}
	r.Attributes = e.evalBodyWith(ctx, r.Body, evalCtx, nil, state)
	r.DynamicCounts = state.dynamic.counts
	r.documentScope = state.document
	doc := AttributesToDocumentWithContext(ctx, &r)
	if attr := r.Body.Attributes["certificate_body"]; override.Effective.Type == scheduledResource && attr != nil {
		terraform.EnrichResourceCertificate(ctx, e.fsys, doc, attr.SrcRange.Filename, override.certificateSource)
	}
	return doc
}

type overrideBlockKey struct{ kind, typ, name string }
type blockPosition struct{ body, block int }

func resourceOverrideKey(block *hclsyntax.Block) (overrideBlockKey, bool) {
	switch {
	case (block.Type == scheduledResource || block.Type == blockTypeData) && len(block.Labels) == 2:
		return overrideBlockKey{block.Type, block.Labels[0], block.Labels[1]}, true
	case block.Type == blockTypeVariable && len(block.Labels) == 1:
		return overrideBlockKey{kind: block.Type, name: block.Labels[0]}, true
	default:
		return overrideBlockKey{}, false
	}
}

func baseDeclarations(bodies []*hclsyntax.Body) map[overrideBlockKey]blockPosition {
	declarations := make(map[overrideBlockKey]blockPosition)
	for i, body := range bodies {
		for j, block := range body.Blocks {
			key, ok := resourceOverrideKey(block)
			if !ok {
				continue
			}
			if _, duplicate := declarations[key]; duplicate {
				declarations[key] = blockPosition{-1, -1}
				continue
			}
			declarations[key] = blockPosition{i, j}
		}
	}
	return declarations
}

// resolveResourceOverrides receives bodies in configuration order, with
// overrides last. Copy only the bodies and blocks an override changes, so
// directories without applicable overrides keep their existing parse shape.
func resolveResourceOverrides(
	ctx context.Context, bodies []*hclsyntax.Body, sources map[string][]byte,
) ([]*hclsyntax.Body, []ResourceOverride) {
	firstOverride := slices.IndexFunc(bodies, func(body *hclsyntax.Body) bool {
		return tfpath.IsOverrideFile(body.SrcRange.Filename)
	})
	if firstOverride == -1 {
		return bodies, nil
	}

	declarations := baseDeclarations(bodies[:firstOverride])
	result := slices.Clone(bodies)
	byKey := make(map[overrideBlockKey]int)
	jsonBlocks := make(map[string]hcl.Blocks)
	var overrides []ResourceOverride
	log := logger.FromContext(ctx)
	for i, body := range bodies[firstOverride:] {
		remaining := make(hclsyntax.Blocks, 0, len(body.Blocks))
		for _, block := range body.Blocks {
			key, ok := resourceOverrideKey(block)
			if !ok {
				remaining = append(remaining, block)
				continue
			}
			pos, ok := declarations[key]
			if !ok || pos.body < 0 {
				log.Warn().Str("file", block.TypeRange.Filename).Int("line", block.TypeRange.Start.Line).
					Msg("tfeval: keeping override as a standalone block because it has no unique base declaration")
				remaining = append(remaining, block)
				continue
			}
			isVariable := key.kind == blockTypeVariable
			decl := bodies[pos.body].Blocks[pos.block]
			effective := result[pos.body].Blocks[pos.block]
			contribution := block
			if !isVariable {
				if effective == decl {
					effective = overrideJSONBlock(decl, sources, jsonBlocks)
				}
				if block.Body.Attributes[metaArgDependsOn] != nil {
					log.Error().Str("file", block.TypeRange.Filename).Int("line", block.TypeRange.Start.Line).
						Msg("tfeval: depends_on is invalid in a resource or data override")
				}
				contribution = overrideJSONBlock(block, sources, jsonBlocks)
			}
			merged := *effective
			merged.Body = mergeOverrideBody(effective, contribution, !isVariable)
			if result[pos.body] == bodies[pos.body] {
				bodyCopy := *result[pos.body]
				bodyCopy.Blocks = slices.Clone(bodyCopy.Blocks)
				result[pos.body] = &bodyCopy
			}
			result[pos.body].Blocks[pos.block] = &merged
			if !isVariable {
				index, exists := byKey[key]
				if !exists {
					index = len(overrides)
					byKey[key] = index
					overrides = append(overrides, ResourceOverride{Declaration: decl})
				}
				overrides[index].Effective = &merged
				overrides[index].Contributions = append(overrides[index].Contributions, contribution)
			}
		}
		bodyCopy := *body
		bodyCopy.Blocks = remaining
		result[firstOverride+i] = &bodyCopy
	}
	for i := range overrides {
		if overrides[i].Effective.Type == scheduledResource {
			overrides[i].certificateSource = writtenCertificate(overrides[i].Effective.Body.Attributes["certificate_body"], sources)
		}
	}
	return result, overrides
}

// The JSON-to-HCL conversion can change expression offsets. Use the original
// attribute range to recover the written certificate expression.
func writtenCertificate(attr *hclsyntax.Attribute, sources map[string][]byte) string {
	if attr == nil || !tfpath.IsJSONConfig(attr.SrcRange.Filename) {
		return ""
	}
	src := sources[attr.SrcRange.Filename]
	start, end := attr.NameRange.End.Byte, attr.SrcRange.End.Byte
	if start < 0 || end > len(src) || start >= end {
		return ""
	}
	_, raw, _ := strings.Cut(string(src[start:end]), ":")
	written, _ := strconv.Unquote(strings.TrimSpace(raw))
	return written
}

// overrideJSONBlock resolves the block/attribute ambiguity of JSON where a
// schema is available. Generic provider fields still merge by name against
// both arguments and nested blocks in the native syntax.
func overrideJSONBlock(block *hclsyntax.Block, sources map[string][]byte, cache map[string]hcl.Blocks) *hclsyntax.Block {
	filename := block.TypeRange.Filename
	if !tfpath.IsJSONConfig(filename) {
		return block
	}
	src := sources[filename]
	native, exists := cache[filename]
	if !exists {
		if file, diags := hcljson.Parse(src, filename); !diags.HasErrors() {
			if content, _, _ := file.Body.PartialContent(jsonConfigSchema); content != nil {
				native = content.Blocks
			}
		}
		cache[filename] = native
	}
	for _, candidate := range native {
		if candidate.Type == block.Type && candidate.DefRange == block.Body.SrcRange && slices.Equal(candidate.Labels, block.Labels) {
			converted := *block
			converted.Body = overrideJSONBody(candidate, src, block.Labels[0], "", "")
			return &converted
		}
	}
	return block
}

func overrideJSONBody(block *hcl.Block, src []byte, typ, parent, generated string) *hclsyntax.Body {
	headers := localdata.ConfigBlocks(typ, parent)
	switch parent {
	case "":
		headers = append(slices.Clone(headers), hcl.BlockHeaderSchema{Type: blockTypeLifecycle})
		if !slices.ContainsFunc(headers, func(header hcl.BlockHeaderSchema) bool { return header.Type == blockTypeDynamic }) {
			headers = append(headers, hcl.BlockHeaderSchema{Type: blockTypeDynamic, LabelNames: []string{"type"}})
		}
		if block.Type == scheduledResource {
			headers = append(headers,
				hcl.BlockHeaderSchema{Type: blockTypeConnection},
				hcl.BlockHeaderSchema{Type: blockTypeProvisioner, LabelNames: []string{"type"}},
			)
		}
	case blockTypeDynamic:
		headers = []hcl.BlockHeaderSchema{{Type: "content"}}
	case blockTypeLifecycle:
		headers = []hcl.BlockHeaderSchema{{Type: "precondition"}, {Type: "postcondition"}}
	case blockTypeProvisioner:
		headers = []hcl.BlockHeaderSchema{{Type: blockTypeConnection}}
	}
	content, remaining, _ := block.Body.PartialContent(&hcl.BodySchema{Blocks: headers})
	out := jsonBodyToHCL(remaining, src, block.DefRange)
	for _, child := range content.Blocks {
		converted := jsonBlockToHCL(child, src)
		nextParent, nextGenerated := child.Type, generated
		if child.Type == blockTypeDynamic && len(child.Labels) == 1 {
			nextGenerated = child.Labels[0]
		} else if child.Type == "content" {
			nextParent = generated
		}
		converted.Body = overrideJSONBody(child, src, typ, nextParent, nextGenerated)
		out.Blocks = append(out.Blocks, converted)
	}
	return out
}

func mergeOverrideBody(base, override *hclsyntax.Block, resource bool) *hclsyntax.Body {
	body := *base.Body
	body.Attributes = maps.Clone(base.Body.Attributes)
	for name, attr := range override.Body.Attributes {
		if !resource || name != metaArgDependsOn {
			body.Attributes[name] = attr
		}
	}
	body.Blocks = mergeOverrideBlocks(base.Body, override.Body, body.Attributes, resource)
	return &body
}

func mergeOverrideBlocks(
	base, override *hclsyntax.Body, attrs hclsyntax.Attributes, resource bool,
) hclsyntax.Blocks {
	blocks := make(hclsyntax.Blocks, 0, len(base.Blocks)+len(override.Blocks))
	replaced := make(map[string]bool, len(override.Blocks))
	var lifecycle *hclsyntax.Block
	for _, b := range override.Blocks {
		typ := overrideNestedBlockType(b)
		replaced[typ] = true
		delete(attrs, typ)
		if resource && b.Type == blockTypeLifecycle {
			lifecycle = b
		}
	}
	mergedLifecycle := false
	for _, b := range base.Blocks {
		typ := overrideNestedBlockType(b)
		switch {
		case lifecycle != nil && b.Type == blockTypeLifecycle:
			merged := *b
			merged.Body = mergeOverrideBody(b, lifecycle, false)
			blocks = append(blocks, &merged)
			mergedLifecycle = true
		case !replaced[typ] && override.Attributes[typ] == nil:
			blocks = append(blocks, b)
		}
	}
	for _, b := range override.Blocks {
		if b != lifecycle || !mergedLifecycle {
			blocks = append(blocks, b)
		}
	}
	return blocks
}

// Terraform overrides dynamic blocks by the type they generate. A concrete or
// dynamic override replaces both forms of that type in the base.
func overrideNestedBlockType(block *hclsyntax.Block) string {
	if dynamicblock.Is(block) {
		return dynamicblock.GeneratedType(block)
	}
	return block.Type
}
