/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package converter

import (
	"context"
	"reflect"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/instances"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

const (
	blockTypeResource = "resource"
	blockTypeData     = "data"
	blockTypeModule   = "module"
)

// convertTopLevelInstances converts a resource, data or module block whose
// count or for_each decides how many instances it has. It reports false,
// adding nothing, for every other block, and for those that stand for a single
// instance or for an unknown number of them: they are converted as written.
func (c *converter) convertTopLevelInstances(
	ctx context.Context, block *hclsyntax.Block, out model.Document, ddLines map[string]model.LineObject,
) (bool, error) {
	switch block.Type {
	case blockTypeResource, blockTypeData:
		if len(block.Labels) < 2 {
			return false, nil
		}
	case blockTypeModule:
		if len(block.Labels) < 1 {
			return false, nil
		}
	default:
		return false, nil
	}
	count, forEach := instances.Attributes(block.Body)
	plan := instances.Resolve(count, forEach, c.renderer.Ctx, 0)
	if plan.Unresolved {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Debug().
			Str("expansion_kind", plan.Kind).
			Str("address", strings.Join(block.Labels, ".")).
			Msg("terraform: count/for_each does not resolve; block scanned as a single instance as written")
	}
	if plan.Kind == "" || plan.Unresolved {
		return false, nil
	}
	if len(plan.Items) == 0 {
		// No instance: the block declares nothing.
		ddLines["_dd_"+block.Type] = model.LineObject{Line: block.TypeRange.Start.Line}
		return true, nil
	}
	values, err := c.convertInstances(ctx, block, &plan)
	if err != nil || values == nil {
		return false, err
	}
	ddLines["_dd_"+block.Type] = model.LineObject{Line: block.TypeRange.Start.Line}
	path := append([]string{block.Type}, block.Labels...)
	if err := insertBlock(ctx, out, path, values[0]); err != nil {
		return true, err
	}
	if len(values) > 1 {
		c.expanded = append(c.expanded, Expanded{Path: path, Values: values})
	}
	return true, nil
}

// convertInstances converts the block once per instance of plan and returns
// the distinct results: instances that read the same under every position add
// nothing the first does not. A block asking for more instances than are
// expanded is also converted as written, with count and each unresolved. It
// returns nil when the block does not fit the file's instance budget.
func (c *converter) convertInstances(
	ctx context.Context, block *hclsyntax.Block, plan *instances.Plan,
) ([]model.Document, error) {
	extra := len(plan.Items) - 1
	if plan.Truncated() {
		extra++
	}
	if extra > c.instancesLeft {
		c.noteInstanceOverflow(ctx, block, plan, instances.MaxPerBlock)
		return nil, nil
	}
	if plan.Truncated() {
		c.noteInstanceOverflow(ctx, block, plan, instances.MaxPerBlock)
	}
	var values []model.Document
	add := func(value model.Document) {
		for _, seen := range values {
			if reflect.DeepEqual(seen, value) {
				return
			}
		}
		values = append(values, value)
	}
	for _, item := range plan.Items {
		name, iteration := plan.Variable(item)
		unbind := c.bind(name, iteration)
		c.dynamicLeft = dynamicblock.MaxGeneratedPerResource
		value, err := c.convertBody(ctx, block.Body, block.TypeRange.Start.Line)
		unbind()
		if err != nil {
			return nil, err
		}
		add(value)
	}
	if plan.Truncated() {
		c.dynamicLeft = dynamicblock.MaxGeneratedPerResource
		value, err := c.convertBody(ctx, block.Body, block.TypeRange.Start.Line)
		if err != nil {
			return nil, err
		}
		add(value)
	}
	c.instancesLeft -= extra
	return values, nil
}

// bind sets the variable name for the evaluation that follows and returns the
// function that restores what it held.
func (c *converter) bind(name string, value cty.Value) func() {
	if c.inputVars == nil {
		c.inputVars = make(VariableMap)
		c.renderer.Ctx.Variables = c.inputVars
	}
	previous, had := c.inputVars[name]
	c.inputVars[name] = value
	return func() {
		if had {
			c.inputVars[name] = previous
		} else {
			delete(c.inputVars, name)
		}
	}
}

// noteInstanceOverflow logs the first block of a file that is not expanded in
// full for exceeding a cap, as the evaluator does per scan.
func (c *converter) noteInstanceOverflow(ctx context.Context, block *hclsyntax.Block, plan *instances.Plan, limit int) {
	if c.instancesWarned {
		return
	}
	c.instancesWarned = true
	contextLogger := logger.FromContext(ctx)
	contextLogger.Warn().
		Str("expansion_kind", plan.Kind).
		Str("address", strings.Join(block.Labels, ".")).
		Int("requested_instances", plan.Requested).
		Int("count_expansion_cap", limit).
		Msg("tfeval: count/for_each expansion truncated; remaining instances scanned as written")
}
