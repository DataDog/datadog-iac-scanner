/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package converter

import (
	"context"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
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
	plan := instances.Resolve(count, forEach, c.renderer.Ctx)
	if plan.Unresolved {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Debug().
			Str("expansion_kind", plan.Kind).
			Str("address", strings.Join(block.Labels, ".")).
			Msg("terraform: count/for_each does not resolve; block scanned as a single instance as written")
	}
	if !plan.Expands() {
		return false, nil
	}
	if len(plan.Items) == 0 {
		// No instance: the block declares nothing and has no address, matching
		// a plan with no resource_changes entry for it.
		ddLines["_dd_"+block.Type] = model.LineObject{Line: block.TypeRange.Start.Line}
		c.expansions = append(c.expansions, c.expansionFor(block, plan, append([]string{block.Type}, block.Labels...), nil))
		return true, nil
	}
	if !instances.ReadsInstance(block.Body) {
		// The block does not read its instance context, so every planned
		// instance converts identically: the file keeps the block as written
		// and findings on it fan out to every planned address.
		c.expansions = append(c.expansions, c.expansionFor(
			block, plan, append([]string{block.Type}, block.Labels...), nil))
		return false, nil
	}
	values, positions, err := c.convertInstances(ctx, block, plan)
	if err != nil || values == nil {
		return false, err
	}
	ddLines["_dd_"+block.Type] = model.LineObject{Line: block.TypeRange.Start.Line}
	c.expansions = append(c.expansions, c.expansionFor(
		block, plan, append([]string{block.Type}, block.Labels...), positions))
	path := append([]string{block.Type}, block.Labels...)
	if err := insertBlock(ctx, out, path, values[0]); err != nil {
		return true, err
	}
	if len(values) > 1 {
		c.expanded = append(c.expanded, Expanded{Path: path, Values: values})
	}
	return true, nil
}

// expansionFor builds the expansion record of one block: every instance
// address its plan produces, and which addresses each distinct converted
// instance covers. A nil positions list means every planned instance converts
// identically, so the single conversion covers them all. Addresses beyond the
// expansion cap are unknown (their keys were never evaluated) and are left
// out; the block is also scanned as written, and findings on that conversion
// carry no address.
func (c *converter) expansionFor(
	block *hclsyntax.Block, plan instances.Plan, path []string, positions [][]int,
) model.ResourceExpansion {
	mode := address.Mode(block.Type)
	typ, name := "", ""
	switch block.Type {
	case blockTypeModule:
		name = block.Labels[0]
		mode = ""
		// A module call address has no resource mode: module.<name>[key].
		typ = blockTypeModule
	default:
		typ, name = block.Labels[0], block.Labels[1]
	}

	prefix := ""
	if block.Type == blockTypeModule {
		prefix = "module." + name
	} else {
		prefix = typ + "." + name
		if mode == address.ModeData {
			prefix = "data." + prefix
		}
	}

	addresses := make([]string, 0, len(plan.Items))
	known := make([]int, 0, len(plan.Items))
	for i, item := range plan.Items {
		key := ""
		if plan.Kind == instances.KindCount {
			key = "[" + strconv.Itoa(i) + "]"
		} else if formatted, ok := address.FormatKey(item.Key); ok {
			key = formatted
		} else {
			// An unformattable key cannot take part in an address; the
			// instance still converts, but is not reported per address.
			continue
		}
		addresses = append(addresses, prefix+key)
		known = append(known, i)
	}

	if positions == nil {
		// Every planned instance converts identically.
		positions = make([][]int, 1)
		positions[0] = known
	}
	// Renumber positions from item indexes to indexes into addresses.
	renumber := make([]int, len(plan.Items))
	for i := range renumber {
		renumber[i] = -1
	}
	for out, in := range known {
		renumber[in] = out
	}
	mapped := make([][]int, len(positions))
	for vi, idx := range positions {
		mapped[vi] = make([]int, 0, len(idx))
		for _, i := range idx {
			if i >= 0 && renumber[i] >= 0 {
				mapped[vi] = append(mapped[vi], renumber[i])
			}
		}
	}
	return model.ResourceExpansion{
		Path:      strings.Join(path, "."),
		Type:      typ,
		Name:      name,
		Data:      mode == address.ModeData,
		Truncated: plan.Truncated(),
		Addresses: addresses,
		Positions: mapped,
	}
}

// convertInstances converts the block once per instance of plan and returns
// the distinct results with the planned instances that produced each: instances
// that read the same under every position add nothing the first does not. A
// block asking for more instances than are expanded is also converted as
// written, with count and each unresolved. It returns nil when the block does
// not fit the file's instance budget.
func (c *converter) convertInstances(
	ctx context.Context, block *hclsyntax.Block, plan instances.Plan,
) ([]model.Document, [][]int, error) {
	extra := len(plan.Items) - 1
	if plan.Truncated() {
		extra++
	}
	if extra > c.instancesLeft {
		c.noteInstanceOverflow(ctx, block, plan, instances.MaxPerBlock)
		return nil, nil, nil
	}
	if plan.Truncated() {
		c.noteInstanceOverflow(ctx, block, plan, instances.MaxPerBlock)
	}
	var values []model.Document
	var positions [][]int
	add := func(value model.Document, itemIndex int) {
		for vi, seen := range values {
			if SameInstance(seen, value) {
				positions[vi] = append(positions[vi], itemIndex)
				return
			}
		}
		values = append(values, value)
		positions = append(positions, []int{itemIndex})
	}
	for itemIndex, item := range plan.Items {
		name, iteration := plan.Variable(item)
		unbind := c.bind(name, iteration)
		c.dynamicLeft = dynamicblock.MaxGeneratedPerResource
		value, err := c.convertBody(ctx, block.Body, block.TypeRange.Start.Line)
		unbind()
		if err != nil {
			return nil, nil, err
		}
		add(value, itemIndex)
	}
	if plan.Truncated() {
		c.dynamicLeft = dynamicblock.MaxGeneratedPerResource
		// The as-written conversion stands for the block itself, not for any
		// one planned instance; its item index is unknown, so it maps to no
		// address (see the expansion info built by the caller).
		value, err := c.convertBody(ctx, block.Body, block.TypeRange.Start.Line)
		if err != nil {
			return nil, nil, err
		}
		add(value, -1)
	}
	c.instancesLeft -= len(values) - 1
	return values, positions, nil
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
func (c *converter) noteInstanceOverflow(ctx context.Context, block *hclsyntax.Block, plan instances.Plan, limit int) {
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
