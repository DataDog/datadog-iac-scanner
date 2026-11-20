/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"fmt"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/zclconf/go-cty/cty"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func instanceAddresses(instances []ModuleInstance) map[string]string {
	out := make(map[string]string, len(instances))
	for _, instance := range instances {
		out[instance.ModuleAddress] = instance.Dir
	}
	return out
}

// Modules declaring no resource are still instances: the variables and outputs
// they declare are deployed by every call. Sibling calls with identical inputs
// reuse one cached evaluation, and the prepass evaluating them first must not
// record them twice.
func TestEvaluateModule_RecordsEveryModuleCall(t *testing.T) {
	root := t.TempDir()
	helper := writeModule(t, root, "helper", map[string]string{
		"outputs.tf": `
variable "name" {}
output "name" { value = var.name }
`,
	})
	wrapper := writeModule(t, root, "wrapper", map[string]string{
		"main.tf": `
variable "name" {}
module "helper" {
  source = "../helper"
  name   = var.name
}
output "name" { value = module.helper.name }
`,
	})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "a" {
  source = "../wrapper"
  name   = "same"
}
module "b" {
  source = "../wrapper"
  name   = module.a.name
}
`,
	})

	e := New()
	e.SetTrackModuleInstances(true)
	evaluation, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	instances := evaluation.ModuleInstances

	require.Equal(t, map[string]string{
		"module.a":               wrapper,
		"module.a.module.helper": helper,
		"module.b":               wrapper,
		"module.b.module.helper": helper,
	}, instanceAddresses(instances))
	require.Len(t, instances, 4)

	byAddress := make(map[string]ModuleInstance, len(instances))
	for _, instance := range instances {
		byAddress[instance.ModuleAddress] = instance
	}
	chain := byAddress["module.b.module.helper"].CallChain
	require.Len(t, chain, 2)
	require.Equal(t, "b", chain[0].ModuleName)
	require.Equal(t, filepath.Join(stack, "main.tf"), chain[0].CalledFrom)
	require.Equal(t, "helper", chain[1].ModuleName)
	require.NotNil(t, chain[0].Body)

}

// A call whose evaluation fails is not an instance, nor is anything below it.
func TestEvaluateModule_DropsCallsOfFailedModules(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{"main.tf": `output "x" { value = 1 }`})
	writeModule(t, root, "loop", map[string]string{
		"main.tf": `
module "leaf" { source = "../leaf" }
module "self" { source = "../loop" }
`,
	})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "ok" { source = "../leaf" }
module "loop" { source = "../loop" }
`,
	})

	e := New()
	e.SetTrackModuleInstances(true)
	evaluation, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)

	addresses := make([]string, 0)
	for _, instance := range evaluation.ModuleInstances {
		addresses = append(addresses, instance.ModuleAddress)
	}
	sort.Strings(addresses)
	require.Equal(t, []string{"module.loop", "module.loop.module.leaf", "module.ok"}, addresses)
}

// Recording is opt-in: scans with no use for module calls pay nothing for them.
func TestEvaluateModule_RecordsNoModuleCallsByDefault(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{"main.tf": `output "x" { value = 1 }`})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "a" { source = "../leaf" }
module "b" { source = "../leaf" }
`,
	})

	e := New()
	evaluation, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Empty(t, evaluation.ModuleInstances)

	e.SetTrackModuleInstances(true)
	fork := e.Fork()
	evaluation2, evaluation2Err := fork.EvaluateModule(context.Background(), stack, nil)
	err = evaluation2Err
	require.NoError(t, err)
	require.Len(t, evaluation2.ModuleInstances, 2, "forks inherit the setting")
}

func TestEvaluateModule_InventoryObservations(t *testing.T) {
	for _, test := range []struct {
		name, source     string
		reason           InventoryGapReason
		kind, typ, group string
	}{
		{"known empty resource", `resource "test_resource" "item" {count=0}`, inventoryNoGap, "", "", ""},
		{"known resource", `resource "test_resource" "item" {count=2}`, inventoryNoGap, "", "", ""},
		{"ordinary unknown attribute", `variable "input" {}
resource "test_resource" "item" {value=var.input}`, inventoryNoGap, "", "", ""},
		{"ordinary failed attribute", `resource "test_resource" "item" {value=length(null)}`, inventoryNoGap, "", "", ""},
		{"unknown resource expansion", `variable "n" {type=number}
resource "test_resource" "item" {count=var.n}`, InventoryExpansionUnknown, "resource", "test_resource", "item"},
		{"invalid resource expansion", `resource "test_resource" "item" {count=-1}`, InventoryExpansionInvalid, "resource", "test_resource", "item"},
		{"known empty data", `data "test_data" "item" {for_each={}}`, inventoryNoGap, "", "", ""},
		{"unknown data expansion", `variable "keys" {type=set(string)}
data "test_data" "item" {for_each=var.keys}`, InventoryExpansionUnknown, "data", "test_data", "item"},
		{"invalid data expansion", `data "test_data" "item" {for_each=["key"]}`, InventoryExpansionInvalid, "data", "test_data", "item"},
		{"cyclic resource expansion", `resource "test_resource" "item" {count=length(test_resource.item)}`, InventoryExpansionCycle, "resource", "test_resource", "item"},
		{"cyclic data expansion", `data "test_data" "item" {count=length(data.test_data.item)}`, InventoryExpansionCycle, "data", "test_data", "item"},
		{"cyclic ordinary attribute", `resource "test_resource" "item" {value=test_resource.item.value}`, inventoryNoGap, "", "", ""},
		{"known empty module", `module "child" {
source="./child"
count=0
}`, inventoryNoGap, "", "", ""},
		{"unknown module expansion", `variable "n" {type=number}
module "child" {
source="./child"
count=var.n
}`, InventoryExpansionUnknown, "module", "", "child"},
		{"invalid module expansion", `module "child" {
source="./child"
count=-1
}`, InventoryExpansionInvalid, "module", "", "child"},
		{"unavailable module source", `module "child" {}`, InventoryModuleSourceUnavailable, "module", "", "child"},
		{"unavailable remote source", `module "child" {source="example.com/acme/module/cloud"}`, InventoryRemoteModuleUnavailable, "module", "", "child"},
		{"unavailable child directory", `module "missing" {source="./missing"}`, InventoryModuleEvaluationFailed, "module", "", "missing"},
		{"cycle", `module "self" {source="./"}`, InventoryModuleCycle, "module", "", "self"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeModule(t, root, "child", map[string]string{"main.tf": `resource "test_resource" "nested" {value="known"}`})
			dir := writeModule(t, root, "", map[string]string{"main.tf": test.source})
			e := New()
			var previous InventoryObservations
			for i := 0; i < 2; i++ {
				result, err := e.EvaluateModule(context.Background(), dir, nil)
				require.NoError(t, err)
				observations := result.InventoryObservations()
				for _, resource := range result.Resources {
					scopes := []*ModuleScope{resource.Scope}
					for _, site := range resource.CallChain {
						scopes = append(scopes, site.Caller)
					}
					for _, scope := range scopes {
						require.NotNil(t, scope)
						require.Zero(t, scope.observations)
						require.Nil(t, scope.inputDiagnostics)
					}
				}
				require.Equal(t, dir, observations.RootDir)
				require.True(t, observations.EvaluationCompleted)
				if test.reason == inventoryNoGap {
					require.Empty(t, observations.Gaps)
					continue
				}
				require.Len(t, observations.Gaps, 1)
				gap := observations.Gaps[0]
				require.Equal(t, test.reason, gap.Reason)
				require.Equal(t, "", gap.ModuleAddress)
				require.Equal(t, test.kind, gap.Kind)
				require.Equal(t, test.typ, gap.Type)
				require.Equal(t, test.group, gap.Name)
				require.Equal(t, filepath.Join(dir, "main.tf"), gap.Subject.Filename)
				if i > 0 {
					require.Equal(t, previous, observations)
				}
				previous = observations
				inspection := result.InventoryObservations()
				inspection.Gaps[0].Name = "mutated snapshot"
				require.Equal(t, test.group, result.InventoryObservations().Gaps[0].Name)
			}
		})
	}
}

func TestEvaluateModule_InventoryContexts(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `variable "n" {type=number}
resource "test_resource" "item" {count=var.n}`})
	dir := writeModule(t, root, "root", map[string]string{"main.tf": `variable "n" {type=number}
module "left" {
source="../child"
n=var.n
}
module "right" {
source="../child"
n=var.n
}`})
	e := New()
	var first InventoryObservations
	for i, input := range []cty.Value{cty.UnknownVal(cty.Number), cty.NumberIntVal(0), cty.NumberIntVal(2), cty.UnknownVal(cty.Number)} {
		result, err := e.EvaluateModule(context.Background(), dir, map[string]cty.Value{"n": input})
		require.NoError(t, err)
		observations := result.InventoryObservations()
		require.True(t, observations.EvaluationCompleted)
		if input.IsKnown() {
			require.Empty(t, observations.Gaps)
			continue
		}
		require.Len(t, observations.Gaps, 2)
		require.Equal(t, []string{"module.left", "module.right"}, []string{observations.Gaps[0].ModuleAddress, observations.Gaps[1].ModuleAddress})
		if i == 0 {
			first = observations
		} else {
			require.Equal(t, first, observations)
		}
	}
	// A data block is refreshed before and after publication of module outputs.
	// Its early unknown expansion must be replaced by the final known plan.
	writeModule(t, root, "sizes", map[string]string{"main.tf": `output "n" {value=1}`})
	settled := writeModule(t, root, "settled", map[string]string{"main.tf": `module "sizes" {source="../sizes"}
data "test_data" "item" {count=module.sizes.n}`})
	result, err := e.EvaluateModule(context.Background(), settled, nil)
	require.NoError(t, err)
	require.Empty(t, result.InventoryObservations().Gaps)
	require.Equal(t, first.RootDir, dir)
}

func TestEvaluateModule_JSONInventoryGroups(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "json", map[string]string{"main.tf.json": `{
 "variable":{"n":{"type":"number"}},
 "resource":{"test_left":{"same":{"count":"${var.n}"}},"test_right":{"same":{"count":"${var.n}"}}},
 "data":{"test_left":{"same":{"count":"${var.n}"}}},
 "module":{"left":{},"right":{}}
}`})
	e := New()
	var first InventoryObservations
	for i := 0; i < 2; i++ {
		result, err := e.EvaluateModule(context.Background(), dir, nil)
		require.NoError(t, err)
		observations := result.InventoryObservations()
		require.True(t, observations.EvaluationCompleted)
		require.Len(t, observations.Gaps, 5)
		groups := map[[3]string]InventoryGapReason{}
		for _, gap := range observations.Gaps {
			require.Equal(t, filepath.Join(dir, "main.tf.json"), gap.Subject.Filename)
			groups[[3]string{gap.Kind, gap.Type, gap.Name}] = gap.Reason
		}
		require.Equal(t, map[[3]string]InventoryGapReason{
			{"resource", "test_left", "same"}:  InventoryExpansionUnknown,
			{"resource", "test_right", "same"}: InventoryExpansionUnknown,
			{"data", "test_left", "same"}:      InventoryExpansionUnknown,
			{"module", "", "left"}:             InventoryModuleSourceUnavailable,
			{"module", "", "right"}:            InventoryModuleSourceUnavailable,
		}, groups)
		if i == 0 {
			first = observations
		} else {
			require.Equal(t, first, observations)
		}
	}
}

func TestEvaluateModule_InventoryConfigurationAndStops(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "root", map[string]string{"bad.tf": `resource "test_resource" "bad" {`, "main.tf": `resource "test_resource" "good" {}`})
	for _, readFailure := range []bool{false, true} {
		t.Run(fmt.Sprintf("readFailure=%t", readFailure), func(t *testing.T) {
			e := New()
			if readFailure {
				e = NewWithFS(&configurationReadFS{FS: vfs.DiskFS{}, failPath: filepath.Join(dir, "bad.tf")})
			}
			result, err := e.EvaluateModule(context.Background(), dir, nil)
			require.NoError(t, err)
			observations := result.InventoryObservations()
			require.True(t, observations.EvaluationCompleted)
			require.Len(t, result.Resources, 1)
			require.Len(t, observations.Gaps, 1)
			require.Equal(t, InventoryConfigurationUnavailable, observations.Gaps[0].Reason)
			require.Equal(t, filepath.Join(dir, "bad.tf"), observations.Gaps[0].Subject.Filename)
		})
	}
	writeModule(t, root, "child", map[string]string{"main.tf": `resource "test_resource" "child" {}`})
	caller := writeModule(t, root, "caller", map[string]string{"main.tf": `module "child" {source="../child"}`})
	e := New()
	e.maxDepth = 0
	result, err := e.EvaluateModule(context.Background(), caller, nil)
	require.NoError(t, err)
	require.Len(t, result.InventoryObservations().Gaps, 1)
	require.Equal(t, InventoryModuleDepth, result.InventoryObservations().Gaps[0].Reason)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = e.EvaluateModule(ctx, caller, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, result.InventoryObservations().EvaluationCompleted)
	require.Empty(t, result.InventoryObservations().Gaps)
	// Cancellation must not replace the earlier completed facts or poison a fork.
	fork := e.Fork()
	fork.maxDepth = defaultMaxDepth
	result, err = fork.EvaluateModule(context.Background(), caller, nil)
	require.NoError(t, err)
	require.True(t, result.InventoryObservations().EvaluationCompleted)
	require.Empty(t, result.InventoryObservations().Gaps)
}
