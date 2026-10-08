/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
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
	_, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	instances := e.TakeModuleInstances()

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

	require.Empty(t, e.TakeModuleInstances())
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
	_, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)

	addresses := make([]string, 0)
	for _, instance := range e.TakeModuleInstances() {
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
	_, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Empty(t, e.TakeModuleInstances())
	require.Empty(t, e.Fork().TakeModuleInstances())

	e.SetTrackModuleInstances(true)
	fork := e.Fork()
	_, _, _, err = fork.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, fork.TakeModuleInstances(), 2, "forks inherit the setting")
}
