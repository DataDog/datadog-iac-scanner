/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Module expansion can depend on a later-declared resource. The addresses
// must reflect its final value, and cache reuse must rebase nested module
// addresses and call chains to each caller.
func TestEvaluateModule_LateExpansionAddressesDoNotDependOnBlockOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "dependencies first"
		if reverse {
			name = "expansions first"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeModule(t, root, "inner", map[string]string{"main.tf": `
variable "name" {}
resource "aws_sqs_queue" "q" { name = var.name }
`})
			writeModule(t, root, "leaf", map[string]string{"main.tf": `
variable "name" {}
resource "aws_s3_bucket" "b" { bucket = var.name }
module "inner" {
  source = "../inner"
  name   = var.name
}
`})

			counted := `module "counted" {
  source = "../leaf"
  count  = length(r.seed.tags)
  name   = "shared"
}`
			mapped := `module "mapped" {
  source   = "../leaf"
  for_each = toset(r.seed.tags)
  name     = "shared"
}`
			seed := `resource "r" "seed" { tags = ["blue", "green"] }`
			var blocks []string
			if reverse {
				blocks = []string{counted, mapped, seed}
			} else {
				blocks = []string{seed, mapped, counted}
			}
			stack := writeModule(t, root, "stack", map[string]string{"main.tf": strings.Join(blocks, "\n")})

			engine := New()
			engine.SetTrackModuleInstances(true)
			resources, _, _, err := engine.EvaluateModule(context.Background(), stack, nil)
			require.NoError(t, err)

			var modules []string
			for _, instance := range engine.TakeModuleInstances() {
				modules = append(modules, instance.ModuleAddress)
			}
			sort.Strings(modules)
			require.Equal(t, []string{
				"module.counted[0]", "module.counted[0].module.inner",
				"module.counted[1]", "module.counted[1].module.inner",
				`module.mapped["blue"]`, `module.mapped["blue"].module.inner`,
				`module.mapped["green"]`, `module.mapped["green"].module.inner`,
			}, modules)

			var nested []string
			for _, resource := range resources {
				if resource.Type == "aws_sqs_queue" {
					nested = append(nested, resource.ModuleAddress+"/"+resource.Type+"."+resource.Name)
					if len(resource.CallChain) != 2 {
						t.Fatalf("%s has call chain length %d, want 2", resource.ModuleAddress, len(resource.CallChain))
					}
					if strings.HasPrefix(resource.ModuleAddress, "module.counted[") {
						require.Equal(t, "counted", resource.CallChain[0].ModuleName)
					} else {
						require.Equal(t, "mapped", resource.CallChain[0].ModuleName)
					}
					require.Equal(t, "inner", resource.CallChain[1].ModuleName)
				}
			}
			sort.Strings(nested)
			require.Equal(t, []string{
				"module.counted[0].module.inner/aws_sqs_queue.q",
				"module.counted[1].module.inner/aws_sqs_queue.q",
				`module.mapped["blue"].module.inner/aws_sqs_queue.q`,
				`module.mapped["green"].module.inner/aws_sqs_queue.q`,
			}, nested)
			var buckets []string
			for _, resource := range resources {
				if resource.Type == "aws_s3_bucket" {
					buckets = append(buckets, resource.ModuleAddress)
				}
			}
			sort.Strings(buckets)
			require.Equal(t, []string{
				"module.counted[0]", "module.counted[1]", `module.mapped["blue"]`, `module.mapped["green"]`,
			}, buckets)
			for _, resource := range resources {
				if resource.Type != "aws_s3_bucket" {
					continue
				}
				require.Equal(t, "shared", resource.Attributes["bucket"].AsString())
			}
		})
	}
}
