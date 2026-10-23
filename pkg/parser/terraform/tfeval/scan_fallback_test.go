/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanFallbacksKeepModuleInputsAndOriginalEvaluation(t *testing.T) {
	for _, tc := range []struct{ meta, value, want string }{
		{`count = 55`, `value = "${var.prefix}-${count.index}"`, `child-${count.index}`},
		{`for_each = {for n in range(55): tostring(n) => n}`, `value = "${var.prefix}-${each.key}-${each.value}"`,
			`child-${each.key}-${each.value}`},
	} {
		t.Run(tc.meta, func(t *testing.T) {
			root := t.TempDir()
			writeModule(t, root, "child", map[string]string{"main.tf": `
variable "prefix" { default = "default" }
resource "example" "r" {
` + tc.meta + "\n" + tc.value + "\n}"})
			dir := writeModule(t, root, "root", map[string]string{"main.tf": `module "m" {
 source = "../child"
 prefix = "child"
}`})
			resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
			require.NoError(t, err)
			require.Len(t, resources, 50)
			views := WithScanFallbacks(resources)
			require.Len(t, views, 51)
			require.True(t, resources[0].ExpansionTruncated, "scan preparation must not mutate evaluation/cache results")
			fallback := &views[len(views)-1]
			require.Equal(t, "r", fallback.Name)
			require.Equal(t, "module.m", fallback.ModuleAddress)
			require.Equal(t, tc.want, AttributesToDocument(fallback)["value"])
		})
	}
}
