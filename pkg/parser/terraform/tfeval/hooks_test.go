/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func TestHooksSeeEveryModuleInstance(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "mod"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
module "a" {
  count  = 2
  source = "./mod"
  n      = count.index
}
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mod", "main.tf"), []byte(`
variable "n" {}
output "o" { value = var.n }
`), 0o600))
	e := New()
	var bodies int
	scopes := map[string]*ModuleScope{}
	inputs := map[string]map[string]cty.Value{}
	e.SetHooks(&Hooks{
		Bodies: func(_ string, b []*hclsyntax.Body) []*hclsyntax.Body { bodies++; return b },
		Scope: func(_, address string, scope *ModuleScope, _ map[string]cty.Value) {
			scopes[address] = scope
		},
		Instance: func(_, address string, _ []CallSite, in, _ map[string]cty.Value) { inputs[address] = in },
	})
	_, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	require.Equal(t, 2, bodies)
	require.Contains(t, scopes, "")
	require.NotNil(t, scopes[""].EvalContext())
	require.Len(t, inputs, 2)
	require.True(t, inputs["module.a[1]"]["n"].RawEquals(cty.NumberIntVal(1)))
}
