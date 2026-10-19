/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package localdata

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func TestGoogleIAMPolicy(t *testing.T) {
	src := `
binding {
  role    = "roles/cloudkms.cryptoKeyDecrypter"
  members = ["allUsers", var.member]
  condition {
    title      = "expires"
    expression = "request.time < timestamp(\"2030-01-01T00:00:00Z\")"
  }
}
binding {
  role    = "roles/viewer"
  members = [google_service_account.sa.member]
}
audit_config {
  service = "allServices"
  audit_log_configs {
    log_type         = "DATA_READ"
    exempted_members = ["user:a@example.com"]
  }
}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	ctx := &hcl.EvalContext{Variables: map[string]cty.Value{
		"var": cty.ObjectVal(map[string]cty.Value{"member": cty.StringVal("user:b@example.com")}),
	}}
	source, ok := Lookup(googleIAMPolicyType)
	require.True(t, ok)
	got := source(file.Body, func(expr hcl.Expression) (cty.Value, bool) {
		v, d := expr.Value(ctx)
		return v, !d.HasErrors()
	})
	require.Equal(t, `{"auditConfigs":[{"auditLogConfigs":[{"exemptedMembers":["user:a@example.com"],"logType":"DATA_READ"}],`+
		`"service":"allServices"}],"bindings":[{"condition":{"expression":"request.time < timestamp(\"2030-01-01T00:00:00Z\")",`+
		`"title":"expires"},"members":["allUsers","user:b@example.com"],"role":"roles/cloudkms.cryptoKeyDecrypter"},`+
		`{"role":"roles/viewer"}]}`, got["policy_data"])
}

func TestGoogleIAMPolicyDynamicBlocks(t *testing.T) {
	src := `
dynamic "binding" {
  for_each = { "roles/viewer" = ["allUsers"], "roles/editor" = ["user:a@example.com"] }
  content {
    role    = binding.key
    members = binding.value
  }
}
binding {
  role    = "roles/owner"
  members = ["user:o@example.com"]
}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	source, ok := Lookup(googleIAMPolicyType)
	require.True(t, ok)
	got := source(file.Body, func(expr hcl.Expression) (cty.Value, bool) {
		v, d := expr.Value(&hcl.EvalContext{})
		return v, !d.HasErrors()
	})
	require.Equal(t, `{"bindings":[{"members":["user:a@example.com"],"role":"roles/editor"},`+
		`{"members":["allUsers"],"role":"roles/viewer"},{"members":["user:o@example.com"],"role":"roles/owner"}]}`,
		got["policy_data"])
}

func TestGoogleIAMPolicyOfUnresolvedDynamicBlocksStaysUnresolved(t *testing.T) {
	source, ok := Lookup(googleIAMPolicyType)
	require.True(t, ok)
	eval := func(expr hcl.Expression) (cty.Value, bool) {
		v, d := expr.Value(&hcl.EvalContext{})
		return v, !d.HasErrors()
	}
	for _, src := range []string{
		`
dynamic "binding" {
  for_each = var.bindings
  content {
    role    = binding.key
    members = binding.value
  }
}
`,
		`
dynamic "binding" {
  for_each = var.bindings
  content {
    role    = binding.key
    members = binding.value
  }
}
binding {
  role    = "roles/owner"
  members = ["user:o@example.com"]
}
`,
		`
binding {
  role    = "roles/viewer"
  members = ["allUsers"]
  dynamic "condition" {
    for_each = var.conditions
    content {
      title      = condition.value
      expression = "true"
    }
  }
}
`,
	} {
		file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
		require.False(t, diags.HasErrors(), diags.Error())
		require.Nil(t, source(file.Body, eval))
	}
}

func TestGoogleBindingKeepsFirstCondition(t *testing.T) {
	src := `
binding {
  role    = "roles/viewer"
  members = ["user:a@example.com"]
  condition {
    title      = "first"
    expression = "false"
  }
  condition {
    title      = "second"
    expression = "true"
  }
}`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	rd := &partial.Renderer{Ctx: &hcl.EvalContext{}, Source: partial.BytesSource([]byte(src))}
	got := googleIAMPolicyAttributes(file.Body, rd.Render)
	require.Contains(t, got["policy_data"], `"title":"first"`)
	require.Contains(t, got["policy_data"], `"expression":"false"`)
	require.NotContains(t, got["policy_data"], `"title":"second"`)
}
