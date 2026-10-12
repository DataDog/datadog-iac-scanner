/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package localdata

import (
	"testing"

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
