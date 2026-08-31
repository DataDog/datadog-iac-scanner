/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfmodules

import "strings"

// IsTerraformJSONPath reports whether path uses Terraform's JSON configuration syntax.
func IsTerraformJSONPath(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".tf.json")
}

// IsTerraformHCLPath reports whether path is a native Terraform HCL configuration file.
func IsTerraformHCLPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".tf") && !IsTerraformJSONPath(path) && !strings.HasSuffix(lower, ".tfvars")
}

// IsTerraformConfigPath reports whether path may declare Terraform modules.
func IsTerraformConfigPath(path string) bool {
	return IsTerraformHCLPath(path) || IsTerraformJSONPath(path)
}
