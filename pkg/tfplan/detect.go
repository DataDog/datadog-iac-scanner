/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfplan

import "bytes"

// IsTerraformPlanJSON is a fast byte-level heuristic that avoids a full JSON
// parse. Both keys are required by the Terraform plan JSON spec, so their
// co-presence is a reliable signal. Shared by the JSON parser and analyzer.
func IsTerraformPlanJSON(content []byte) bool {
	return bytes.Contains(content, []byte(`"format_version"`)) &&
		bytes.Contains(content, []byte(`"planned_values"`))
}
