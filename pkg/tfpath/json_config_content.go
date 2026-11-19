/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfpath

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
)

// Top-level keys of Terraform/OpenTofu JSON configuration (not plan JSON).
// "data" and "output" alone are too common in unrelated JSON, so they are
// omitted; a data-only or output-only file still needs another config key or a
// .tf.json suffix.
var jsonConfigBlockKeys = []string{
	"resource", "module", "terraform", "provider", "variable", "locals",
	"ephemeral", "check", "moved", "import", "removed",
}

// IsPlainJSON reports whether path is a bare .json file (not .tf.json,
// .tofu.json or .tfvars.json).
func IsPlainJSON(path string) bool {
	if IsJSONConfig(path) || IsTFVarsJSON(path) {
		return false
	}
	return strings.EqualFold(filepath.Ext(path), ".json")
}

// UsesJSONSyntax reports whether a Terraform configuration path should be
// parsed with HCL JSON syntax: .tf.json / .tofu.json, or a plain .json file
// that was already accepted as configuration by content.
func UsesJSONSyntax(path string) bool {
	return IsJSONConfig(path) || IsPlainJSON(path)
}

// LooksLikeJSONConfig reports whether content is Terraform/OpenTofu JSON
// configuration (including CDKTF-generated stacks), not a plan, package.json
// or other unrelated JSON. Extension-based callers still prefer IsJSONConfig
// for .tf.json; this is for plain .json names.
func LooksLikeJSONConfig(content []byte) bool {
	if looksLikeTerraformPlan(content) {
		return false
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(content, &top); err != nil || len(top) == 0 {
		return false
	}
	for _, key := range jsonConfigBlockKeys {
		if _, ok := top[key]; ok {
			return true
		}
	}
	return false
}

func looksLikeTerraformPlan(content []byte) bool {
	return bytes.Contains(content, []byte(`"format_version"`)) &&
		bytes.Contains(content, []byte(`"planned_values"`))
}
