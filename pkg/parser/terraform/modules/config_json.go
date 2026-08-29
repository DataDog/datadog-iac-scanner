/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfmodules

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

func extractJSONFile(content []byte) (*fileExtract, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(content, &root); err != nil {
		return nil, fmt.Errorf("decoding Terraform JSON: %w", err)
	}
	extract := &fileExtract{}
	if raw, ok := root["locals"]; ok {
		extract.locals = stringMapFromJSON(raw)
	}
	if raw, ok := root["variable"]; ok {
		extract.vars = variableDefaultsFromJSON(raw)
	}
	if raw, ok := root["module"]; ok {
		modules, err := moduleBlocksFromJSON(raw)
		if err != nil {
			return nil, err
		}
		extract.modules = modules
	}
	return extract, nil
}

func moduleBlocksFromJSON(raw json.RawMessage) ([]moduleBlockExtract, error) {
	var blocks map[string]json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil, fmt.Errorf("decoding module blocks: %w", err)
	}
	modules := make([]moduleBlockExtract, 0, len(blocks))
	for name, body := range blocks {
		source, version, err := moduleSourceVersionFromJSON(body)
		if err != nil {
			return nil, fmt.Errorf("module %q: %w", name, err)
		}
		mod := moduleBlockExtract{
			name: name,
			// JSON configuration has no source positions; callers treat line 1 as the declaration anchor.
			defLine:    1,
			defEndLine: 1,
		}
		if source != "" {
			mod.source = jsonStringToModuleExpr(source)
		}
		if version != "" {
			mod.version = jsonStringToModuleExpr(version)
		}
		modules = append(modules, mod)
	}
	return modules, nil
}

func moduleSourceVersionFromJSON(raw json.RawMessage) (source, version string, err error) {
	var attrs map[string]json.RawMessage
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return "", "", fmt.Errorf("decoding module attributes: %w", err)
	}
	if rawSource, ok := attrs["source"]; ok {
		source, err = decodeJSONString(rawSource)
		if err != nil {
			return "", "", fmt.Errorf("source: %w", err)
		}
	}
	if rawVersion, ok := attrs["version"]; ok {
		version, err = decodeJSONString(rawVersion)
		if err != nil {
			return "", "", fmt.Errorf("version: %w", err)
		}
	}
	return source, version, nil
}

func variableDefaultsFromJSON(raw json.RawMessage) map[string]string {
	var blocks map[string]json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil
	}
	defaults := make(map[string]string, len(blocks))
	for name, body := range blocks {
		var attrs map[string]json.RawMessage
		if err := json.Unmarshal(body, &attrs); err != nil {
			continue
		}
		rawDefault, ok := attrs["default"]
		if !ok {
			continue
		}
		value, err := decodeJSONString(rawDefault)
		if err != nil || value == "" {
			continue
		}
		defaults[name] = value
	}
	return defaults
}

func stringMapFromJSON(raw json.RawMessage) map[string]string {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, rawValue := range values {
		value, err := decodeJSONString(rawValue)
		if err != nil || value == "" {
			continue
		}
		out[key] = value
	}
	return out
}

func decodeJSONString(raw json.RawMessage) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	return value, nil
}

func stringLiteralExpr(value string) hclsyntax.Expression {
	return &hclsyntax.LiteralValueExpr{
		Val:      cty.StringVal(value),
		SrcRange: hcl.Range{Start: hcl.Pos{Line: 1, Column: 1}, End: hcl.Pos{Line: 1, Column: 1}},
	}
}

func jsonStringToModuleExpr(value string) hclsyntax.Expression {
	if !strings.Contains(value, "${") {
		return stringLiteralExpr(value)
	}
	expr, diags := hclsyntax.ParseExpression(
		[]byte(strconv.Quote(value)),
		"main.tf.json",
		hcl.Pos{Line: 1, Column: 1},
	)
	if diags.HasErrors() {
		return stringLiteralExpr(value)
	}
	return expr
}
