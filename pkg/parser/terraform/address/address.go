/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
// Package address formats Terraform instance identities independently of the
// base-named document keys used by rules and source lookup.
package address

import (
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/zclconf/go-cty/cty"
)

const moduleKind = "module"

// InstanceSuffix formats a known count index or for_each key as HCL syntax.
func InstanceSuffix(key cty.Value) string {
	key, _ = key.Unmark()
	suffix, _ := ctyutil.FormatIndexKey(key)
	return suffix
}

// Resource joins a module instance address and a resource's instance name.
// Evaluator names use Go quoted keys internally; convert those to HCL strings
// here, including escaping template openers and control characters.
func Resource(module, kind, typ, name string) string {
	if i := strings.IndexByte(name, '['); i >= 0 && strings.HasSuffix(name, "]") {
		if key, err := strconv.Unquote(name[i+1 : len(name)-1]); err == nil {
			name = name[:i] + InstanceSuffix(cty.StringVal(key))
		}
	}
	parts := []string{}
	if module != "" {
		parts = append(parts, module)
	}
	if kind == "data" || kind == moduleKind {
		parts = append(parts, kind)
	}
	if kind != moduleKind {
		parts = append(parts, typ)
	}
	return strings.Join(append(parts, name), ".")
}
