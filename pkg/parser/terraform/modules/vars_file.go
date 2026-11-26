/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfmodules

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"

	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
)

// ParseVarsFile returns the assignments of a variable definitions file, in
// native or JSON syntax, or nil when the file is not valid.
func ParseVarsFile(src []byte, path string) hcl.Attributes {
	var file *hcl.File
	var diags hcl.Diagnostics
	if tfpath.IsTFVarsJSON(path) {
		file, diags = hcljson.Parse(src, path)
	} else {
		file, diags = hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	}
	if diags.HasErrors() || file == nil {
		return nil
	}
	attrs, _ := file.Body.JustAttributes()
	return attrs
}
