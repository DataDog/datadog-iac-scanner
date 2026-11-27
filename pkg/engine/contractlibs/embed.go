/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package contractlibs embeds the built-in Contract v2 Rego libraries
// (data.datadog.output, data.datadog.iac, and data.datadog.terraform).
package contractlibs

import (
	"embed"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
)

//go:embed *.rego
var libFS embed.FS

type libSpec struct {
	name string
	file string
}

var libs = []libSpec{
	{name: "datadog_output.rego", file: "output.rego"},
	{name: "datadog_iac.rego", file: "iac.rego"},
	{name: "datadog_terraform.rego", file: "terraform.rego"},
}

var parsedLibs = sync.OnceValues(func() (map[string]*ast.Module, error) {
	out := make(map[string]*ast.Module, len(libs))
	for _, spec := range libs {
		raw, err := libFS.ReadFile(spec.file)
		if err != nil {
			return nil, fmt.Errorf("reading embedded library %s: %w", spec.file, err)
		}
		mod, err := ast.ParseModuleWithOpts(spec.name, string(raw), ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return nil, fmt.Errorf("parsing embedded library %s: %w", spec.file, err)
		}
		out[spec.name] = mod
	}
	return out, nil
})

// Modules returns fresh copies of the parsed Contract v2 libraries so callers
// may safely compile them without mutating shared AST state.
func Modules() (map[string]*ast.Module, error) {
	base, err := parsedLibs()
	if err != nil {
		return nil, err
	}
	copies := make(map[string]*ast.Module, len(base))
	for name, mod := range base {
		copies[name] = mod.Copy()
	}
	return copies, nil
}

// Sources returns fresh copies of the embedded source text, keyed by the same
// module names as Modules, for standalone authoring and lint tools.
func Sources() (map[string][]byte, error) {
	sources := make(map[string][]byte, len(libs))
	for _, spec := range libs {
		raw, err := libFS.ReadFile(spec.file)
		if err != nil {
			return nil, fmt.Errorf("reading embedded library %s: %w", spec.file, err)
		}
		sources[spec.name] = raw
	}
	return sources, nil
}
