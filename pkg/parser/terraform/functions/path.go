/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

var BasenameFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "path", Type: cty.String}},
	Type:   function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return cty.StringVal(filepath.Base(args[0].AsString())), nil
	},
})

var DirnameFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "path", Type: cty.String}},
	Type:   function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return cty.StringVal(filepath.Dir(args[0].AsString())), nil
	},
})

var AbsPathFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "path", Type: cty.String}},
	Type:   function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		abs, err := filepath.Abs(args[0].AsString())
		if err != nil {
			return cty.NilVal, err
		}
		return cty.StringVal(filepath.ToSlash(abs)), nil
	},
})

func MakeAbsPathFunc(baseDir string) function.Function {
	root := filepath.Clean(baseDir)
	if root == "" {
		return AbsPathFunc
	}
	return function.New(&function.Spec{
		Params: []function.Parameter{{Name: "path", Type: cty.String}},
		Type:   function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			p := args[0].AsString()
			if !filepath.IsAbs(p) {
				p = filepath.Join(root, p)
			}
			return cty.StringVal(filepath.ToSlash(filepath.Clean(p))), nil
		},
	})
}

var PathExpandFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "path", Type: cty.String}},
	Type:   function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		p := args[0].AsString()
		if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
			home, err := os.UserHomeDir()
			if err != nil {
				return cty.NilVal, err
			}
			if p == "~" {
				return cty.StringVal(home), nil
			}
			return cty.StringVal(filepath.Join(home, p[2:])), nil
		}
		return cty.StringVal(p), nil
	},
})
