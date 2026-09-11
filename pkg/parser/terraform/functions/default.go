/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"encoding/base64"
	"maps"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2/ext/tryfunc"
	ctyyaml "github.com/zclconf/go-cty-yaml"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// Base64EncodeFunc - https://www.terraform.io/docs/language/functions/base64encode.html
var Base64EncodeFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name:             "val",
			Type:             cty.DynamicPseudoType,
			AllowDynamicType: true,
			AllowNull:        true,
		},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		val := args[0]
		if !val.IsWhollyKnown() {
			// We can't serialize unknowns, so if the value is unknown or
			// contains any _nested_ unknowns then our result must be
			// unknown.
			return cty.UnknownVal(retType), nil
		}

		if val.IsNull() {
			return cty.StringVal("null"), nil
		}

		encoded := base64.StdEncoding.EncodeToString([]byte(val.AsString()))

		return cty.StringVal(encoded), nil
	},
})

// TerraformFuncs contains all functions, overriding any conflicting built-ins
// it should create a file in this package and add/change this function key here
var TerraformFuncs = func() map[string]function.Function {
	funcs := map[string]function.Function{
		"abs":              stdlib.AbsoluteFunc,
		"abspath":          AbsPathFunc,
		"alltrue":          AllTrueFunc,
		"anytrue":          AnyTrueFunc,
		"base64decode":     Base64DecodeFunc,
		"base64encode":     Base64EncodeFunc,
		"base64gzip":       Base64GzipFunc,
		"base64sha256":     Base64Sha256Func,
		"base64sha512":     Base64Sha512Func,
		"basename":         BasenameFunc,
		"can":              tryfunc.CanFunc,
		"cidrhost":         CidrHostFunc,
		"cidrnetmask":      CidrNetmaskFunc,
		"cidrsubnet":       CidrSubnetFunc,
		"cidrsubnets":      CidrSubnetsFunc,
		"ceil":             stdlib.CeilFunc,
		"chomp":            stdlib.ChompFunc,
		"coalesce":         CoalesceFunc,
		"coalescelist":     stdlib.CoalesceListFunc,
		"compact":          stdlib.CompactFunc,
		"concat":           stdlib.ConcatFunc,
		"contains":         stdlib.ContainsFunc,
		"csvdecode":        stdlib.CSVDecodeFunc,
		"dirname":          DirnameFunc,
		"distinct":         stdlib.DistinctFunc,
		"endswith":         EndsWithFunc,
		"element":          stdlib.ElementFunc,
		"chunklist":        stdlib.ChunklistFunc,
		"flatten":          stdlib.FlattenFunc,
		"floor":            stdlib.FloorFunc,
		"format":           stdlib.FormatFunc,
		"formatdate":       stdlib.FormatDateFunc,
		"formatlist":       stdlib.FormatListFunc,
		"indent":           stdlib.IndentFunc,
		"index":            IndexFunc,
		"join":             stdlib.JoinFunc,
		"jsondecode":       stdlib.JSONDecodeFunc,
		"jsonencode":       stdlib.JSONEncodeFunc,
		"keys":             stdlib.KeysFunc,
		"length":           LengthFunc,
		"log":              stdlib.LogFunc,
		"lookup":           LookupFunc,
		"lower":            stdlib.LowerFunc,
		"matchkeys":        MatchkeysFunc,
		"max":              stdlib.MaxFunc,
		"md5":              Md5Func,
		"merge":            stdlib.MergeFunc,
		"min":              stdlib.MinFunc,
		"one":              OneFunc,
		"parseint":         stdlib.ParseIntFunc,
		"pathexpand":       PathExpandFunc,
		"pow":              stdlib.PowFunc,
		"range":            stdlib.RangeFunc,
		"regex":            stdlib.RegexFunc,
		"regexall":         stdlib.RegexAllFunc,
		"replace":          ReplaceFunc,
		"reverse":          stdlib.ReverseListFunc,
		"setintersection":  stdlib.SetIntersectionFunc,
		"setproduct":       stdlib.SetProductFunc,
		"setsubtract":      stdlib.SetSubtractFunc,
		"setunion":         stdlib.SetUnionFunc,
		"sha1":             Sha1Func,
		"sha256":           Sha256Func,
		"sha512":           Sha512Func,
		"signum":           stdlib.SignumFunc,
		"slice":            stdlib.SliceFunc,
		"sort":             stdlib.SortFunc,
		"split":            stdlib.SplitFunc,
		"startswith":       StartsWithFunc,
		"strcontains":      StrContainsFunc,
		"strrev":           stdlib.ReverseFunc,
		"substr":           stdlib.SubstrFunc,
		"sum":              SumFunc,
		"textdecodebase64": TextDecodeBase64Func,
		"textencodebase64": TextEncodeBase64Func,
		"timeadd":          stdlib.TimeAddFunc,
		"timecmp":          TimeCmpFunc,
		"title":            stdlib.TitleFunc,
		"tobool":           stdlib.MakeToFunc(cty.Bool),
		"tolist":           ToListFunc,
		"tomap":            ToMapFunc,
		"tonumber":         stdlib.MakeToFunc(cty.Number),
		"toset":            ToSetFunc,
		"tostring":         stdlib.MakeToFunc(cty.String),
		"transpose":        TransposeFunc,
		"trim":             stdlib.TrimFunc,
		"trimprefix":       stdlib.TrimPrefixFunc,
		"trimspace":        stdlib.TrimSpaceFunc,
		"trimsuffix":       stdlib.TrimSuffixFunc,
		"try":              tryfunc.TryFunc,
		"upper":            stdlib.UpperFunc,
		"urlencode":        URLEncodeFunc,
		"uuidv5":           UUIDV5Func,
		"values":           stdlib.ValuesFunc,
		"yamldecode":       ctyyaml.YAMLDecodeFunc,
		"yamlencode":       ctyyaml.YAMLEncodeFunc,
		"zipmap":           stdlib.ZipmapFunc,
	}
	funcs["templatestring"] = makeTemplateStringFunc(func() map[string]function.Function {
		return funcs
	})
	return funcs
}()

// EvalFuncs returns TerraformFuncs plus filesystem functions rooted at baseDir.
// When fsys is nil and baseDir is empty the static map is returned unchanged.
func EvalFuncs(baseDir string, fsys vfs.FS) map[string]function.Function {
	if fsys == nil && baseDir == "" {
		return TerraformFuncs
	}
	if fsys == nil {
		fsys = vfs.DiskFS{}
	}
	if baseDir == "" {
		baseDir = "."
	}
	funcs := maps.Clone(TerraformFuncs)
	funcsCb := func() map[string]function.Function { return funcs }
	funcs["file"] = makeFileFunc(baseDir, fsys, false)
	funcs["fileexists"] = makeFileExistsFunc(baseDir, fsys)
	funcs["fileset"] = makeFileSetFunc(baseDir, fsys)
	funcs["filebase64"] = makeFileFunc(baseDir, fsys, true)
	for name, fn := range fileHashFuncs(baseDir, fsys) {
		funcs[name] = fn
	}
	funcs["abspath"] = MakeAbsPathFunc(baseDir)
	funcs["templatefile"] = makeTemplateFileFunc(baseDir, fsys, funcsCb)
	funcs["templatestring"] = makeTemplateStringFunc(funcsCb)
	return funcs
}
