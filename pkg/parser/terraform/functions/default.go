/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"encoding/base64"

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
var TerraformFuncs = map[string]function.Function{
	"abs":             stdlib.AbsoluteFunc,
	"alltrue":         AllTrueFunc,
	"anytrue":         AnyTrueFunc,
	"base64decode":    Base64DecodeFunc,
	"base64encode":    Base64EncodeFunc,
	"can":             tryfunc.CanFunc,
	"cidrhost":        CidrHostFunc,
	"cidrnetmask":     CidrNetmaskFunc,
	"cidrsubnet":      CidrSubnetFunc,
	"cidrsubnets":     CidrSubnetsFunc,
	"ceil":            stdlib.CeilFunc,
	"chomp":           stdlib.ChompFunc,
	"coalesce":        CoalesceFunc,
	"coalescelist":    stdlib.CoalesceListFunc,
	"compact":         stdlib.CompactFunc,
	"concat":          stdlib.ConcatFunc,
	"contains":        stdlib.ContainsFunc,
	"csvdecode":       stdlib.CSVDecodeFunc,
	"distinct":        stdlib.DistinctFunc,
	"endswith":        EndsWithFunc,
	"element":         stdlib.ElementFunc,
	"chunklist":       stdlib.ChunklistFunc,
	"flatten":         stdlib.FlattenFunc,
	"floor":           stdlib.FloorFunc,
	"format":          stdlib.FormatFunc,
	"formatdate":      stdlib.FormatDateFunc,
	"formatlist":      stdlib.FormatListFunc,
	"indent":          stdlib.IndentFunc,
	"index":           IndexFunc,
	"join":            stdlib.JoinFunc,
	"jsondecode":      stdlib.JSONDecodeFunc,
	"jsonencode":      stdlib.JSONEncodeFunc,
	"keys":            stdlib.KeysFunc,
	"length":          LengthFunc,
	"log":             stdlib.LogFunc,
	"lookup":          LookupFunc,
	"lower":           stdlib.LowerFunc,
	"matchkeys":       MatchkeysFunc,
	"max":             stdlib.MaxFunc,
	"md5":             Md5Func,
	"merge":           stdlib.MergeFunc,
	"min":             stdlib.MinFunc,
	"one":             OneFunc,
	"parseint":        stdlib.ParseIntFunc,
	"pow":             stdlib.PowFunc,
	"range":           stdlib.RangeFunc,
	"regex":           stdlib.RegexFunc,
	"regexall":        stdlib.RegexAllFunc,
	"replace":         ReplaceFunc,
	"reverse":         stdlib.ReverseListFunc,
	"setintersection": stdlib.SetIntersectionFunc,
	"setproduct":      stdlib.SetProductFunc,
	"setsubtract":     stdlib.SetSubtractFunc,
	"setunion":        stdlib.SetUnionFunc,
	"sha1":            Sha1Func,
	"sha256":          Sha256Func,
	"sha512":          Sha512Func,
	"signum":          stdlib.SignumFunc,
	"slice":           stdlib.SliceFunc,
	"sort":            stdlib.SortFunc,
	"split":           stdlib.SplitFunc,
	"startswith":      StartsWithFunc,
	"strcontains":     StrContainsFunc,
	"strrev":          stdlib.ReverseFunc,
	"substr":          stdlib.SubstrFunc,
	"sum":             SumFunc,
	"timeadd":         stdlib.TimeAddFunc,
	"title":           stdlib.TitleFunc,
	"tobool":          stdlib.MakeToFunc(cty.Bool),
	"tolist":          ToListFunc,
	"tomap":           ToMapFunc,
	"tonumber":        stdlib.MakeToFunc(cty.Number),
	"toset":           ToSetFunc,
	"tostring":        stdlib.MakeToFunc(cty.String),
	"transpose":       TransposeFunc,
	"trim":            stdlib.TrimFunc,
	"trimprefix":      stdlib.TrimPrefixFunc,
	"trimspace":       stdlib.TrimSpaceFunc,
	"trimsuffix":      stdlib.TrimSuffixFunc,
	"try":             tryfunc.TryFunc,
	"upper":           stdlib.UpperFunc,
	"urlencode":       URLEncodeFunc,
	"values":          stdlib.ValuesFunc,
	"yamldecode":      ctyyaml.YAMLDecodeFunc,
	"yamlencode":      ctyyaml.YAMLEncodeFunc,
	"zipmap":          stdlib.ZipmapFunc,
}
