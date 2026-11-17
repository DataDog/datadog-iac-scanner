/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package address formats Terraform block and instance addresses.
package address

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

type Block = model.TerraformBlock

const (
	KindResource    = "resource"
	KindData        = "data"
	KindEphemeral   = "ephemeral"
	KindModule      = "module"
	KindVariable    = "variable"
	KindLocal       = "local"
	KindOutput      = "output"
	KindProvider    = "provider"
	KindCheck       = "check"
	KindTerraform   = "terraform"
	KindMoved       = "moved"
	KindImport      = "import"
	KindRemoved     = "removed"
	DataPrefix      = "data."
	EphemeralPrefix = "ephemeral."
)

// Addr returns the block's Terraform address without module or instance keys.
func Addr(b Block) string {
	switch b.Kind {
	case KindResource:
		return b.Type + "." + b.Name
	case KindData, KindEphemeral:
		return b.Kind + "." + b.Type + "." + b.Name
	case KindModule, KindOutput, KindCheck:
		return b.Kind + "." + b.Name
	case KindVariable:
		return "var." + b.Name
	case KindLocal:
		return "local." + b.Name
	case KindProvider:
		if b.Name == "" {
			return "provider." + b.Type
		}
		return "provider." + b.Type + "." + b.Name
	default:
		if b.Name != "" {
			return b.Kind + "." + b.Name
		}
		return b.Kind
	}
}

// Instance returns the address of a block instance, optionally under a module
// instance address. suffix is already formatted HCL syntax (for example [0]).
func Instance(module string, b Block, suffix string) string {
	addr := Addr(b)
	if suffix != "" && (b.Kind == KindResource || b.Kind == KindData || b.Kind == KindEphemeral) {
		addr += suffix
	}
	if module != "" {
		return module + "." + addr
	}
	return addr
}

// InstanceSuffix formats a count index or for_each key using HCL syntax.
func InstanceSuffix(key cty.Value) string {
	suffix, _ := FormatIndexKey(key)
	return suffix
}

// FormatIndexKey renders a materialized index using Terraform-compatible HCL
// string escaping. It is separate from the legacy cty helper because existing
// scanner identities rely on that helper's historical output.
func FormatIndexKey(key cty.Value) (string, bool) {
	key, _ = key.Unmark()
	if !ctyutil.Materialized(key) {
		return "", false
	}
	if key.Type() != cty.String {
		return ctyutil.FormatIndexKey(key)
	}
	s := key.AsString()
	if isPlainQuotedLiteral(s) {
		return `["` + s + `"]`, true
	}
	return "[" + string(hclwrite.TokensForValue(key).Bytes()) + "]", true
}

func isPlainQuotedLiteral(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
		if (c == '$' || c == '%') && i+1 < len(s) && s[i+1] == '{' {
			return false
		}
	}
	return true
}
