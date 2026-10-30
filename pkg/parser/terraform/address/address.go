/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package address formats Terraform block and instance addresses
// (K9CODESEC-7158), independently of the base-named document keys used by
// rules and source lookup.
package address

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/zclconf/go-cty/cty"
)

// Block is the engine's block identity key: the same struct FileMetadata's
// TerraformScope maps are keyed by, aliased so a scope lookup never converts.
type Block = model.TerraformBlock

// Block kinds. The first three label a typed, named block; the rest are
// Terraform's own address namespaces.
const (
	KindResource  = "resource"
	KindData      = "data"
	KindEphemeral = "ephemeral"
	KindModule    = "module"
	KindVariable  = "variable"
	KindLocal     = "local"
	KindOutput    = "output"
	KindProvider  = "provider"
	KindCheck     = "check"
	KindTerraform = "terraform"
)

// Addr returns the block's as-written Terraform address, without a module
// prefix and without an instance index: aws_s3_bucket.example, var.size,
// module.network, provider.aws.west, local.name, terraform.
func Addr(b Block) string {
	switch b.Kind {
	case KindResource:
		return b.Type + "." + b.Name
	case KindEphemeral:
		return KindEphemeral + "." + b.Type + "." + b.Name
	case KindData:
		return KindData + "." + b.Type + "." + b.Name
	case KindModule:
		return KindModule + "." + b.Name
	case KindVariable:
		return "var." + b.Name
	case KindLocal:
		return "local." + b.Name
	case KindOutput:
		return KindOutput + "." + b.Name
	case KindProvider:
		addr := KindProvider + "." + b.Type
		if b.Name != "" {
			addr += "." + b.Name
		}
		return addr
	case KindCheck:
		return KindCheck + "." + b.Name
	case KindTerraform:
		return KindTerraform
	default:
		// Unlabeled blocks (terraform, moved, import, removed) are addressed
		// by type; a repeated one carries its list index.
		if b.Name != "" {
			return b.Kind + "." + b.Name
		}
		return b.Kind
	}
}

// instanceKinded reports whether count and for_each expand the block into
// instances.
func instanceKinded(b Block) bool {
	return b.Kind == KindResource || b.Kind == KindData || b.Kind == KindEphemeral
}

// Instance joins a module instance address and a block into the full Terraform
// address of one instance, e.g. module.a["x"].aws_s3_bucket.example[0].
//
// suffix is the count index or for_each key of the instance, already in HCL
// syntax (see InstanceSuffix — the one escaping path, applied when the
// evaluator names the instance). It is appended verbatim: re-escaping an
// already-escaped key would double every $ and %. Only instance-kinded blocks
// take a suffix; a module call block configures every instance at once and
// the label-only kinds do not expand, so their suffix is ignored.
func Instance(module string, b Block, suffix string) string {
	addr := Addr(b)
	if suffix != "" && instanceKinded(b) {
		addr += suffix
	}
	if module != "" {
		return module + "." + addr
	}
	return addr
}

// InstanceSuffix formats a known count index or for_each key as HCL syntax,
// e.g. "[0]" or `["key"]`. It returns "" when key cannot be formatted.
func InstanceSuffix(key cty.Value) string {
	key, _ = key.Unmark()
	suffix, _ := ctyutil.FormatIndexKey(key)
	return suffix
}
