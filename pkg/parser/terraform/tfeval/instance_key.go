/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"github.com/zclconf/go-cty/cty"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
)

type KeyKind uint8

const (
	NoKey KeyKind = iota
	IntKey
	StringKey
)

// InstanceKey is the count index or for_each key of one resource instance.
type InstanceKey struct {
	Kind KeyKind
	Int  int
	Str  string
}

// String renders the key as Terraform writes it in an address: "", "[3]" or ["k"] with HCL string escaping.
func (k InstanceKey) String() string {
	switch k.Kind {
	case IntKey:
		return address.InstanceSuffix(cty.NumberIntVal(int64(k.Int)))
	case StringKey:
		return address.InstanceSuffix(cty.StringVal(k.Str))
	default:
		return ""
	}
}
