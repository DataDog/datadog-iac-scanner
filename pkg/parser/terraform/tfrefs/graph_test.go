/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfrefs

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
)

func TestDataCycles(t *testing.T) {
	parse := func(src string) []hcl.Traversal {
		expr, diags := hclsyntax.ParseExpression([]byte(src), "main.tf", hcl.InitialPos)
		require.False(t, diags.HasErrors())
		return expr.Variables()
	}
	reads := map[string][]hcl.Traversal{
		DataKey("t", "self"):     parse(`data.t.self.json`),
		DataKey("t", "indexed"):  parse(`data.t["indexed"].json`),
		DataKey("t", "bracket"):  parse(`data["t"]["bracket"].json`),
		DataKey("t", "viaA"):     parse(`local.a`),
		DataKey("t", "chain"):    parse(`data.t.self.json`),
		DataKey("t", "plain"):    parse(`local.c`),
		DataKey("t", "runtime"):  parse(`data.t[var.name].json`),
		DataKey("t", "lookup"):   parse(`lookup(data.t, "lookup").json`),
		DataKey("t", "values"):   parse(`values(data.t)[0].json`),
		DataKey("t", "splat"):    parse(`data.t.*.json`),
		DataKey("t", "number"):   parse(`data.t[0].json`),
		DataKey("t", "dotted"):   parse(`data.t["a.b"].json`),
		DataKey("t", "viaLocal"): parse(`lookup(local, "alias")`),
		DataKey("t", "viaIndex"): parse(`local[var.k]`),
		DataKey("u", "other"):    parse(`data.t[var.name].json`),
		DataKey("u", "safe"):     parse(`local.c`),
	}
	locals := map[string][]hcl.Traversal{
		"a":     parse(`[local.b]`),
		"b":     parse(`data.t["viaA"].json`),
		"c":     parse(`var.x`),
		"alias": parse(`data.t.viaLocal.json`),
		"idx":   parse(`data.t.viaIndex.json`),
	}
	require.Equal(t, map[string]bool{
		DataKey("t", "self"):     true,
		DataKey("t", "indexed"):  true,
		DataKey("t", "bracket"):  true,
		DataKey("t", "viaA"):     true,
		DataKey("t", "runtime"):  true,
		DataKey("t", "lookup"):   true,
		DataKey("t", "values"):   true,
		DataKey("t", "splat"):    true,
		DataKey("t", "number"):   true,
		DataKey("t", "dotted"):   true,
		DataKey("t", "viaLocal"): true,
		DataKey("t", "viaIndex"): true,
	}, DataCycles(reads, locals))
}

func TestDataCycles_WholeDataReferenceReachesEveryBlock(t *testing.T) {
	parse := func(src string) []hcl.Traversal {
		expr, diags := hclsyntax.ParseExpression([]byte(src), "main.tf", hcl.InitialPos)
		require.False(t, diags.HasErrors())
		return expr.Variables()
	}
	reads := map[string][]hcl.Traversal{
		DataKey("t", "bare"):    parse(`data`),
		DataKey("t", "dynType"): parse(`data[var.kind].name`),
		DataKey("u", "sibling"): parse(`var.x`),
	}
	require.Equal(t, map[string]bool{
		DataKey("t", "bare"):    true,
		DataKey("t", "dynType"): true,
	}, DataCycles(reads, nil))
}
