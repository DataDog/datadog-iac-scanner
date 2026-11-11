/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestSplitTerraformRules(t *testing.T) {
	const pkg = "package datadog\n"
	queries := []model.QueryMetadata{
		{Query: "finding", Content: pkg + "import data.generic.common as c\nDatadogPolicy contains c.finding(b, [], {}) if { some b in x }"},
		{Query: "blocks", Content: pkg + "import data.generic.terraform as t\nDatadogPolicy contains r if { some b in t.blocks(\"aws_s3_bucket\") }"},
		{Query: "qualified", Content: pkg + "DatadogPolicy contains data.generic.common.finding(b, [], {}) if { some b in x }"},
		{Query: "document", Content: pkg + "DatadogPolicy contains r if { input.document[i].resource }"},
		{Query: "comment", Content: pkg + "# common.finding( is only mentioned here\nDatadogPolicy contains r if { input.document[i].resource }"},
		{Query: "other_package", Content: pkg + "import data.generic.terraform as t\nDatadogPolicy contains r if { t.resource_type(\"x\") }"},
		{
			Query:    "forced",
			Content:  pkg + "import data.generic.common as common\nDatadogPolicy contains common.finding(b, [], {}) if { some b in x }",
			Metadata: map[string]interface{}{"contract": "legacy"},
		},
	}
	contract, legacy := splitTerraformRules(queries)
	names := func(qs []model.QueryMetadata) []string {
		out := make([]string, len(qs))
		for i := range qs {
			out[i] = qs[i].Query
		}
		return out
	}
	require.Equal(t, []string{"finding", "blocks", "qualified"}, names(contract))
	require.Equal(t, []string{"document", "comment", "other_package", "forced"}, names(legacy))
}
