/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package pulumi_test contains integration tests that verify the full
// parser → document → OPA rule evaluation pipeline for Pulumi source files.
//
// Each test parses a source file and directly evaluates it with a self-contained
// Rego rule (no network, no full scan pipeline) to assert that a violation is
// produced when expected and suppressed when the resource is correctly configured.
package pulumi_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"

	pulumiGoParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/golang"
	pulumiPyParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/python"
	pulumiTSParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/typescript"
)

// dmsPubliclyAccessibleRule is a self-contained Rego rule that mirrors the
// real "amazon_dms_replication_instance_is_publicly_accessible" rule.
// It has no library imports so it can be evaluated without any backend.
const dmsPubliclyAccessibleRule = `
package datadog

DatadogPolicy contains result if {
	some i, name
	resource := input.document[i].resources[name]
	resource.type == "aws:dms:ReplicationInstance"
	resource.properties.publiclyAccessible == true
	result := {
		"documentId": input.document[i].id,
		"resourceType": resource.type,
		"resourceName": name,
		"searchKey": sprintf("resources[%s].properties.publiclyAccessible", [name]),
	}
}
`

// ec2MonitoringRule mirrors ec2_instance_monitoring_disabled.
const ec2MonitoringRule = `
package datadog

DatadogPolicy contains result if {
	some i, name
	resource := input.document[i].resources[name]
	resource.type == "aws:ec2:Instance"
	resource.properties.monitoring == false
	result := {
		"documentId": input.document[i].id,
		"resourceType": resource.type,
		"resourceName": name,
		"searchKey": sprintf("resources[%s].properties.monitoring", [name]),
	}
}
`

// ruleEvalCase describes a single parser+rule integration test.
type ruleEvalCase struct {
	name      string
	rule      string
	filename  string
	src       []byte
	wantFire  bool // true → expect at least one violation, false → expect none
}

var ruleEvalCases = []ruleEvalCase{
	// ── DMS publiclyAccessible ────────────────────────────────────────────────
	{
		name:     "python/dms-publicly-accessible-positive",
		rule:     dmsPubliclyAccessibleRule,
		filename: "main.py",
		src: []byte(`import pulumi_aws as aws
instance = aws.dms.ReplicationInstance("r",
    replication_instance_class="dms.t2.micro",
    publicly_accessible=True,
)
`),
		wantFire: true,
	},
	{
		name:     "python/dms-publicly-accessible-negative",
		rule:     dmsPubliclyAccessibleRule,
		filename: "main.py",
		src: []byte(`import pulumi_aws as aws
instance = aws.dms.ReplicationInstance("r",
    replication_instance_class="dms.t2.micro",
    publicly_accessible=False,
)
`),
		wantFire: false,
	},
	{
		name:     "typescript/dms-publicly-accessible-positive",
		rule:     dmsPubliclyAccessibleRule,
		filename: "index.ts",
		src: []byte(`import * as aws from "@pulumi/aws";
const instance = new aws.dms.ReplicationInstance("r", {
    replicationInstanceClass: "dms.t2.micro",
    publiclyAccessible: true,
});
`),
		wantFire: true,
	},
	{
		name:     "typescript/dms-publicly-accessible-negative",
		rule:     dmsPubliclyAccessibleRule,
		filename: "index.ts",
		src: []byte(`import * as aws from "@pulumi/aws";
const instance = new aws.dms.ReplicationInstance("r", {
    replicationInstanceClass: "dms.t2.micro",
    publiclyAccessible: false,
});
`),
		wantFire: false,
	},
	{
		name:     "go/dms-publicly-accessible-positive",
		rule:     dmsPubliclyAccessibleRule,
		filename: "main.go",
		src: []byte(`package main
import (
	dms "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/dms"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)
func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := dms.NewReplicationInstance(ctx, "r", &dms.ReplicationInstanceArgs{
			ReplicationInstanceClass: pulumi.String("dms.t2.micro"),
			PubliclyAccessible:       pulumi.Bool(true),
		})
		return err
	})
}
`),
		wantFire: true,
	},
	{
		name:     "go/dms-publicly-accessible-negative",
		rule:     dmsPubliclyAccessibleRule,
		filename: "main.go",
		src: []byte(`package main
import (
	dms "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/dms"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)
func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := dms.NewReplicationInstance(ctx, "r", &dms.ReplicationInstanceArgs{
			ReplicationInstanceClass: pulumi.String("dms.t2.micro"),
			PubliclyAccessible:       pulumi.Bool(false),
		})
		return err
	})
}
`),
		wantFire: false,
	},
	// ── EC2 monitoring (single-word property — no case conversion needed) ──────
	{
		name:     "python/ec2-monitoring-disabled-positive",
		rule:     ec2MonitoringRule,
		filename: "main.py",
		src: []byte(`import pulumi_aws as aws
inst = aws.ec2.Instance("web", instance_type="t3.micro", monitoring=False)
`),
		wantFire: true,
	},
	{
		name:     "typescript/ec2-monitoring-disabled-positive",
		rule:     ec2MonitoringRule,
		filename: "index.ts",
		src: []byte(`import * as aws from "@pulumi/aws";
const inst = new aws.ec2.Instance("web", { instanceType: "t3.micro", monitoring: false });
`),
		wantFire: true,
	},
	{
		name:     "go/ec2-monitoring-disabled-positive",
		rule:     ec2MonitoringRule,
		filename: "main.go",
		src: []byte(`package main
import (
	ec2 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)
func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := ec2.NewInstance(ctx, "web", &ec2.InstanceArgs{
			InstanceType: pulumi.String("t3.micro"),
			Monitoring:   pulumi.Bool(false),
		})
		return err
	})
}
`),
		wantFire: true,
	},
}

func TestRuleEval(t *testing.T) {
	for _, tc := range ruleEvalCases {
		t.Run(tc.name, func(t *testing.T) {
			docs := parseSource(t, tc.filename, tc.src)
			violations := evalRule(t, tc.rule, docs)
			if tc.wantFire {
				require.NotEmpty(t, violations,
					"expected rule to fire but got no violations\ndocument: %s",
					mustJSON(docs))
			} else {
				require.Empty(t, violations,
					"expected no violations but got %d\ndocument: %s",
					len(violations), mustJSON(docs))
			}
		})
	}
}

// parseSource dispatches to the right parser based on the filename extension.
func parseSource(t *testing.T, filename string, src []byte) []map[string]interface{} {
	t.Helper()
	ctx := context.Background()

	var rawDocs interface{}
	switch {
	case len(filename) > 3 && filename[len(filename)-3:] == ".py":
		_, docs, _, _, err := (&pulumiPyParser.Parser{}).Parse(ctx, src, filename, false, 0)
		require.NoError(t, err)
		rawDocs = docs
	case len(filename) > 3 && filename[len(filename)-3:] == ".ts":
		_, docs, _, _, err := (&pulumiTSParser.Parser{}).Parse(ctx, src, filename, false, 0)
		require.NoError(t, err)
		rawDocs = docs
	default:
		_, docs, _, _, err := (&pulumiGoParser.Parser{}).Parse(ctx, src, filename, false, 0)
		require.NoError(t, err)
		rawDocs = docs
	}

	// Round-trip through JSON to get plain map[string]interface{} — the same
	// representation OPA sees when the engine feeds documents as input.
	b, err := json.Marshal(rawDocs)
	require.NoError(t, err)
	var out []map[string]interface{}
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

// evalRule evaluates the Rego rule against the parsed documents and returns
// the matched result set.
func evalRule(t *testing.T, ruleText string, docs []map[string]interface{}) []interface{} {
	t.Helper()
	ctx := context.Background()

	// Wrap docs as input.document array and add synthetic id fields.
	inputDocs := make([]map[string]interface{}, len(docs))
	for i, d := range docs {
		d["id"] = "test-doc"
		inputDocs[i] = d
	}
	input := map[string]interface{}{"document": inputDocs}

	q, err := rego.New(
		rego.Query(`result = data.datadog.DatadogPolicy`),
		rego.Module("rule.rego", ruleText),
		rego.Input(input),
	).PrepareForEval(ctx)
	require.NoError(t, err)

	rs, err := q.Eval(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, rs)

	set, _ := rs[0].Bindings["result"].([]interface{})
	return set
}

func mustJSON(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
