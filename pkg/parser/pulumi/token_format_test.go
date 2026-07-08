/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package pulumi_test verifies that every parser emits type tokens in the
// canonical Pulumi format "provider:module:TypeName" that the Rego rules
// expect.  Each test case corresponds to at least one real rule in
// datadog-iac-scanner-default-rules/assets/queries/pulumi/.
package pulumi_test

import (
	"context"
	"testing"

	pulumiGoParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/golang"
	pulumiPyParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/python"
	pulumiTSParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/typescript"
	"github.com/stretchr/testify/require"
)

// typeTokenCase pairs a per-language source snippet with the expected type
// token that the Rego rule checks.
type typeTokenCase struct {
	name          string
	expectedToken string
	pySrc         string
	tsSrc         string
	goSrc         string
}

// The cases below map directly to real Rego rules in the default-rules repo.
var tokenCases = []typeTokenCase{
	{
		name:          "aws:dms:ReplicationInstance",
		expectedToken: "aws:dms:ReplicationInstance",
		pySrc: `import pulumi_aws as aws
instance = aws.dms.ReplicationInstance("r", replication_instance_class="dms.t2.micro")`,
		tsSrc: `import * as aws from "@pulumi/aws";
const instance = new aws.dms.ReplicationInstance("r", { replicationInstanceClass: "dms.t2.micro" });`,
		goSrc: `package main
import (
	dms "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/dms"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)
func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := dms.NewReplicationInstance(ctx, "r", &dms.ReplicationInstanceArgs{
			ReplicationInstanceClass: pulumi.String("dms.t2.micro"),
		})
		return err
	})
}`,
	},
	{
		name:          "aws:ec2:Instance",
		expectedToken: "aws:ec2:Instance",
		pySrc: `import pulumi_aws as aws
inst = aws.ec2.Instance("web", instance_type="t3.micro")`,
		tsSrc: `import * as aws from "@pulumi/aws";
const inst = new aws.ec2.Instance("web", { instanceType: "t3.micro" });`,
		goSrc: `package main
import (
	ec2 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)
func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := ec2.NewInstance(ctx, "web", &ec2.InstanceArgs{
			InstanceType: pulumi.String("t3.micro"),
		})
		return err
	})
}`,
	},
	{
		name:          "aws:rds:Instance",
		expectedToken: "aws:rds:Instance",
		pySrc: `import pulumi_aws as aws
db = aws.rds.Instance("db", instance_class="db.t3.micro")`,
		tsSrc: `import * as aws from "@pulumi/aws";
const db = new aws.rds.Instance("db", { instanceClass: "db.t3.micro" });`,
		goSrc: `package main
import (
	rds "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/rds"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)
func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := rds.NewInstance(ctx, "db", &rds.InstanceArgs{
			InstanceClass: pulumi.String("db.t3.micro"),
		})
		return err
	})
}`,
	},
	{
		name:          "azure-native:cache:Redis",
		expectedToken: "azure-native:cache:Redis",
		pySrc: `import pulumi_azure_native as azure_native
cache = azure_native.cache.Redis("r", resource_group_name="rg")`,
		tsSrc: `import * as azureNative from "@pulumi/azure-native";
const cache = new azureNative.cache.Redis("r", { resourceGroupName: "rg" });`,
		goSrc: `package main
import (
	cache "github.com/pulumi/pulumi-azure-native/sdk/v2/go/azure-native/cache"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)
func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := cache.NewRedis(ctx, "r", &cache.RedisArgs{
			ResourceGroupName: pulumi.String("rg"),
		})
		return err
	})
}`,
	},
	{
		name:          "gcp:storage:Bucket",
		expectedToken: "gcp:storage:Bucket",
		pySrc: `import pulumi_gcp as gcp
bucket = gcp.storage.Bucket("b")`,
		tsSrc: `import * as gcp from "@pulumi/gcp";
const bucket = new gcp.storage.Bucket("b", {});`,
		goSrc: `package main
import (
	storage "github.com/pulumi/pulumi-gcp/sdk/v7/go/gcp/storage"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)
func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := storage.NewBucket(ctx, "b", &storage.BucketArgs{})
		return err
	})
}`,
	},
}

func TestTypeTokenFormat_Python(t *testing.T) {
	p := &pulumiPyParser.Parser{}
	for _, tc := range tokenCases {
		t.Run(tc.name, func(t *testing.T) {
			_, docs, _, _, err := p.Parse(context.Background(), []byte(tc.pySrc), "main.py", false, 0)
			require.NoError(t, err)
			require.NotEmpty(t, docs, "expected at least one document for %s", tc.name)
			assertTypeToken(t, docs[0], tc.expectedToken)
		})
	}
}

func TestTypeTokenFormat_TypeScript(t *testing.T) {
	p := &pulumiTSParser.Parser{}
	for _, tc := range tokenCases {
		t.Run(tc.name, func(t *testing.T) {
			_, docs, _, _, err := p.Parse(context.Background(), []byte(tc.tsSrc), "index.ts", false, 0)
			require.NoError(t, err)
			require.NotEmpty(t, docs, "expected at least one document for %s", tc.name)
			assertTypeToken(t, docs[0], tc.expectedToken)
		})
	}
}

func TestTypeTokenFormat_Go(t *testing.T) {
	p := &pulumiGoParser.Parser{}
	for _, tc := range tokenCases {
		t.Run(tc.name, func(t *testing.T) {
			_, docs, _, _, err := p.Parse(context.Background(), []byte(tc.goSrc), "main.go", false, 0)
			require.NoError(t, err)
			require.NotEmpty(t, docs, "expected at least one document for %s", tc.name)
			assertTypeToken(t, docs[0], tc.expectedToken)
		})
	}
}

// assertTypeToken checks that at least one resource in the document has the
// expected type token.
func assertTypeToken(t *testing.T, doc map[string]interface{}, want string) {
	t.Helper()
	resources, ok := doc["resources"].(map[string]interface{})
	require.True(t, ok, "document must have 'resources' map")

	for k, v := range resources {
		if k == "_dd_lines" {
			continue
		}
		res, ok := v.(map[string]interface{})
		require.True(t, ok)
		got, _ := res["type"].(string)
		require.Equal(t, want, got,
			"type token mismatch: Rego rule expects %q but parser emitted %q", want, got)
		return
	}
	t.Fatal("no resource entries found in document")
}
