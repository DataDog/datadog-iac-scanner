/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package golang

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestParser_GetKind(t *testing.T) {
	require.Equal(t, model.KindPulumiGo, (&Parser{}).GetKind())
}

func TestParser_SupportedExtensions(t *testing.T) {
	require.Equal(t, []string{".go"}, (&Parser{}).SupportedExtensions())
}

func TestParser_SupportedTypes(t *testing.T) {
	require.Equal(t, map[string]bool{"pulumi": true}, (&Parser{}).SupportedTypes())
}

// TestParser_Parse_S3Bucket verifies that an aws.s3.NewBucketV2 call is
// extracted and represented with the correct type token and properties.
func TestParser_Parse_S3Bucket(t *testing.T) {
	src := []byte(`package main

import (
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := s3.NewBucketV2(ctx, "my-bucket", &s3.BucketV2Args{
			Acl: pulumi.String("public-read"),
		})
		return err
	})
}
`)
	p := &Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), src, "main.go", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1, "expected exactly one document")

	resources, ok := docs[0]["resources"].(map[string]interface{})
	require.True(t, ok, "document must have a 'resources' map")

	var res map[string]interface{}
	for k, v := range resources {
		if k == "_dd_lines" {
			continue
		}
		res, ok = v.(map[string]interface{})
		require.True(t, ok)
		break
	}
	require.NotNil(t, res, "expected at least one resource entry")

	typ, _ := res["type"].(string)
	require.Contains(t, typ, "aws:", "resource type should contain provider prefix")
	require.Contains(t, typ, "BucketV2", "resource type should preserve constructor name")
}

// TestParser_Parse_NoImport verifies that a Go file without Pulumi SDK imports
// produces no documents.
func TestParser_Parse_NoImport(t *testing.T) {
	src := []byte(`package main

import "fmt"

func main() { fmt.Println("hello") }
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "main.go", false, 0)
	require.NoError(t, err)
	require.Empty(t, docs, "non-Pulumi file must produce no documents")
}

// TestParser_Parse_MultiResource verifies that multiple resource constructor
// calls in a single file all appear in the extracted document.
func TestParser_Parse_MultiResource(t *testing.T) {
	src := []byte(`package main

import (
	ec2 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		vpc, err := ec2.NewVpc(ctx, "main-vpc", &ec2.VpcArgs{
			CidrBlock: pulumi.String("10.0.0.0/16"),
		})
		if err != nil {
			return err
		}
		_, err = ec2.NewSecurityGroup(ctx, "web-sg", &ec2.SecurityGroupArgs{
			VpcId: vpc.ID(),
		})
		return err
	})
}
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "infra.go", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, ok := docs[0]["resources"].(map[string]interface{})
	require.True(t, ok)

	count := 0
	for k := range resources {
		if k != "_dd_lines" {
			count++
		}
	}
	require.Equal(t, 2, count, "expected two resource entries")
}
