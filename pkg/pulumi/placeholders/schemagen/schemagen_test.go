/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package schemagen

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixture = `{
  "functions": {
    "aws:ec2/getVpc:getVpc": {"outputs": {"properties": {
      "id": {"type": "string"},
      "cidrBlock": {"type": "string"},
      "ownerId": {"type": "string"},
      "arn": {"type": "string"},
      "default": {"type": "boolean"},
      "count": {"type": "integer"},
      "ratio": {"type": "number"},
      "tags": {"type": "object", "additionalProperties": {"type": "string"}},
      "names": {"type": "array", "items": {"type": "string"}},
      "zoneIds": {"type": "array", "items": {"type": "string"}},
      "subnetIds": {"type": "array", "items": {"type": "string"}},
      "cidrBlockAssociations": {"type": "array", "items": {"$ref": "#/types/aws:ec2%2FgetVpcCidrBlockAssociation:getVpcCidrBlockAssociation"}},
      "tenancy": {"$ref": "#/types/aws:ec2/Tenancy:Tenancy"},
      "external": {"$ref": "aws.json#/types/other"},
      "deep": {"$ref": "#/types/aws:x/Loop:Loop"}
    }}},
    "aws:index/getRegion:getRegion": {"outputs": {"properties": {"name": {"type": "string"}, "endpoint": {"type": "string"}}}},
    "aws:index/getNothing:getNothing": {}
  },
  "types": {
    "aws:ec2/getVpcCidrBlockAssociation:getVpcCidrBlockAssociation": {"type": "object", "properties": {
      "associationId": {"type": "string"}, "state": {"type": "string"}}},
    "aws:ec2/Tenancy:Tenancy": {"type": "string", "enum": [{"value": "default"}, {"value": "dedicated"}]},
    "aws:x/Loop:Loop": {"type": "object", "properties": {"next": {"$ref": "#/types/aws:x/Loop:Loop"}}}
  }
}`

func TestBuild(t *testing.T) {
	var s Schema
	require.NoError(t, json.Unmarshal([]byte(fixture), &s))
	got := Build("aws", &s)

	vpc := got["aws:ec2/getVpc:getVpc"]
	assert.Equal(t, "dd-placeholder-id", vpc["id"])
	assert.Equal(t, "10.0.0.0/16", vpc["cidrBlock"])
	assert.Equal(t, AccountID, vpc["ownerId"])
	assert.Equal(t, "arn:aws:iam::000000000000:dd-placeholder", vpc["arn"])
	assert.Equal(t, false, vpc["default"])
	assert.Equal(t, 1, vpc["count"])
	assert.InDelta(t, 1.5, vpc["ratio"], 0)
	assert.Equal(t, map[string]any{}, vpc["tags"])
	assert.Equal(t, []any{"us-east-1a", "us-east-1b", "us-east-1c"}, vpc["names"])
	assert.Equal(t, []any{"use1-az1", "use1-az2", "use1-az4"}, vpc["zoneIds"])
	assert.Equal(t, []any{"dd-placeholder-0", "dd-placeholder-1", "dd-placeholder-2"}, vpc["subnetIds"])
	assoc := map[string]any{"associationId": "dd-placeholder", "state": "dd-placeholder"}
	assert.Equal(t, []any{assoc, assoc, assoc}, vpc["cidrBlockAssociations"])
	assert.Equal(t, "default", vpc["tenancy"], "enums take their first value")
	assert.NotContains(t, vpc, "external", "references to other packages are skipped")
	assert.NotNil(t, vpc["deep"], "recursive types stop at the depth limit")

	assert.Equal(t, map[string]any{"name": "us-east-1", "endpoint": "https://dd-placeholder.example.invalid"},
		got["aws:index/getRegion:getRegion"])
	assert.Equal(t, map[string]any{}, got["aws:index/getNothing:getNothing"])
}

func TestTextByProvider(t *testing.T) {
	assert.Equal(t, "us-central1-a", gen{provider: "gcp"}.text("zone"))
	assert.Equal(t, GCPProject, gen{provider: "gcp"}.text("project"))
	assert.Equal(t, Text, gen{provider: "aws"}.text("project"))
	assert.Equal(t, GUID, gen{provider: "azure"}.text("tenant_id"))
	assert.Equal(t, "westus", gen{provider: "azure"}.text("location"))
	assert.Equal(t, Text, gen{provider: "azure"}.text("arn"))
}
