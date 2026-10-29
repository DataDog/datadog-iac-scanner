/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package placeholders

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/placeholders/schemagen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedTable(t *testing.T) {
	require.NoError(t, LoadError())

	var m struct {
		Providers []schemagen.Pin `json:"providers"`
		Functions int             `json:"functions"`
	}
	b, err := os.ReadFile("invokes.meta.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &m))
	assert.Equal(t, schemagen.Pins, m.Providers, "the embedded table was generated from the pinned schemas: run make generate-pulumi-placeholders")
	assert.Equal(t, m.Functions, Len())
}

func TestInvokeCommonDataSources(t *testing.T) {
	zones, ok := Invoke("aws:index/getAvailabilityZones:getAvailabilityZones")
	require.True(t, ok)
	assert.Equal(t, []any{"us-east-1a", "us-east-1b", "us-east-1c"}, zones["names"])

	identity, ok := Invoke("aws:index/getCallerIdentity:getCallerIdentity")
	require.True(t, ok)
	assert.Equal(t, schemagen.AccountID, identity["accountId"])

	region, ok := Invoke("aws:index/getRegion:getRegion")
	require.True(t, ok)
	assert.Equal(t, "us-east-1", region["name"])

	client, ok := Invoke("gcp:organizations/getClientConfig:getClientConfig")
	require.True(t, ok)
	assert.Equal(t, schemagen.GCPProject, client["project"])

	azure, ok := Invoke("azure:core/getClientConfig:getClientConfig")
	require.True(t, ok)
	assert.Equal(t, schemagen.GUID, azure["tenantId"])

	_, ok = Invoke("kubernetes:helm:template")
	assert.False(t, ok, "only aws, gcp and azure functions have placeholders")
}
