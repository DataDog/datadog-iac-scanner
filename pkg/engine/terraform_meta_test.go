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

func providerDoc(blocks ...map[string]interface{}) model.Document {
	entries := make([]interface{}, len(blocks))
	for i, b := range blocks {
		entries[i] = b
	}
	return model.Document{
		"provider": map[string]interface{}{"aws": entries},
		"resource": map[string]interface{}{"aws_s3_bucket": map[string]interface{}{
			"b": map[string]interface{}{"_dd_meta": map[string]interface{}{"address": "aws_s3_bucket.b", "provider": "aws"}},
		}},
	}
}

func providerFile(id, root string, doc model.Document) *model.FileMetadata {
	return &model.FileMetadata{ID: id, Kind: model.KindTerraform, Document: doc, TerraformScope: &model.TerraformScope{RootModule: root}}
}

func providerMetas(doc model.Document) []interface{} {
	var out []interface{}
	for _, entry := range doc["provider"].(map[string]interface{})["aws"].([]interface{}) {
		out = append(out, entry.(map[string]interface{})["_dd_meta"])
	}
	return out
}

func bucketProvider(doc model.Document) interface{} {
	return doc["resource"].(map[string]interface{})["aws_s3_bucket"].(map[string]interface{})["b"].(map[string]interface{})["_dd_meta"].(map[string]interface{})["provider"]
}

// A provider block gets the key resources carry in _dd_meta.provider only in
// a file that stands for its own root alone.
func TestStampProviderMeta(t *testing.T) {
	own := providerFile("own", "stack", providerDoc(
		map[string]interface{}{"region": "us-east-1"},
		map[string]interface{}{"alias": "west"},
		map[string]interface{}{"alias": "${__dd_unknown__}", "_dd_meta": map[string]interface{}{"unknown": map[string]interface{}{"alias": true}}},
	))
	shared := providerFile("shared", "modules/m", providerDoc(map[string]interface{}{"region": "eu-west-1"}))
	stampProviderMeta(model.FileMetadatas{own, shared}, map[string][]string{
		"own":    {"stack"},
		"shared": {"modules/m", "stack"},
	})

	require.Equal(t, []interface{}{
		map[string]interface{}{"address": "provider.aws", "provider": "aws"},
		map[string]interface{}{"address": "provider.aws.west", "provider": "aws.west"},
		map[string]interface{}{"unknown": map[string]interface{}{"alias": true}},
	}, providerMetas(own.Document))
	require.Equal(t, "aws", bucketProvider(own.Document))

	require.Equal(t, []interface{}{nil}, providerMetas(shared.Document))
	require.Nil(t, bucketProvider(shared.Document), "a block of a shared file names a different configuration in each root")
}
