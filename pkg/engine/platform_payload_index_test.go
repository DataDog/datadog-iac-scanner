/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/resourceindex"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	platformreg "github.com/DataDog/datadog-iac-scanner/pkg/platform"
)

func TestBuildPlatformPayloadsMatchesLegacyRebuild(t *testing.T) {
	filesMap, combinedDocs, moduleDocs := platformPayloadTestDocuments()
	allQueries := []model.QueryMetadata{
		{Platform: "terraform"},
		{Platform: "cloudFormation"},
		{Platform: "k8s"},
		{Platform: "knative"},
		{Platform: "crossplane"},
		{Platform: "serverlessFW"},
		{Platform: "dockerfile"},
		{Platform: "cicd"},
		{Platform: "ansible"},
		{Platform: "pulumi"},
	}
	testCases := []struct {
		name    string
		queries []model.QueryMetadata
	}{
		{name: "one platform", queries: allQueries[:1]},
		{name: "six platforms", queries: allQueries[:6]},
		{name: "all platforms and common", queries: append(allQueries, model.QueryMetadata{Platform: "Common"})},
	}

	inspector := &Inspector{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := inspector.buildPlatformPayloads(
				context.Background(), filesMap, combinedDocs, moduleDocs, tc.queries,
			)
			require.NoError(t, err)

			expected, err := legacyBuildPlatformPayloads(
				context.Background(), inspector, filesMap, combinedDocs, moduleDocs, tc.queries,
			)
			require.NoError(t, err)
			require.Equal(t, expected.byPlatform, actual.byPlatform)
			require.Equal(t, expected.full, actual.full)
			require.NotEmpty(t, actual.lookupByPlatform)
		})
	}
}

func TestBuildPlatformPayloadsPreservesSelectionEdges(t *testing.T) {
	filesMap, combinedDocs, moduleDocs := platformPayloadTestDocuments()
	queries := []model.QueryMetadata{
		{Platform: "kubernetes"},
		{Platform: "crossplane"},
		{Platform: "cloudformation"},
		{Platform: "terraform"},
		{Platform: "common"},
	}

	payloads, err := (&Inspector{}).buildPlatformPayloads(
		context.Background(), filesMap, combinedDocs, moduleDocs, queries,
	)
	require.NoError(t, err)

	kubernetesPayload := payloads.byPlatform["kubernetes"].String()
	require.Contains(t, kubernetesPayload, "k8s-id")
	require.Contains(t, kubernetesPayload, "knative-id")
	require.Contains(t, kubernetesPayload, "k8s-module-id")
	require.NotContains(t, kubernetesPayload, "unknown-id")
	require.NotContains(t, kubernetesPayload, "crossplane-id")
	require.Less(t, strings.Index(kubernetesPayload, "k8s-id"), strings.Index(kubernetesPayload, "k8s-module-id"))

	require.Contains(t, payloads.byPlatform["crossplane"].String(), "crossplane-id")
	require.NotContains(t, payloads.byPlatform["crossplane"].String(), "k8s-id")
	require.Contains(t, payloads.byPlatform["cloudformation"].String(), "serverless-id")
	require.Contains(t, payloads.byPlatform["terraform"].String(), "unknown-id")
	require.NotContains(t, payloads.byPlatform["terraform"].String(), "k8s-id")
	require.Contains(t, payloads.full.String(), "unsupported-id")
	require.NotContains(t, payloads.full.String(), "jsonencode")
	require.Contains(t, payloads.full.String(), `"enabled": true`)
}

func legacyBuildPlatformPayloads(
	ctx context.Context,
	inspector *Inspector,
	filesMap map[string]*model.FileMetadata,
	combinedDocs, moduleDocs []model.Document,
	queries []model.QueryMetadata,
) (platformPayloads, error) {
	docsByPlatform, unknownDocs, allDocs := partitionDocsByPlatform(filesMap, combinedDocs, moduleDocs)
	makePayload := func(docs []interface{}) (ast.Value, error) {
		index, _ := resourceindex.BuildWithLookup(docs, filesMap)
		value, err := ast.InterfaceToValue(map[string]interface{}{
			"document":  docs,
			"resources": index,
		})
		if err != nil {
			return nil, err
		}
		return inspector.TransformJsonencodeInPayload(ctx, value), nil
	}

	needFullPayload := false
	neededPlatforms := make(map[string]bool)
	for i := range queries {
		if platformreg.IsCrossPlatformRule(queries[i].Platform) {
			needFullPayload = true
			continue
		}
		neededPlatforms[canonicalPlatformKey(queries[i].Platform)] = true
	}

	out := platformPayloads{byPlatform: make(map[string]ast.Value, len(neededPlatforms))}
	for key := range neededPlatforms {
		docs := docsByPlatform[key]
		if len(unknownDocs) > 0 {
			selected := make([]interface{}, 0, len(docs))
			selected = append(selected, docs...)
			selected = append(selected, unknownDocs...)
			docs = selected
		}
		payload, err := makePayload(docs)
		if err != nil {
			return platformPayloads{}, err
		}
		out.byPlatform[key] = payload
	}

	if needFullPayload {
		payload, err := makePayload(allDocs)
		if err != nil {
			return platformPayloads{}, err
		}
		out.full = payload
	}
	return out, nil
}

func platformPayloadTestDocuments() (
	map[string]*model.FileMetadata,
	[]model.Document,
	[]model.Document,
) {
	platforms := map[string]string{
		"tf-id":          "terraform",
		"cf-id":          "cloudformation",
		"k8s-id":         "kubernetes",
		"knative-id":     "knative",
		"crossplane-id":  "crossplane",
		"serverless-id":  "serverlessfw",
		"docker-id":      "dockerfile",
		"cicd-id":        "cicd",
		"ansible-id":     "ansible",
		"unsupported-id": "pulumi",
		"unknown-id":     "",
		"k8s-module-id":  "kubernetes",
	}
	filesMap := make(map[string]*model.FileMetadata, len(platforms))
	for id, platform := range platforms {
		filesMap[id] = &model.FileMetadata{ID: id, Platform: platform}
	}

	combinedDocs := []model.Document{
		{
			"id": "unknown-id",
			"resource": map[string]interface{}{
				"aws_s3_bucket": map[string]interface{}{"unknown": map[string]interface{}{"bucket": "unknown"}},
			},
		},
		{
			"id": "tf-id",
			"resource": map[string]interface{}{
				"aws_s3_bucket": map[string]interface{}{
					"same": map[string]interface{}{"policy": `jsonencode({"enabled":true})`},
				},
			},
		},
		{"id": "cf-id", "Resources": map[string]interface{}{"Bucket": map[string]interface{}{"Type": "AWS::S3::Bucket"}}},
		{"id": "k8s-id", "apiVersion": "v1", "kind": "Pod", "metadata": map[string]interface{}{"name": "pod"}},
		{"id": "knative-id", "apiVersion": "serving.knative.dev/v1", "kind": "Service", "metadata": map[string]interface{}{"name": "service"}},
		{"id": "crossplane-id", "apiVersion": "s3.aws.crossplane.io/v1beta1", "kind": "Bucket", "metadata": map[string]interface{}{"name": "crossplane"}},
		{"id": "serverless-id", "Resources": map[string]interface{}{"Function": map[string]interface{}{"Type": "AWS::Lambda::Function"}}},
		{"id": "docker-id", "command": []interface{}{map[string]interface{}{"Cmd": "FROM", "Value": []interface{}{"alpine"}}}},
		{"id": "cicd-id", "on": "push", "jobs": map[string]interface{}{"build": map[string]interface{}{"runs-on": "ubuntu-latest"}}},
		{"id": "ansible-id", "playbooks": []interface{}{map[string]interface{}{"tasks": []interface{}{map[string]interface{}{"debug": map[string]interface{}{"msg": "hello"}}}}}},
		{"id": "unsupported-id", "resources": map[string]interface{}{"bucket": map[string]interface{}{}}},
	}
	moduleDocs := []model.Document{
		{
			"id": "tf-id",
			"resource": map[string]interface{}{
				"aws_s3_bucket": map[string]interface{}{"same": map[string]interface{}{"bucket": "module-copy"}},
			},
		},
		{"id": "k8s-module-id", "apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]interface{}{"name": "module"}},
	}
	return filesMap, combinedDocs, moduleDocs
}
