/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resourceindex

import (
	"testing"
)

// assertBucketHasEntry checks that the index has a bucket for wantType with
// at least one entry whose resourceName matches wantName.
func assertBucketHasEntry(t *testing.T, index map[string]interface{}, wantType, wantName string) {
	t.Helper()
	bucket, ok := index[wantType].(map[string]interface{})
	if !ok {
		t.Fatalf("%s bucket missing from index", wantType)
	}
	for _, rawEntry := range bucket {
		entry, ok := rawEntry.(map[string]interface{})
		if !ok {
			continue
		}
		if rt, _ := entry[EntryResourceType].(string); rt != wantType {
			continue
		}
		if rn, _ := entry[EntryResourceName].(string); rn == wantName {
			return
		}
	}
	t.Errorf("no entry with resourceName=%q found in %s bucket", wantName, wantType)
}

// TestCF_SAMTypesAreIndexed verifies that AWS SAM resource types
// (AWS::Serverless::Function, AWS::Serverless::Api) are indexed by the
// CloudFormation adapter, which iterates all Resources entries by Type
// without any prefix allowlist.
func TestCF_SAMTypesAreIndexed(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id": "sam1",
			"Resources": map[string]interface{}{
				"MyFunc": map[string]interface{}{
					"Type": "AWS::Serverless::Function",
					"Properties": map[string]interface{}{
						"Handler": "index.handler",
						"Runtime": "nodejs18.x",
					},
				},
				"MyApi": map[string]interface{}{
					"Type": "AWS::Serverless::Api",
					"Properties": map[string]interface{}{
						"StageName": "prod",
					},
				},
			},
		},
	}
	index := buildIndex(t, docs, map[string]string{"sam1": "cloudformation"})

	assertBucketHasEntry(t, index, "AWS::Serverless::Function", "MyFunc")
	assertBucketHasEntry(t, index, "AWS::Serverless::Api", "MyApi")
}
