/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

func TestDeclaresExpandedBlock(t *testing.T) {
	files := model.FileMetadatas{{
		FilePath: "main.tf",
		Document: model.Document{
			"resource": map[string]interface{}{
				"aws_s3_bucket": map[string]interface{}{
					"b": map[string]interface{}{
						"_dd_lines": map[string]interface{}{"_dd_count": map[string]interface{}{}},
					},
				},
			},
		},
	}}
	aws := &ruleTargets{types: map[string]bool{"aws_s3_bucket": true}}
	if !declaresExpandedBlock(files, aws) {
		t.Fatal("count on a targeted type must be noticed")
	}
	if declaresExpandedBlock(files, &ruleTargets{types: map[string]bool{"aws_instance": true}}) {
		t.Fatal("count on an untargeted type must be ignored")
	}
}
