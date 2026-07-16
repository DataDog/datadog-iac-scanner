/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package platform_test

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyStructuredContent_CNI(t *testing.T) {
	tests := []struct {
		name    string
		pathExt string
		content string
		want    bool
	}{
		{"plugin list", ".conflist", `{"cniVersion":"1.0.0","plugins":[{"type":"bridge"}]}`, true},
		{"single plugin", ".conf", `{"cniVersion":"1.0.0","type":"bridge"}`, true},
		{"json extension", ".json", `{"cniVersion":"1.0.0","type":"bridge"}`, true},
		{"unsupported extension", ".yaml", `{"cniVersion":"1.0.0","type":"bridge"}`, false},
		{"nested keys", ".conf", `{"wrapper":{"cniVersion":"1.0.0","type":"bridge"}}`, false},
		{"substring values", ".conf", `{"description":"cniVersion plugins type"}`, false},
		{"version only", ".conf", `{"cniVersion":"1.0.0"}`, false},
		{"type only", ".conf", `{"type":"bridge"}`, false},
		{"malformed", ".conf", `{"cniVersion":`, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := platform.ClassifyStructuredContent(test.pathExt, []byte(test.content))
			assert.Equal(t, test.want, ok)
			if test.want {
				require.Equal(t, platform.Kubernetes, got)
			}
		})
	}
}

func TestIsRequested(t *testing.T) {
	assert.True(t, platform.IsRequested(platform.Kubernetes, nil))
	assert.True(t, platform.IsRequested(platform.Kubernetes, []string{""}))
	assert.True(t, platform.IsRequested(platform.Kubernetes, []string{"k8s"}))
	assert.True(t, platform.IsRequested(platform.Kubernetes, []string{"Kubernetes"}))
	assert.False(t, platform.IsRequested(platform.Kubernetes, []string{"Ansible"}))
}

func TestClassifyDocument_ResourceIndexShapes(t *testing.T) {
	tests := []struct {
		name     string
		document map[string]interface{}
		want     platform.ID
		ok       bool
	}{
		{"cni", map[string]interface{}{"cniVersion": "1.0.0", "type": "bridge"}, platform.Kubernetes, true},
		{"terraform", map[string]interface{}{"resource": map[string]interface{}{}}, platform.Terraform, true},
		{"cloudformation", map[string]interface{}{"Resources": map[string]interface{}{}}, platform.CloudFormation, true},
		{"kubernetes", map[string]interface{}{"apiVersion": "v1", "kind": "Pod"}, platform.Kubernetes, true},
		{"kubernetes configmap data", map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"data":       map[string]interface{}{"cni-conf.json": "{}"},
		}, platform.Kubernetes, true},
		{"kubernetes secret data", map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"data":       map[string]interface{}{"token": "Cg=="},
		}, platform.Kubernetes, true},
		{"dockerfile", map[string]interface{}{"command": "FROM"}, platform.Dockerfile, true},
		{"cicd", map[string]interface{}{"jobs": map[string]interface{}{}, "on": "push"}, platform.CICD, true},
		{"ansible", map[string]interface{}{"playbooks": []interface{}{}}, platform.Ansible, true},
		{"nested keys", map[string]interface{}{"wrapper": map[string]interface{}{"apiVersion": "v1", "kind": "Pod"}}, "", false},
		{"partial kubernetes", map[string]interface{}{"kind": "Pod"}, "", false},
		{"partial cicd", map[string]interface{}{"jobs": map[string]interface{}{}}, "", false},
		{"nil keys", map[string]interface{}{"Resources": nil, "all": nil, "command": nil}, "", false},
		{"unknown", map[string]interface{}{"description": "resource Resources kind apiVersion command jobs on all"}, "", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := platform.ClassifyDocument(test.document)
			assert.Equal(t, test.ok, ok)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestClassifyDocument_Precedence(t *testing.T) {
	tests := []struct {
		name     string
		document map[string]interface{}
		want     platform.ID
	}{
		{"cni before terraform", map[string]interface{}{"cniVersion": "1.0.0", "type": "bridge", "resource": true}, platform.Kubernetes},
		{"terraform before cloudformation", map[string]interface{}{"resource": true, "Resources": true}, platform.Terraform},
		{"cloudformation before kubernetes", map[string]interface{}{"Resources": true, "apiVersion": "v1", "kind": "Pod"}, platform.CloudFormation},
		{"kubernetes before dockerfile", map[string]interface{}{"apiVersion": "v1", "kind": "Pod", "command": "RUN"}, platform.Kubernetes},
		{"dockerfile before cicd", map[string]interface{}{"command": "RUN", "jobs": true, "on": true}, platform.Dockerfile},
		{"cicd before ansible", map[string]interface{}{"jobs": true, "on": true, "all": true}, platform.CICD},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := platform.ClassifyDocument(test.document)
			require.True(t, ok)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestClassifyStructuredDocument_AnalyzerPrecedence(t *testing.T) {
	document := map[string]interface{}{
		"Resources":  map[string]interface{}{},
		"apiVersion": "v1",
		"kind":       "Pod",
		"jobs":       map[string]interface{}{},
		"on":         "push",
	}

	got, ok := platform.ClassifyStructuredDocument(".yaml", document)

	require.True(t, ok)
	assert.Equal(t, platform.Kubernetes, got)
	_, ok = platform.ClassifyStructuredDocument(".json", document)
	assert.False(t, ok)
}

func TestStructuralExtensions(t *testing.T) {
	assert.ElementsMatch(t, []string{".json", ".conf", ".conflist", ".yaml", ".yml"}, platform.StructuralExtensions())
	assert.True(t, platform.StructuralClassificationRequiresContent(".conf"))
	assert.True(t, platform.StructuralClassificationRequiresContent(".conflist"))
}
