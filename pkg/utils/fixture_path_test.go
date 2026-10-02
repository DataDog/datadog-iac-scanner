/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import "testing"

func TestIsTestFixturePath(t *testing.T) {
	tests := map[string]bool{
		"/repo/pkg/testdata/a.yaml":   true,
		"/repo/tests/fixtures/a.yaml": true,
		"repo/__fixtures__/a.tf":      true,
		"/repo/prod/main.tf":          false,
		"/repo/testdata-gen/main.tf":  false,
		"/repo/config/fixtures.yaml":  false,
	}
	for path, want := range tests {
		if got := IsTestFixturePath(path); got != want {
			t.Errorf("IsTestFixturePath(%q) = %v, want %v", path, got, want)
		}
	}
}
