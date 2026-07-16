/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package source

import (
	"strings"
	"testing"
)

func TestScannerFindingLibraryIsMechanical(t *testing.T) {
	code := ScannerFindingLibrary().LibraryCode
	for _, expected := range []string{"finding(resource, relative_path)", `"_dd": {"id": resource._dd.id}`, `"path": relative_path`} {
		if !strings.Contains(code, expected) {
			t.Fatalf("scanner finding helper missing %q: %s", expected, code)
		}
	}
	for _, forbidden := range []string{"documentId", "resourceType", "resourceName", "issueType", "scope"} {
		if strings.Contains(code, forbidden) {
			t.Fatalf("scanner finding helper contains policy field %q: %s", forbidden, code)
		}
	}
}
