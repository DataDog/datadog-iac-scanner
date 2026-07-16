/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPublicFindingJSONPreservesCompatibilityWithoutInternalResourceID(t *testing.T) {
	vulnerability := Vulnerability{
		SearchKey:             "resource.secret",
		SearchLine:            12,
		Value:                 ptr("secret"),
		Output:                `{"debug":"raw"}`,
		RemediationType:       "replacement",
		QueryDuration:         time.Second,
		LineWithVulnerability: "password = secret",
		ResourceSource:        "resource source",
		FileSource:            []string{"whole", "file"},
		ModuleCallChain:       "module.child",
	}
	vulnerableFile := VulnerableFile{
		SearchKey:             vulnerability.SearchKey,
		SearchLine:            vulnerability.SearchLine,
		Value:                 vulnerability.Value,
		RemediationType:       vulnerability.RemediationType,
		LineWithVulnerability: vulnerability.LineWithVulnerability,
		ResourceSource:        vulnerability.ResourceSource,
		FileSource:            vulnerability.FileSource,
		ModuleCallChain:       vulnerability.ModuleCallChain,
	}

	for name, value := range map[string]interface{}{
		"vulnerability": vulnerability,
		"summary file":  vulnerableFile,
	} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		for _, forbidden := range []string{"_dd", "resourceId", "resource_id"} {
			if strings.Contains(string(raw), forbidden) {
				t.Errorf("%s JSON exposes %q: %s", name, forbidden, raw)
			}
		}
	}
}

func ptr(value string) *string {
	return &value
}
