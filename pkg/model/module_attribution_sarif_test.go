/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestModuleAttributionForSARIF_IncludesCodeLocationColumns(t *testing.T) {
	attr := &ModuleAttribution{
		ModuleCodeLocation: SourceLocation{
			Filename:    "main.tf",
			LineStart:   24,
			LineEnd:     31,
			ColumnStart: 3,
			ColumnEnd:   12,
		},
		ModulePath: []ModulePathHop{{
			Name: "wrapper",
			CodeLocation: SourceLocation{
				Filename:    "stack/main.tf",
				LineStart:   2,
				LineEnd:     4,
				ColumnStart: 1,
				ColumnEnd:   2,
			},
		}},
	}

	payload := ModuleAttributionForSARIF(attr)
	require.Equal(t, 3, payload.ModuleCodeLocation.ColumnStart)
	require.Equal(t, 12, payload.ModuleCodeLocation.ColumnEnd)
	require.Equal(t, 1, payload.ModulePath[0].CodeLocation.ColumnStart)
	require.Equal(t, 2, payload.ModulePath[0].CodeLocation.ColumnEnd)
}

func TestModuleAttributionForSARIF_RedactsCredentials(t *testing.T) {
	attr := &ModuleAttribution{
		Source: "https://user:token@example.com/modules/bucket",
		ModulePath: []ModulePathHop{{
			Source: "https://user:token@example.com/modules/bucket",
		}},
	}

	payload := ModuleAttributionForSARIF(attr)
	require.NotContains(t, payload.Source, "user:token@")
	require.NotContains(t, payload.ModulePath[0].Source, "user:token@")
	require.Contains(t, payload.Source, "example.com/modules/bucket")
}
