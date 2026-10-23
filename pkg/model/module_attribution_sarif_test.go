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
		Source: "https://user:token@example.com/modules",
		ModulePath: []ModulePathHop{{
			Source: "https://user:token@example.com/modules//bucket",
		}, {
			Source: "../local",
		}},
	}

	payload := ModuleAttributionForSARIF(attr)
	require.Equal(t, "https://example.com/modules", payload.Source)
	require.NotContains(t, payload.ModulePath[0].Source, "user:token@")
	require.Contains(t, payload.ModulePath[0].Source, "example.com/modules//bucket")
	require.Equal(t, "../local", payload.ModulePath[1].Source)
	require.Equal(t, "https://user:token@example.com/modules//bucket", attr.ModulePath[0].Source, "the attribution is not modified")

	clean := []ModulePathHop{{Source: "../local"}, {Source: "registry.example.com/ns/name/aws"}}
	require.Equal(t, clean, ModuleAttributionForSARIF(&ModuleAttribution{ModulePath: clean}).ModulePath)
	require.Equal(t, "git::https://example.com/m.git?ref=v1", RedactURLCredentials("git::https://example.com/m.git?ref=v1"))
	require.Equal(t, "user@example.com", RedactURLCredentials("user@example.com"), "no scheme, nothing to redact")
}

func TestModuleAttributionForSARIFEmptyPathIsNotNull(t *testing.T) {
	out := ModuleAttributionForSARIF(&ModuleAttribution{})
	require.NotNil(t, out.ModulePath)
	require.Empty(t, out.ModulePath)
}
