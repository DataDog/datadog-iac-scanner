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
