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

func TestIsCrossPlatformRule(t *testing.T) {
	assert.True(t, platform.IsCrossPlatformRule("Common"))
	assert.True(t, platform.IsCrossPlatformRule("common"))
	assert.False(t, platform.IsCrossPlatformRule("terraform"))
	assert.False(t, platform.IsCrossPlatformRule("datadog"))
}

func TestDatadogIsNotScanPlatform(t *testing.T) {
	_, ok := platform.CanonicalID("datadog")
	assert.False(t, ok)
}

func TestLibraryIdentity_ResolvesSharedLibraries(t *testing.T) {
	lib, ok := platform.LibraryIdentity("datadog")
	require.True(t, ok)
	assert.Equal(t, platform.LibraryDatadog, lib)

	lib, ok = platform.LibraryIdentity("Common")
	require.True(t, ok)
	assert.Equal(t, platform.LibraryCommon, lib)
}
