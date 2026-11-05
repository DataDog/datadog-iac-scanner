/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */
package modulegraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/stretchr/testify/require"
)

func TestResolveCollectsResolvedModuleStat(t *testing.T) {
	root, moduleDir := writeModuleGraphFixture(t)

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: stubResolver{resolution: resolver.Resolution{
			LocalPath: moduleDir,
			Origin:    "git",
			Cache:     "miss",
		}},
		MaxDepth: 2,
	})

	require.Len(t, result.Stats, 1)
	stat := result.Stats[0]
	require.Equal(t, "git", stat.Source)
	require.Equal(t, ModuleOutcomeResolved, stat.Outcome)
	require.Equal(t, "miss", stat.Cache)
	require.Empty(t, stat.FailureCode)
	require.GreaterOrEqual(t, stat.DurationMS, int64(0))
}

func TestResolveCollectsOneStatPerModuleIdentity(t *testing.T) {
	root, moduleDir := writeModuleGraphFixture(t)
	// A second declaration of the same git source+version is the same module
	// identity: it must not produce a second telemetry sample.
	require.NoError(t, os.WriteFile(filepath.Join(root, "second.tf"), []byte(`
module "network_dup" {
  source  = "git::https://git@github.com/acme/network.git//modules/vpc?ref=v1"
  version = "1.2.3"
}
`), 0o644))

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf"), filepath.Join(root, "second.tf")},
		Resolver: stubResolver{resolution: resolver.Resolution{
			LocalPath: moduleDir,
			Origin:    "git",
		}},
		MaxDepth: 2,
	})

	require.Len(t, result.Modules, 2)
	require.Len(t, result.Stats, 1)
	require.Equal(t, ModuleOutcomeResolved, result.Stats[0].Outcome)
}

func TestResolveCollectsFailureModuleStat(t *testing.T) {
	root, _ := writeModuleGraphFixture(t)

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: errorResolver{err: &tfmodules.UnresolvedError{
			Reason: "module host \"example.com\" is not in --module-host-allowlist",
		}},
		MaxDepth: 2,
	})

	require.Len(t, result.Stats, 1)
	stat := result.Stats[0]
	require.Equal(t, "git", stat.Source) // detected fallback: no resolver-provided origin
	require.Equal(t, ModuleOutcomeUnresolved, stat.Outcome)
	require.Equal(t, resolver.FailureHostNotAllowlisted, stat.FailureCode)
	require.Empty(t, stat.Cache)
}

func TestResolveCollectsHTTPFailureCode(t *testing.T) {
	root, _ := writeModuleGraphFixture(t)

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver:       errorResolver{err: fmt.Errorf("versions endpoint returned HTTP 502")},
		MaxDepth:       2,
	})

	require.Len(t, result.Stats, 1)
	require.Equal(t, ModuleOutcomeUnresolved, result.Stats[0].Outcome)
	require.Equal(t, resolver.FailureHTTPServer, result.Stats[0].FailureCode)
}

func TestResolveCollectsDetailedFailureCodes(t *testing.T) {
	const source = "git::https://example.com/acme/network.git?ref=v1"
	const placeholderSource = "git::https://example.com/acme/network.git?ref=__SOURCE_REF__"
	for _, tc := range []struct{ name, source, reason, want string }{
		{"SCI repo or ref", source, "git ref not found through SCI: NotFound", resolver.FailureGitRepoOrRefNotFound},
		{"broker ref", source, "git ref not advertised", resolver.FailureGitRefNotFound},
		{"SCI placeholder", placeholderSource, "git ref not found through SCI: NotFound", resolver.FailurePlaceholderRef},
		{"broker placeholder", placeholderSource, "git ref not advertised", resolver.FailurePlaceholderRef},
		{"empty source", "", "fixture resolver must not run", resolver.FailureEmptySource},
		{"missing subdir", source, "git_archive: archive path unavailable", resolver.FailureGitSubdirNotFound},
		{"broker subdir absent at ref", source, "module subdirectory is not in the repository at this ref", resolver.FailureGitSubdirNotFound},
		{"broker subdir not found", source, "brokered module subdirectory was not found", resolver.FailureGitSubdirNotFound},
		{"registry module", "acme/network/aws", "versions endpoint returned HTTP 404", resolver.FailureRegistryModuleNotFound},
		{"registry version", "acme/network/aws", "download endpoint returned HTTP 404", resolver.FailureRegistryVersionNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			file := filepath.Join(root, "main.tf")
			require.NoError(t, os.WriteFile(file, []byte(fmt.Sprintf(`module "network" { source = %q }`, tc.source)), 0o644))
			result := Resolve(t.Context(), &Request{
				RootPaths: []string{root}, DiscoveryPaths: []string{file}, MaxDepth: 2,
				Resolver: errorResolver{err: &tfmodules.UnresolvedError{Reason: tc.reason}},
			})
			require.Len(t, result.Stats, 1)
			require.Equal(t, ModuleOutcomeUnresolved, result.Stats[0].Outcome)
			require.Equal(t, tc.want, result.Stats[0].FailureCode)
			require.Len(t, result.Failures, 1)
			require.Equal(t, result.Failures[0].Failure.Class, result.Stats[0].FailureCode)
		})
	}
}
