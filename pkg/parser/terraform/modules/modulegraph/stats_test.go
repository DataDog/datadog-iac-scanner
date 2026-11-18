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
	require.Equal(t, resolver.FailureAllowlistDenied, stat.FailureCode)
	require.Empty(t, stat.Cache)
	require.Equal(t, resolver.FailureAllowlistDenied, result.Failures[0].Code)
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

// A remote source that is not a static value fails before any resolver runs:
// the reason and code come from the declaration, not from the resolver.
func TestResolveRejectsNonStaticSourcesBeforeResolving(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "dynamic" {
  source = var.module_source
}
`), 0o644))

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver:       errorResolver{err: fmt.Errorf("the resolver must not run")},
		MaxDepth:       2,
	})

	require.Len(t, result.Failures, 1)
	require.Equal(t, tfmodules.ErrNonStaticModuleSource.Error(), result.Failures[0].Reason)
	require.Equal(t, tfmodules.FailureSourceNotStatic, result.Failures[0].Code)
	require.Equal(t, `source contains "__UNKNOWN_REF__"`, result.Failures[0].Detail)
}
