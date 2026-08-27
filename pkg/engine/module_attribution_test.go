/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/stretchr/testify/require"
)

func TestBuildModuleAttributionDirectLocalModule(t *testing.T) {
	repo := t.TempDir()
	moduleDir := writeLocalModuleFixture(t, repo, "modules/bucket", `
resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`)
	callerPath := writeCallerFixture(t, repo, "stack/main.tf", `
module "bucket" {
  source = "../modules/bucket"
  acl    = "public-read"
}
`)

	resource := tfeval.ResolvedResource{
		Type:          "aws_s3_bucket",
		Name:          "this",
		DefinedIn:     filepath.Join(moduleDir, "main.tf"),
		DefLine:       2,
		DefEndLine:    4,
		DefColumn:     1,
		DefEndColumn:  2,
		ModuleAddress: "module.bucket",
		CallChain: []tfeval.CallSite{{
			ModuleName:      "bucket",
			Source:          "../modules/bucket",
			CalledFrom:      callerPath,
			CalledLine:      2,
			CalledEndLine:   5,
			CalledColumn:    1,
			CalledEndColumn: 2,
		}},
	}

	attr := buildModuleAttribution(&resource, repo, moduleDir, nil)
	require.NotNil(t, attr)
	require.Equal(t, "direct", attr.DependencyType)
	require.Equal(t, "stack/main.tf", attr.CodeLocation.Filename)
	require.Equal(t, 2, attr.CodeLocation.LineStart)
	require.Equal(t, 5, attr.CodeLocation.LineEnd)
	require.Equal(t, 1, attr.CodeLocation.ColumnStart)
	require.Equal(t, 2, attr.CodeLocation.ColumnEnd)
	require.Equal(t, "bucket", attr.Name)
	require.Equal(t, "modules/bucket", attr.Source)
	require.Equal(t, "local", attr.SourceType)
	require.Equal(t, "main.tf", attr.ModuleCodeLocation.Filename)
	require.Equal(t, 2, attr.ModuleCodeLocation.LineStart)
	require.Equal(t, 1, attr.ModuleCodeLocation.ColumnStart)
	require.Equal(t, 2, attr.ModuleCodeLocation.ColumnEnd)
	require.True(t, attr.ModuleCodeOwned)
	require.Empty(t, attr.ModulePath)
}

func TestBuildModuleAttributionRemoteModuleUsesProvenance(t *testing.T) {
	repo := t.TempDir()
	callerPath := writeCallerFixture(t, repo, "stack/main.tf", `
module "bucket" {
  source  = "registry.example.com/acme/bucket/aws"
  version = "1.0.0"
  acl     = "public-read"
}
`)
	moduleBody := filepath.Join(repo, "cache", "main.tf")
	resource := tfeval.ResolvedResource{
		Type:          "aws_s3_bucket",
		Name:          "this",
		DefinedIn:     moduleBody,
		DefLine:       8,
		DefEndLine:    10,
		ModuleAddress: "module.bucket",
		CallChain: []tfeval.CallSite{{
			ModuleName:    "bucket",
			Source:        "registry.example.com/acme/bucket/aws",
			Version:       "1.0.0",
			CalledFrom:    callerPath,
			CalledLine:    2,
			CalledEndLine: 6,
		}},
	}
	lookup := moduleProvenanceLookup(func(_, _, _, _ string) (RemoteModuleProvenance, bool) {
		return RemoteModuleProvenance{
			Source:          "registry.example.com/acme/bucket/aws",
			ResolvedVersion: "1.0.0",
			CanonicalSource: "registry.example.com/acme/bucket/aws",
			SourceType:      "registry",
			ModuleRoot:      filepath.Join(repo, "cache"),
		}, true
	})

	attr := buildModuleAttribution(&resource, repo, filepath.Join(repo, "cache"), lookup)
	require.NotNil(t, attr)
	require.Equal(t, "bucket", attr.Name)
	require.Equal(t, "registry.example.com/acme/bucket/aws", attr.Source)
	require.Equal(t, "registry", attr.SourceType)
	require.Equal(t, "1.0.0", attr.Version)
	require.Equal(t, "main.tf", attr.ModuleCodeLocation.Filename)
	require.Equal(t, "stack/main.tf", attr.CodeLocation.Filename)
	require.Empty(t, attr.ModulePath)
	require.False(t, attr.ModuleCodeOwned)
}

func TestBuildModuleAttributionUsesSelectedRemoteModuleRoot(t *testing.T) {
	repo := t.TempDir()
	callerPath := writeCallerFixture(t, repo, "stack/main.tf", `
module "vpc" {
  source = "git::https://example.com/acme/network.git//modules/vpc?ref=v1.0.0"
}
`)
	moduleRoot := filepath.Join(repo, "cache", "modules", "vpc")
	resource := tfeval.ResolvedResource{
		Type:      "aws_vpc",
		Name:      "this",
		DefinedIn: filepath.Join(moduleRoot, "main.tf"),
		DefLine:   3,
		CallChain: []tfeval.CallSite{{
			ModuleName: "vpc",
			Source:     "git::https://example.com/acme/network.git//modules/vpc?ref=v1.0.0",
			CalledFrom: callerPath,
			CalledLine: 2,
		}},
	}
	lookup := moduleProvenanceLookup(func(_, _, _, _ string) (RemoteModuleProvenance, bool) {
		return RemoteModuleProvenance{
			Source:     resource.CallChain[0].Source,
			SourceType: "git",
			ModuleRoot: moduleRoot,
		}, true
	})

	attr := buildModuleAttribution(
		&resource, repo, moduleRootForResource(&resource, repo, lookup), lookup,
	)
	require.NotNil(t, attr)
	require.Equal(t, "main.tf", attr.ModuleCodeLocation.Filename)
}

func TestBuildModuleAttributionUsesOnlyConcreteResolvedVersion(t *testing.T) {
	repo := t.TempDir()
	callerPath := writeCallerFixture(t, repo, "stack/main.tf", `
module "bucket" {
  source  = "registry.example.com/acme/bucket/aws"
  version = "~> 1.0"
}
`)
	resource := tfeval.ResolvedResource{
		Type:      "aws_s3_bucket",
		Name:      "this",
		DefinedIn: filepath.Join(repo, "cache", "main.tf"),
		DefLine:   2,
		CallChain: []tfeval.CallSite{{
			ModuleName: "bucket",
			Source:     "registry.example.com/acme/bucket/aws",
			Version:    "~> 1.0",
			CalledFrom: callerPath,
			CalledLine: 2,
		}},
	}

	attr := buildModuleAttribution(&resource, repo, filepath.Join(repo, "cache"), nil)
	require.NotNil(t, attr)
	require.Empty(t, attr.Version)
}

func TestBuildModuleAttributionUsesResolvedGitRefAsVersion(t *testing.T) {
	repo := t.TempDir()
	callerPath := writeCallerFixture(t, repo, "stack/main.tf", `
module "vpc" {
  source = "git::https://user:token@example.com/acme/network.git//modules/vpc?ref=v3.2.0"
}
`)
	resource := tfeval.ResolvedResource{
		Type:      "aws_vpc",
		Name:      "this",
		DefinedIn: filepath.Join(repo, "cache", "main.tf"),
		DefLine:   2,
		CallChain: []tfeval.CallSite{{
			ModuleName: "vpc",
			Source:     "git::https://user:token@example.com/acme/network.git//modules/vpc?ref=v3.2.0",
			CalledFrom: callerPath,
			CalledLine: 2,
		}},
	}
	lookup := moduleProvenanceLookup(func(_, _, _, _ string) (RemoteModuleProvenance, bool) {
		return RemoteModuleProvenance{
			Source:          resource.CallChain[0].Source,
			ResolvedRef:     "45ea6a143c2d",
			CanonicalSource: resource.CallChain[0].Source,
			SourceType:      "git",
			ModuleRoot:      filepath.Join(repo, "cache"),
		}, true
	})

	attr := buildModuleAttribution(&resource, repo, filepath.Join(repo, "cache"), lookup)
	require.NotNil(t, attr)
	require.Equal(t, "https://example.com/acme/network//modules/vpc", attr.Source)
	require.Equal(t, "45ea6a143c2d", attr.Version)
}

func TestNormalizedModuleSourceDoesNotExposeExternalLocalPaths(t *testing.T) {
	repo := t.TempDir()

	require.Equal(t, "shared", normalizedModuleSource("/Users/example/shared", "local", repo, repo))
	require.Equal(t, "shared", normalizedModuleSource("../../../Users/example/shared", "local", repo, repo))
	require.Equal(t, "shared", normalizedModuleSource("file:///Users/example/shared", "local", repo, repo))
	require.Equal(t, "shared", normalizedModuleSource(`C:\Users\example\shared`, "local", repo, repo))
	require.Equal(
		t,
		"network//modules/vpc",
		normalizedModuleSource(
			"git::file:///Users/example/network.git//modules/vpc?ref=v1.0.0",
			"git",
			repo,
			repo,
		),
	)
	require.Equal(
		t,
		"github.com:acme/network",
		normalizedModuleSource("token@github.com:acme/network.git?ref=v1.0.0", "git", repo, repo),
	)
}

func TestBuildModuleAttributionTransitiveHopUsesCallerDirectory(t *testing.T) {
	repo := t.TempDir()
	rootCaller := writeCallerFixture(t, repo, "stack/main.tf", `
module "wrapper" {
  source = "../modules/wrapper"
}
`)
	wrapperCaller := writeCallerFixture(t, repo, "modules/wrapper/main.tf", `
module "bucket" {
  source  = "registry.example.com/acme/bucket/aws"
  version = "1.0.0"
}
`)
	_ = wrapperCaller
	moduleBody := filepath.Join(repo, "cache", "main.tf")
	wrapperRoot := filepath.Join(repo, "modules", "wrapper")
	lookup := moduleProvenanceLookup(func(callerRoot, _, _, moduleName string) (RemoteModuleProvenance, bool) {
		if callerRoot == wrapperRoot && moduleName == "bucket" {
			return RemoteModuleProvenance{
				Source:          "registry.example.com/acme/bucket/aws",
				ResolvedVersion: "1.0.0",
				CanonicalSource: "registry.example.com/acme/bucket/aws",
				SourceType:      "registry",
				ModuleRoot:      filepath.Join(repo, "cache"),
			}, true
		}
		return RemoteModuleProvenance{}, false
	})
	resource := tfeval.ResolvedResource{
		Type:          "aws_s3_bucket",
		Name:          "this",
		DefinedIn:     moduleBody,
		DefLine:       2,
		ModuleAddress: "module.wrapper.module.bucket",
		CallChain: []tfeval.CallSite{
			{
				ModuleName: "wrapper",
				Source:     "../modules/wrapper",
				CalledFrom: rootCaller,
				CalledLine: 2,
			},
			{
				ModuleName: "bucket",
				Source:     "registry.example.com/acme/bucket/aws",
				Version:    "1.0.0",
				CalledFrom: wrapperCaller,
				CalledLine: 2,
			},
		},
	}

	attr := buildModuleAttribution(&resource, repo, filepath.Join(repo, "cache"), lookup)
	require.NotNil(t, attr)
	require.Equal(t, "transitive", attr.DependencyType)
	require.Len(t, attr.ModulePath, 2)
	require.Equal(t, "modules/wrapper", attr.ModulePath[0].Source)
	require.Equal(t, "stack/main.tf", attr.ModulePath[0].CodeLocation.Filename)
	require.Equal(t, "registry.example.com/acme/bucket/aws", attr.ModulePath[1].Source)
	require.Equal(t, "1.0.0", attr.ModulePath[1].Version)
	require.Equal(t, "main.tf", attr.ModulePath[1].CodeLocation.Filename)
	require.Equal(t, "main.tf", attr.ModuleCodeLocation.Filename)
}

func TestModuleAttributionForResourceSelectsMatchingResource(t *testing.T) {
	attrs := map[string]*model.ModuleAttribution{
		"aws_s3_bucket.5.1": {
			Name:               "a",
			ModuleCodeLocation: model.SourceLocation{Filename: "a.tf", LineStart: 5},
		},
		"aws_s3_bucket.5.3": {
			Name:               "b",
			ModuleCodeLocation: model.SourceLocation{Filename: "b.tf", LineStart: 5},
		},
	}

	got := moduleAttributionForResource(attrs, "aws_s3_bucket", 5, 3)
	require.NotNil(t, got)
	require.Equal(t, "b", got.Name)
	require.Equal(t, 5, got.ModuleCodeLocation.LineStart)
}

func writeLocalModuleFixture(t *testing.T, repo, relDir, body string) string {
	t.Helper()
	dir := filepath.Join(repo, relDir)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(body), 0o644))
	return dir
}

func writeCallerFixture(t *testing.T, repo, relPath, body string) string {
	t.Helper()
	path := filepath.Join(repo, relPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}
