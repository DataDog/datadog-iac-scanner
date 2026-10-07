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

	attr := buildModuleAttribution(&resource, repo, nil, nil)
	require.NotNil(t, attr)
	require.Equal(t, "direct", attr.DependencyType)
	require.Equal(t, "stack/main.tf", attr.CallSite.Filename)
	require.Equal(t, 2, attr.CallSite.LineStart)
	require.Equal(t, 5, attr.CallSite.LineEnd)
	require.Equal(t, 1, attr.CallSite.ColumnStart)
	require.Equal(t, 2, attr.CallSite.ColumnEnd)
	require.Equal(t, "local", attr.SourceType)
	require.Empty(t, attr.Source, "files of local modules are named from the scanned repository")
	require.Empty(t, attr.Version)
	require.Len(t, attr.ModulePath, 1)
	require.Equal(t, "bucket", attr.ModulePath[0].Name)
	require.Equal(t, "modules/bucket", attr.ModulePath[0].Source)
	require.Equal(t, "local", attr.ModulePath[0].SourceType)
	require.Equal(t, "stack/main.tf", attr.ModulePath[0].CodeLocation.Filename)
	require.Equal(t, "modules/bucket/main.tf", attr.ModuleCodeLocation.Filename)
	require.Equal(t, 2, attr.ModuleCodeLocation.LineStart)
	require.Equal(t, 1, attr.ModuleCodeLocation.ColumnStart)
	require.Equal(t, 2, attr.ModuleCodeLocation.ColumnEnd)
	require.True(t, attr.ModuleCodeOwned)
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

	attr := buildModuleAttribution(&resource, repo, lookup, nil)
	require.NotNil(t, attr)
	require.Len(t, attr.ModulePath, 1)
	require.Equal(t, "bucket", attr.ModulePath[0].Name)
	require.Equal(t, "registry.example.com/acme/bucket/aws", attr.ModulePath[0].Source)
	require.Equal(t, "registry", attr.ModulePath[0].SourceType)
	require.Equal(t, "1.0.0", attr.ModulePath[0].Version)
	require.Equal(t, "registry.example.com/acme/bucket/aws", attr.Source)
	require.Equal(t, "registry", attr.SourceType)
	require.Equal(t, "1.0.0", attr.Version)
	require.Equal(t, "main.tf", attr.ModuleCodeLocation.Filename)
	require.Equal(t, "stack/main.tf", attr.CallSite.Filename)
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

	attr := buildModuleAttribution(&resource, repo, lookup, nil)
	require.NotNil(t, attr)
	require.Equal(t, "main.tf", attr.ModuleCodeLocation.Filename)
	require.Equal(t, "https://example.com/acme/network//modules/vpc", attr.Source,
		"without a package root, files are named from the module root, which the full source names")
	require.Equal(t, "v1.0.0", attr.Version)
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

	attr := buildModuleAttribution(&resource, repo, nil, nil)
	require.NotNil(t, attr)
	require.Empty(t, attr.ModulePath[0].Version)
}

func TestBuildModuleAttributionUsesDeclaredGitRefAsVersion(t *testing.T) {
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

	attr := buildModuleAttribution(&resource, repo, lookup, nil)
	require.NotNil(t, attr)
	require.Equal(t, "https://example.com/acme/network//modules/vpc", attr.ModulePath[0].Source)
	require.Equal(t, "v3.2.0", attr.ModulePath[0].Version)

	resource.CallChain[0].Source = "git::https://example.com/acme/network.git//modules/vpc"
	attr = buildModuleAttribution(&resource, repo, lookup, nil)
	require.NotNil(t, attr)
	require.Equal(t, "45ea6a143c2d", attr.ModulePath[0].Version, "falls back to the resolved commit when no ref is declared")
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
		"https://github.com/acme/network",
		normalizedModuleSource("token@github.com:acme/network.git?ref=v1.0.0", "git", repo, repo),
	)
}

func TestNormalizedModuleSourceGivesEquivalentGitSpellingsOneSource(t *testing.T) {
	repo := t.TempDir()
	const want = "https://github.com/datadog/appgate//gateways/aws/instance"
	for _, source := range []string{
		"git::https://github.com/DataDog/appgate//gateways/aws/instance?ref=80bbe065",
		"git::https://github.com/DataDog/appgate.git//gateways/aws/instance?ref=80bbe065",
		"github.com/DataDog/appgate//gateways/aws/instance?ref=80bbe065",
		"git::git@github.com:DataDog/appgate.git//gateways/aws/instance?ref=80bbe065",
		"git@github.com:DataDog/appgate.git//gateways/aws/instance",
		"git::ssh://git@github.com/DataDog/appgate.git//gateways/aws/instance?ref=80bbe065",
	} {
		require.Equal(t, want, normalizedModuleSource(source, "git", repo, repo), source)
	}
	require.Equal(t, "https://bitbucket.org/acme/network",
		normalizedModuleSource("bitbucket.org/acme/network", "git", repo, repo))
	require.Equal(t, "https://git.example.com/acme/network//vpc",
		normalizedModuleSource("git::https://ci:token@git.example.com/acme/network.git//vpc?ref=v1", "git", repo, repo))
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

	attr := buildModuleAttribution(&resource, repo, lookup, nil)
	require.NotNil(t, attr)
	require.Equal(t, "transitive", attr.DependencyType)
	require.Len(t, attr.ModulePath, 2)
	require.Equal(t, "modules/wrapper", attr.ModulePath[0].Source)
	require.Equal(t, "stack/main.tf", attr.ModulePath[0].CodeLocation.Filename)
	require.Equal(t, "registry.example.com/acme/bucket/aws", attr.ModulePath[1].Source)
	require.Equal(t, "1.0.0", attr.ModulePath[1].Version)
	require.Equal(t, "modules/wrapper/main.tf", attr.ModulePath[1].CodeLocation.Filename)
	require.Equal(t, "main.tf", attr.ModuleCodeLocation.Filename)
	require.Equal(t, "registry.example.com/acme/bucket/aws", attr.Source, "the package holding the resource, not the root call")
	require.Equal(t, "registry", attr.SourceType)
	require.Equal(t, "1.0.0", attr.Version)
}

func TestModuleAttributionForResourceSelectsMatchingResource(t *testing.T) {
	attrs := map[string]*model.ModuleAttribution{
		"aws_s3_bucket.5.1": {
			DependencyType:     "a",
			ModuleCodeLocation: model.SourceLocation{Filename: "a.tf", LineStart: 5},
		},
		"aws_s3_bucket.5.3": {
			DependencyType:     "b",
			ModuleCodeLocation: model.SourceLocation{Filename: "b.tf", LineStart: 5},
		},
	}

	vulnerability := &model.Vulnerability{
		ResourceType:  "aws_s3_bucket",
		BlockLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 5, Col: 3}},
	}
	got := moduleAttributionForResource(attrs, vulnerability)
	require.NotNil(t, got)
	require.Equal(t, "b", got.DependencyType)
	require.Equal(t, 5, got.ModuleCodeLocation.LineStart)
}

func TestModuleAttributionForResourceNarrowsCodeLocation(t *testing.T) {
	attrs := map[string]*model.ModuleAttribution{
		"aws_s3_bucket.2.1": {
			ModuleCodeLocation: model.SourceLocation{Filename: "modules/bucket/main.tf", LineStart: 2, LineEnd: 9, ColumnStart: 1, ColumnEnd: 2},
		},
	}
	vulnerability := func() *model.Vulnerability {
		return &model.Vulnerability{
			ResourceType:          "aws_s3_bucket",
			BlockLocation:         model.ResourceLocation{Start: model.ResourceLine{Line: 2, Col: 1}},
			VulnerabilityLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 2, Col: 1}, End: model.ResourceLine{Line: 9, Col: 2}},
		}
	}

	t.Run("remediation location within the vulnerable region", func(t *testing.T) {
		v := vulnerability()
		v.RemediationLocation = model.ResourceLocation{Start: model.ResourceLine{Line: 6, Col: 5}, End: model.ResourceLine{Line: 6, Col: 27}}
		require.Equal(t, model.SourceLocation{
			Filename: "modules/bucket/main.tf", LineStart: 6, LineEnd: 6, ColumnStart: 5, ColumnEnd: 27,
		}, moduleAttributionForResource(attrs, v).ModuleCodeLocation)
	})

	t.Run("vulnerable region without a remediation location", func(t *testing.T) {
		require.Equal(t, model.SourceLocation{
			Filename: "modules/bucket/main.tf", LineStart: 2, LineEnd: 9, ColumnStart: 1, ColumnEnd: 2,
		}, moduleAttributionForResource(attrs, vulnerability()).ModuleCodeLocation)
	})

	t.Run("finding without a region keeps the definition", func(t *testing.T) {
		v := vulnerability()
		v.VulnerabilityLocation = model.ResourceLocation{}
		require.Equal(t, attrs["aws_s3_bucket.2.1"].ModuleCodeLocation, moduleAttributionForResource(attrs, v).ModuleCodeLocation)
	})

	t.Run("shared attribution is not modified", func(t *testing.T) {
		v := vulnerability()
		v.RemediationLocation = model.ResourceLocation{Start: model.ResourceLine{Line: 6, Col: 5}, End: model.ResourceLine{Line: 6, Col: 27}}
		_ = moduleAttributionForResource(attrs, v)
		require.Equal(t, 2, attrs["aws_s3_bucket.2.1"].ModuleCodeLocation.LineStart)
	})
}

func TestModuleRootAddressNamesTheRootFilesAreRelativeTo(t *testing.T) {
	const source = "https://github.com/acme/infra//modules/vpc"
	tests := []struct {
		name        string
		prov        RemoteModuleProvenance
		wantRoot    string
		wantAddress string
	}{
		{"package root above the module", RemoteModuleProvenance{ModuleRoot: "/c/infra/modules/vpc", PackageRoot: "/c/infra"}, "/c/infra", "https://github.com/acme/infra"},
		{"module root only", RemoteModuleProvenance{ModuleRoot: "/c/infra/modules/vpc"}, "/c/infra/modules/vpc", source},
		{"package root defaulted to the module root", RemoteModuleProvenance{ModuleRoot: "/c/vpc", PackageRoot: "/c/vpc"}, "/c/vpc", source},
		{"package root only", RemoteModuleProvenance{PackageRoot: "/c/infra"}, "/c/infra", "https://github.com/acme/infra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, address := moduleRootAddress(&tt.prov, source)
			require.Equal(t, tt.wantRoot, root)
			require.Equal(t, tt.wantAddress, address)
		})
	}

	root, address := moduleRootAddress(
		&RemoteModuleProvenance{ModuleRoot: "/c/module", PackageRoot: "/c/package"}, "registry.example.com/acme/bucket/aws",
	)
	require.Equal(t, "/c/module", root, "a source without a subdirectory cannot name a larger package")
	require.Equal(t, "registry.example.com/acme/bucket/aws", address)
}

func TestJoinModuleSubdir(t *testing.T) {
	require.Equal(t, "https://github.com/acme/infra", joinModuleSubdir("https://github.com/acme/infra", "."))
	require.Equal(t, "https://github.com/acme/infra//alerting", joinModuleSubdir("https://github.com/acme/infra", "alerting"))
	require.Equal(t, "https://github.com/acme/infra//modules/vpc/alerting",
		joinModuleSubdir("https://github.com/acme/infra//modules/vpc", "alerting"))
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

func TestLowerRemoteSourceKeepsSubdirectoryCase(t *testing.T) {
	require.Equal(t, "https://github.com/acme/infra//Modules/VPC",
		lowerRemoteSource("https://GitHub.com/Acme/Infra//Modules/VPC"))
	require.Equal(t, "https://git.example.com/Acme/Infra//Mod",
		lowerRemoteSource("https://Git.Example.com/Acme/Infra//Mod"))
}

func TestDeclaredGitRefHandlesShorthandAndSemicolons(t *testing.T) {
	cases := map[string]string{
		"git::https://github.com/o/r//m?ref=v1":       "v1",
		"github.com/o/r?ref=v2":                       "v2",
		"git@github.com:o/r.git//m?ref=v3":            "v3",
		"git::https://github.com/o/r?depth=1&ref=a;b": "a;b",
		"git::https://github.com/o/r":                 "",
	}
	for source, want := range cases {
		if got := declaredGitRef(source); got != want {
			t.Errorf("declaredGitRef(%q) = %q, want %q", source, got, want)
		}
	}
	if !isGitShorthand("github.com/o/r?ref=v2") || !isGitShorthand("git@github.com:o/r.git") || isGitShorthand("./local") {
		t.Error("isGitShorthand misclassifies sources")
	}
}

func TestNormalizedRemoteModuleSourceKeepsSSHPort(t *testing.T) {
	require.Equal(t, "https://host:2222/o/r", normalizedRemoteModuleSource("git::ssh://git@host:2222/o/r.git"))
	require.Equal(t, "https://host/o/r", normalizedRemoteModuleSource("git::ssh://git@host:22/o/r.git"))
	require.Equal(t, "https://host/o/r", normalizedRemoteModuleSource("git::ssh://git@host/o/r.git"))
}

func TestDeclaredModuleSourceKeepsCallCasing(t *testing.T) {
	repo := t.TempDir()
	const source = "git::https://GitHub.com/DataDog/Infra.git//Modules/VPC?ref=v1"
	require.Equal(t, "https://GitHub.com/DataDog/Infra//Modules/VPC", declaredModuleSource(source, "git", repo, repo))
	require.Equal(t, "https://github.com/datadog/infra//Modules/VPC", normalizedModuleSource(source, "git", repo, repo))
	require.Equal(t, "registry.example.com/Acme/Bucket/aws",
		declaredModuleSource("registry.example.com/Acme/Bucket/aws@1.0.0", "registry", repo, repo))
	require.Equal(t, "registry.example.com/acme/bucket/aws",
		normalizedModuleSource("registry.example.com/Acme/Bucket/aws@1.0.0", "registry", repo, repo))
}
