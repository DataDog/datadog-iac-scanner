/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Remote module evaluation uses the same instantiateLocalModules + tfeval path as local
// modules. Pre-scan adds fetched .tf files to the scan set and registers remoteModuleDirs;
// evaluation then materializes resources with caller-resolved values into synthetic OPA
// documents and removes those resource blocks from the standalone module-body copy.
//
// Dual-scan contract:
//   - Evaluated path (remoteModuleDirs wired): caller inputs beat module defaults;
//     unresolved caller inputs stay unknown and do not leak defaults.
//   - Standalone path (intentional): variable/output/data/locals blocks, uncalled modules,
//     and resource types no rule targets continue to be scanned where written.
//   - Unevaluated fallback (pre-scan bug): fetched module files present without
//     remoteModuleDirs are scanned with parser variable defaults, not caller inputs.
package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const (
	remoteBucketSource  = "registry.example.com/acme/bucket/aws"
	remoteBucketVersion = "1.0.0"
)

type remoteBucketFixture struct {
	root       string
	cacheDir   string
	callerRoot string
	modPath    string
}

func writeRemoteBucketModule(t *testing.T, modPath, moduleBody string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(modPath), 0o755))
	require.NoError(t, os.WriteFile(modPath, []byte(moduleBody), 0o644))
}

func newRemoteBucketFixture(t *testing.T) remoteBucketFixture {
	t.Helper()
	root := t.TempDir()
	cacheDir := filepath.Join(root, "cache", "bucket")
	callerRoot := filepath.Join(root, "stack")
	modPath := filepath.Join(cacheDir, "main.tf")
	writeRemoteBucketModule(t, modPath, `
variable "acl" {
  type = string
}

resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`)
	return remoteBucketFixture{
		root:       root,
		cacheDir:   cacheDir,
		callerRoot: callerRoot,
		modPath:    modPath,
	}
}

func writeRemoteCaller(t *testing.T, callerRoot, moduleBlock string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(callerRoot, 0o755))
	callerPath := filepath.Join(callerRoot, "main.tf")
	require.NoError(t, os.WriteFile(callerPath, []byte(moduleBlock), 0o644))
	return callerPath
}

func remoteModuleKey(callerRoot string) string {
	return RemoteModuleKey(callerRoot, remoteBucketSource, remoteBucketVersion)
}

func registerRemoteBucket(ins *Inspector, callerRoot, cacheDir string) {
	directory := RemoteModuleDirectory{Path: cacheDir, PackageRoot: cacheDir}
	provenance := RemoteModuleProvenance{
		Source:          remoteBucketSource,
		ResolvedVersion: remoteBucketVersion,
		CanonicalSource: remoteBucketSource,
		SourceType:      "registry",
		ModuleRoot:      cacheDir,
	}
	keys := []string{
		RemoteModuleKey(callerRoot, remoteBucketSource, remoteBucketVersion),
		RemoteModuleCallKey(callerRoot, remoteBucketSource, remoteBucketVersion, "bucket"),
		RemoteModuleCallKey(callerRoot, remoteBucketSource, "", "bucket"),
	}
	dirs := make(map[string]RemoteModuleDirectory, len(keys))
	provs := make(map[string]RemoteModuleProvenance, len(keys))
	for _, key := range keys {
		dirs[key] = directory
		provs[key] = provenance
	}
	ins.SetRemoteModuleDirectories(dirs)
	ins.SetRemoteModuleProvenance(provs)
}

func inspectRemoteBucket(t *testing.T, fx remoteBucketFixture, callerPaths []string, rule string) []model.Vulnerability {
	t.Helper()
	var files model.FileMetadatas
	for _, path := range callerPaths {
		files = append(files, parseTerraform(t, path)...)
	}
	files = append(files, parseTerraform(t, fx.modPath)...)

	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "acl_rule", Content: rule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
		}},
		repoPath: fx.root, vb: DefaultVulnerabilityBuilder, flagEvaluator: moduleEvalEnabled(),
	})
	registerRemoteBucket(ins, fx.callerRoot, fx.cacheDir)

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	return vulns
}

func TestInspect_RemoteModule_InstantiatesWithCallerValue(t *testing.T) {
	fx := newRemoteBucketFixture(t)
	callerPath := writeRemoteCaller(t, fx.callerRoot, `
module "bucket" {
  source  = "`+remoteBucketSource+`"
  version = "`+remoteBucketVersion+`"
  acl     = "public-read"
}
`)

	vulns := inspectRemoteBucket(t, fx, []string{callerPath}, aclRule)
	require.Len(t, vulns, 1)
	require.Equal(t, fx.modPath, vulns[0].FileName)
	require.NotEmpty(t, vulns[0].ModuleCallChain)
	require.NotNil(t, vulns[0].ModuleAttribution)
	require.Equal(t, "stack/main.tf", vulns[0].ModuleAttribution.CodeLocation.Filename)
	require.Equal(t, remoteBucketSource, vulns[0].ModuleAttribution.Source)
	require.Equal(t, remoteBucketVersion, vulns[0].ModuleAttribution.Version)
	require.Equal(t, "main.tf", vulns[0].ModuleAttribution.ModuleCodeLocation.Filename)
}

func TestInspect_RemoteModule_SecureCallerOverridesInsecureDefault(t *testing.T) {
	fx := newRemoteBucketFixture(t)
	writeRemoteBucketModule(t, fx.modPath, `
variable "acl" {
  type    = string
  default = "public-read"
}
resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`)
	callerPath := writeRemoteCaller(t, fx.callerRoot, `
module "bucket" {
  source  = "`+remoteBucketSource+`"
  version = "`+remoteBucketVersion+`"
  acl     = "private"
}
`)

	vulns := inspectRemoteBucket(t, fx, []string{callerPath}, aclRule)
	require.Empty(t, vulns, "secure caller override must not produce a default-derived finding")
}

func TestInspect_RemoteModule_UnresolvedCallerInputDoesNotUseDefault(t *testing.T) {
	fx := newRemoteBucketFixture(t)
	writeRemoteBucketModule(t, fx.modPath, `
variable "acl" {
  type    = string
  default = "public-read"
}
resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`)
	callerPath := writeRemoteCaller(t, fx.callerRoot, `
variable "acl" { type = string }
module "bucket" {
  source  = "`+remoteBucketSource+`"
  version = "`+remoteBucketVersion+`"
  acl     = var.acl
}
`)

	vulns := inspectRemoteBucket(t, fx, []string{callerPath}, aclRule)
	require.Empty(t, vulns, "unresolved caller input must not fall back to the module default")
}

func TestInspect_RemoteModule_MixedCallersOnlyVulnerableInstances(t *testing.T) {
	fx := newRemoteBucketFixture(t)
	aRoot := filepath.Join(fx.root, "stack-a")
	bRoot := filepath.Join(fx.root, "stack-b")
	aPath := writeRemoteCaller(t, aRoot, `
module "bucket" {
  source  = "`+remoteBucketSource+`"
  version = "`+remoteBucketVersion+`"
  acl     = "private"
}
`)
	bPath := writeRemoteCaller(t, bRoot, `
module "bucket" {
  source  = "`+remoteBucketSource+`"
  version = "`+remoteBucketVersion+`"
  acl     = "public-read"
}
`)

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, aPath)...)
	files = append(files, parseTerraform(t, bPath)...)
	files = append(files, parseTerraform(t, fx.modPath)...)

	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
		}},
		repoPath: fx.root, vb: DefaultVulnerabilityBuilder, flagEvaluator: moduleEvalEnabled(),
	})
	ins.SetRemoteModuleDirectories(map[string]RemoteModuleDirectory{
		RemoteModuleKey(aRoot, remoteBucketSource, remoteBucketVersion): {Path: fx.cacheDir, PackageRoot: fx.cacheDir},
		RemoteModuleKey(bRoot, remoteBucketSource, remoteBucketVersion): {Path: fx.cacheDir, PackageRoot: fx.cacheDir},
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 1, "only the public-read caller should produce a finding")
	require.Equal(t, "stack-b/main.tf|module.bucket", vulns[0].ModuleCallChain,
		"finding must be attributed to the vulnerable caller, not the secure one")
}

func TestInspect_RemoteModule_TwoCallersGetDistinctCallChains(t *testing.T) {
	fx := newRemoteBucketFixture(t)
	aRoot := filepath.Join(fx.root, "stack-a")
	bRoot := filepath.Join(fx.root, "stack-b")
	aPath := writeRemoteCaller(t, aRoot, `
module "bucket" {
  source  = "`+remoteBucketSource+`"
  version = "`+remoteBucketVersion+`"
  acl     = "public-read"
}
`)
	bPath := writeRemoteCaller(t, bRoot, `
module "bucket" {
  source  = "`+remoteBucketSource+`"
  version = "`+remoteBucketVersion+`"
  acl     = "public-read"
}
`)

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, aPath)...)
	files = append(files, parseTerraform(t, bPath)...)
	files = append(files, parseTerraform(t, fx.modPath)...)

	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
		}},
		repoPath: fx.root, vb: DefaultVulnerabilityBuilder, flagEvaluator: moduleEvalEnabled(),
	})
	ins.SetRemoteModuleDirectories(map[string]RemoteModuleDirectory{
		RemoteModuleKey(aRoot, remoteBucketSource, remoteBucketVersion): {Path: fx.cacheDir, PackageRoot: fx.cacheDir},
		RemoteModuleKey(bRoot, remoteBucketSource, remoteBucketVersion): {Path: fx.cacheDir, PackageRoot: fx.cacheDir},
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2)

	chains := map[string]bool{}
	for _, v := range vulns {
		require.Equal(t, fx.modPath, v.FileName)
		require.NotEmpty(t, v.ModuleCallChain)
		chains[v.ModuleCallChain] = true
	}
	require.Len(t, chains, 2)
}

func TestInspect_RemoteModule_CountExpansionBothInstancesScanned(t *testing.T) {
	fx := newRemoteBucketFixture(t)
	writeRemoteBucketModule(t, fx.modPath, `
variable "acl" {
  type = string
}

resource "aws_s3_bucket" "replica" {
  count  = 2
  bucket = "bucket-${count.index}"
  acl    = var.acl
}
`)
	callerPath := writeRemoteCaller(t, fx.callerRoot, `
module "bucket" {
  source  = "`+remoteBucketSource+`"
  version = "`+remoteBucketVersion+`"
  acl     = "public-read"
}
`)

	vulns := inspectRemoteBucket(t, fx, []string{callerPath}, aclRule)
	require.Len(t, vulns, 2, "both count-expanded instances must produce a finding")
}

func TestInspect_RemoteModule_PreservesNonResourceBlocksInModuleBody(t *testing.T) {
	fx := newRemoteBucketFixture(t)
	writeRemoteBucketModule(t, fx.modPath, `
variable "acl" {
}

resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`)
	callerPath := writeRemoteCaller(t, fx.callerRoot, `
module "bucket" {
  source  = "`+remoteBucketSource+`"
  version = "`+remoteBucketVersion+`"
  acl     = "public-read"
}
`)

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, callerPath)...)
	files = append(files, parseTerraform(t, fx.modPath)...)

	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "variable_type_rule", Content: variableTypeRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "variable-type-rule"}, Aggregation: 1,
		}},
		repoPath: fx.root, vb: DefaultVulnerabilityBuilder, flagEvaluator: moduleEvalEnabled(),
	})
	registerRemoteBucket(ins, fx.callerRoot, fx.cacheDir)

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 1)
	require.Equal(t, "variable", vulns[0].ResourceType)
	require.Equal(t, fx.modPath, vulns[0].FileName)
}

// When fetched module files are in the scan but evaluation mapping is missing,
// the standalone parser substitutes variable defaults. Document this contract so
// pre-scan wiring bugs are visible rather than silently mis-attributed.
func TestInspect_RemoteModule_StandaloneFallbackUsesModuleDefaultWhenUnevaluated(t *testing.T) {
	fx := newRemoteBucketFixture(t)
	writeRemoteBucketModule(t, fx.modPath, `
variable "acl" {
  type    = string
  default = "public-read"
}
resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`)
	callerPath := writeRemoteCaller(t, fx.callerRoot, `
module "bucket" {
  source  = "`+remoteBucketSource+`"
  version = "`+remoteBucketVersion+`"
  acl     = "private"
}
`)

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, callerPath)...)
	files = append(files, parseTerraform(t, fx.modPath)...)

	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
		}},
		repoPath: fx.root, vb: DefaultVulnerabilityBuilder, flagEvaluator: moduleEvalEnabled(),
	})
	// Deliberately omit SetRemoteModuleDirectories.

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 1,
		"unevaluated fetched module bodies use parser variable defaults, not caller inputs")
}
