/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	remoteCall = `source = "terraform-aws-modules/vpc/aws"`
	gitCall    = `source = "git::https://example.invalid/mod.git"`
)

func related(idx map[string]any, bucket string) any {
	return get(idx, "related", bucket, "aws_s3_bucket_versioning", "bucket")
}

func referrers(idx map[string]any, bucket string) any {
	return get(idx, "referrers", bucket, "bucket")
}

func requireDefinite(t *testing.T, p *Projection, idx map[string]any, bucket string, want []any) {
	t.Helper()
	require.Equal(t, want, ids(related(idx, bucket)), bucket)
	require.Equal(t, want, ids(referrers(idx, bucket)), bucket)
	require.False(t, p.Blocks[bucket].RelPlaceholder, bucket)
}

// requireIncomplete checks that the answers of bucket end with the
// placeholder; the calls that read the bucket are its concrete referrers.
func requireIncomplete(t *testing.T, p *Projection, idx map[string]any, bucket string, calls ...any) {
	t.Helper()
	require.Equal(t, []any{testPlaceholder}, ids(related(idx, bucket)), bucket)
	require.Equal(t, append(calls, testPlaceholder), ids(referrers(idx, bucket)), bucket)
	require.True(t, p.Blocks[bucket].RelPlaceholder, bucket)
}

// A call with no argument cannot read a block of its caller: the buckets keep
// definite companions, with or without one.
func TestInputFreeUnresolvedModulesKeepRelationsDefinite(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "aws_s3_bucket" "logged" { bucket = "logged" }
resource "aws_s3_bucket" "bare" { bucket = "bare" }
resource "aws_s3_bucket_versioning" "v" { bucket = aws_s3_bucket.logged.bucket }
resource "aws_s3_bucket_versioning" "named" { bucket = "literal-name" }
resource "aws_s3_bucket" "literal" { bucket = "literal-name" }
module "remote" { ` + remoteCall + ` }
module "git" { ` + gitCall + ` }
`}, s3Keys)
	idx := dd(t, p)
	requireDefinite(t, p, idx, "./aws_s3_bucket.logged", []any{"./aws_s3_bucket_versioning.v"})
	requireDefinite(t, p, idx, "./aws_s3_bucket.literal", []any{"./aws_s3_bucket_versioning.named"})
	requireDefinite(t, p, idx, "./aws_s3_bucket.bare", nil)
	require.Nil(t, get(idx, "related", "./aws_s3_bucket.bare"))
	require.Nil(t, get(idx, "referrers", "./aws_s3_bucket.bare"))
	require.Equal(t, []any{"./aws_s3_bucket.logged"}, ids(get(idx, "targets", "./aws_s3_bucket_versioning.v", "bucket")))
	require.False(t, p.Blocks["./aws_s3_bucket_versioning.v"].RelPlaceholder)
	require.True(t, p.Blocks["./module.remote"].RelPlaceholder)
	require.True(t, p.Blocks["./module.git"].RelPlaceholder)

	require.Len(t, p.Incompleteness, 1)
	require.Equal(t, RootIncompleteness{Root: ".", Unresolved: 2, Exposed: 0, Blocks: 7}, p.Incompleteness[0])
}

// The blocks an argument reads, directly, through a local or through a value
// it shares with the call, stay incomplete; the other ones do not.
func TestUnresolvedModuleArgumentsExposeTheBlocksTheyReach(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
locals {
  via_local = aws_s3_bucket.local.bucket
  shared    = "shared-name"
}
resource "aws_s3_bucket" "direct" { bucket = "direct" }
resource "aws_s3_bucket" "local" { bucket = "local" }
resource "aws_s3_bucket" "shared" { bucket = local.shared }
resource "aws_s3_bucket" "other" { bucket = "other" }
resource "aws_s3_bucket_versioning" "v" { bucket = aws_s3_bucket.other.bucket }
module "remote" {
  ` + remoteCall + `
  bucket  = aws_s3_bucket.direct.id
  region  = "eu-west-1"
  shared  = "shared-name"
}
module "second" {
  ` + gitCall + `
  bucket = local.via_local
}
`}, s3Keys)
	idx := dd(t, p)
	requireIncomplete(t, p, idx, "./aws_s3_bucket.direct", "./module.remote")
	requireIncomplete(t, p, idx, "./aws_s3_bucket.local", "./module.second")
	requireIncomplete(t, p, idx, "./aws_s3_bucket.shared")
	requireDefinite(t, p, idx, "./aws_s3_bucket.other", []any{"./aws_s3_bucket_versioning.v"})
	require.Equal(t, RootIncompleteness{Root: ".", Unresolved: 2, Exposed: 3, Blocks: p.Incompleteness[0].Blocks}, p.Incompleteness[0])
}

// A call that reads the output of another unresolved call reads no block
// through it, and the root stays scoped.
func TestUnresolvedModulesChainedThroughOutputs(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "aws_s3_bucket" "a" { bucket = "a" }
resource "aws_s3_bucket" "b" { bucket = "b" }
module "first" {
  ` + remoteCall + `
  bucket = aws_s3_bucket.a.id
}
module "second" {
  ` + gitCall + `
  input = module.first.id
}
`}, s3Keys)
	idx := dd(t, p)
	requireIncomplete(t, p, idx, "./aws_s3_bucket.a", "./module.first")
	requireDefinite(t, p, idx, "./aws_s3_bucket.b", nil)
}

// An argument the model cannot trace to blocks leaves the whole root open.
func TestUntracedUnresolvedModuleArgumentOpensTheRoot(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "aws_s3_bucket" "a" { bucket = "a" }
resource "aws_s3_bucket" "b" { bucket = "b" }
module "remote" {
  ` + remoteCall + `
  bucket = aws_s3_bucket.missing.id
}
`}, s3Keys)
	idx := dd(t, p)
	requireIncomplete(t, p, idx, "./aws_s3_bucket.a")
	requireIncomplete(t, p, idx, "./aws_s3_bucket.b")
	require.Empty(t, p.Incompleteness)
}

// A parse failure, which can hide any block, opens the root next to a call
// that reads nothing.
func TestOtherIncompletenessOpensTheRoot(t *testing.T) {
	p := project(t, map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "a" { bucket = "a" }
module "remote" { ` + remoteCall + ` }
`,
		"broken.tf": `resource "aws_s3_bucket" "c" {`,
	}, s3Keys)
	idx := dd(t, p)
	requireIncomplete(t, p, idx, "./aws_s3_bucket.a")
}

// A nested call is scoped per module instance: its arguments reach the blocks
// of its own module and, through variables, those of the callers.
func TestNestedUnresolvedModuleScopesPerModuleInstance(t *testing.T) {
	p := project(t, map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "passed" { bucket = "passed" }
resource "aws_s3_bucket" "unrelated" { bucket = "unrelated" }
resource "aws_s3_bucket_versioning" "v" { bucket = aws_s3_bucket.unrelated.bucket }
module "child" {
  source = "./child"
  bucket = aws_s3_bucket.passed.id
  other  = "x"
}
`,
		"child/main.tf": `
variable "bucket" {}
variable "other" {}
resource "aws_s3_bucket" "inner" { bucket = "inner" }
resource "aws_s3_bucket" "inner_unrelated" { bucket = "inner-unrelated" }
resource "aws_s3_bucket_versioning" "iv" { bucket = aws_s3_bucket.inner_unrelated.bucket }
module "deep" {
  ` + gitCall + `
  bucket = aws_s3_bucket.inner.id
  passed = var.bucket
  other  = var.other
}
`,
	}, s3Keys)
	idx := dd(t, p)
	requireIncomplete(t, p, idx, "./aws_s3_bucket.passed", "./module.child")
	requireIncomplete(t, p, idx, "./module.child.aws_s3_bucket.inner", "./module.child.module.deep")
	requireDefinite(t, p, idx, "./aws_s3_bucket.unrelated", []any{"./aws_s3_bucket_versioning.v"})
	requireDefinite(t, p, idx, "./module.child.aws_s3_bucket.inner_unrelated", []any{"./module.child.aws_s3_bucket_versioning.iv"})
	require.True(t, p.Blocks["./module.child.module.deep"].RelPlaceholder)
}

// An unresolved call inside a module instance reads nothing of the root when
// the instance passes it nothing.
func TestNestedUnresolvedModuleWithoutInputsKeepsTheRootDefinite(t *testing.T) {
	p := project(t, map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "a" { bucket = "a" }
module "child" { source = "./child" }
`,
		"child/main.tf": `
module "deep" { ` + gitCall + ` }
`,
	}, s3Keys)
	idx := dd(t, p)
	requireDefinite(t, p, idx, "./aws_s3_bucket.a", nil)
}

// A root variable is an input from outside the root: passing one to an
// unresolved call exposes no block.
func TestRootVariableArgumentDoesNotOpenTheRoot(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
variable "region" {}
resource "aws_s3_bucket" "a" { bucket = "a" }
module "remote" {
  ` + remoteCall + `
  region = var.region
}
`}, s3Keys)
	require.Len(t, p.Incompleteness, 1)
	require.Equal(t, 0, p.Incompleteness[0].Exposed)
	require.Nil(t, get(dd(t, p), "referrers", "./aws_s3_bucket.a", "bucket"))
}

// A block that reads what an unresolved call returns may name a block of the
// root only when the arguments of a call reach it.
func TestReadingAnUnresolvedModuleOutputOnlyOpensTheBlocksItReaches(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "aws_s3_bucket" "passed" { bucket = "passed" }
resource "aws_s3_bucket" "other" { bucket = "other" }
resource "aws_s3_bucket_versioning" "v" { bucket = module.logs.bucket }
module "logs" {
  ` + remoteCall + `
  bucket = aws_s3_bucket.passed.id
}
`}, s3Keys)
	idx := dd(t, p)
	requireIncomplete(t, p, idx, "./aws_s3_bucket.passed", "./module.logs")
	requireDefinite(t, p, idx, "./aws_s3_bucket.other", nil)
	require.Equal(t, []any{testPlaceholder}, ids(get(idx, "targets", "./aws_s3_bucket_versioning.v", "bucket")))

	p = project(t, map[string]string{"main.tf": `
resource "aws_s3_bucket" "other" { bucket = "other" }
resource "aws_s3_bucket_versioning" "v" { bucket = module.logs.bucket }
module "logs" { ` + remoteCall + ` }
`}, s3Keys)
	requireDefinite(t, p, dd(t, p), "./aws_s3_bucket.other", nil)
}
