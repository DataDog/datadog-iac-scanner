/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/stretchr/testify/require"
)

const bucketRoot = `
resource "aws_s3_bucket" "b" {
  bucket = "logs"
}
resource "aws_s3_bucket_versioning" "v" {
  bucket = aws_s3_bucket.b.id
}
`

// projectRoots projects each root of dir on its own.
func projectRoots(t *testing.T, files map[string]string) map[string]*Projection {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	scan, err := model.Load(context.Background(), dir, model.Options{})
	require.NoError(t, err)
	out := map[string]*Projection{}
	for _, r := range scan.Roots {
		out[filepath.Base(r.Dir)] = Project([]*model.Root{r}, Options{Placeholder: testPlaceholder, LiteralKeys: s3Keys})
	}
	return out
}

func TestDigestIgnoresIDsAndDirectories(t *testing.T) {
	roots := projectRoots(t, map[string]string{
		"a/main.tf": bucketRoot,
		"b/main.tf": bucketRoot,
		"c/main.tf": bucketRoot + "\nresource \"aws_s3_bucket\" \"extra\" {}\n",
		"d/main.tf": `resource "aws_s3_bucket" "b" { bucket = "other" }`,
	})
	digest := map[string]string{}
	order := map[string][]string{}
	for name, p := range roots {
		order[name] = p.BlockOrder()
		digest[name] = p.Digest(order[name])
	}
	require.Equal(t, digest["a"], digest["b"])
	require.NotEqual(t, digest["a"], digest["c"])
	require.NotEqual(t, digest["a"], digest["d"])
	require.Len(t, order["a"], len(order["b"]))
	for i := range order["a"] {
		require.NotEqual(t, order["a"][i], order["b"][i], "ids differ between roots")
		require.Equal(t, roots["a"].Blocks[order["a"][i]].Address, roots["b"].Blocks[order["b"][i]].Address)
	}
}

func TestMergeHoldsEveryRoot(t *testing.T) {
	roots := projectRoots(t, map[string]string{"a/main.tf": bucketRoot, "b/main.tf": bucketRoot})
	merged := Merge([]*Projection{roots["a"], roots["b"]})

	require.Len(t, merged.Blocks, len(roots["a"].Blocks)+len(roots["b"].Blocks))
	d := dd(t, merged)
	require.Len(t, get(d, "blocks", "resource", "aws_s3_bucket"), 2)
	require.Len(t, get(d, "by_id"), len(merged.Blocks))
	for _, p := range roots {
		for id, loc := range p.Blocks {
			require.Same(t, loc, merged.Blocks[id])
			if loc.Type != "aws_s3_bucket" {
				continue
			}
			related := get(d, "related", id, "aws_s3_bucket_versioning", "bucket")
			require.Len(t, related, 1, "the companion of %s", id)
		}
	}
	require.Equal(t, testPlaceholder, get(d, "placeholder"))
}

func crossProject(t *testing.T, files map[string]string, keys LiteralKeys) (map[string]*Projection, map[string]*model.Root) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	scan, err := model.Load(context.Background(), dir, model.Options{})
	require.NoError(t, err)
	opts := Options{Placeholder: testPlaceholder, LiteralKeys: keys}
	idx := NewCrossIndex()
	roots := map[string]*model.Root{}
	for _, r := range scan.Roots {
		roots[filepath.Base(r.Dir)] = r
		idx.Add(Project([]*model.Root{r}, opts))
	}
	opts.Cross = idx
	out := map[string]*Projection{}
	for name, r := range roots {
		out[name] = Project([]*model.Root{r}, opts)
	}
	return out, roots
}

func relatedOf(t *testing.T, p *Projection, typ, companion, path string) []any {
	t.Helper()
	for id, loc := range p.Blocks {
		if loc.Type == typ && !p.External[id] {
			list, _ := get(dd(t, p), "related", id, companion, path).([]any)
			return list
		}
	}
	return nil
}

func TestCrossIndexDetachesTheEvidenceModule(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
provider "aws" { region = "us-east-1" }
resource "aws_s3_bucket_versioning" "v" { bucket = "acme" }
resource "aws_s3_bucket" "other" { bucket = "unrelated" }
`), 0o600))
	scan, err := model.Load(context.Background(), dir, model.Options{})
	require.NoError(t, err)
	idx := NewCrossIndex()
	idx.Add(Project(scan.Roots, Options{Placeholder: testPlaceholder, LiteralKeys: s3Keys}))
	n := 0
	for _, byPath := range idx.byKey {
		for _, byValue := range byPath {
			for _, list := range byValue {
				for _, loc := range list {
					n++
					require.NotNil(t, loc.Block.Module)
					require.Empty(t, loc.Block.Module.Blocks, "the index must not keep the evidence root's blocks")
					require.Nil(t, loc.Block.Module.Root)
				}
			}
		}
	}
	require.Positive(t, n)
}

func TestCrossIndexDropsTheProjectedTerm(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
resource "aws_s3_bucket_versioning" "v" { bucket = "acme" }
`), 0o600))
	scan, err := model.Load(context.Background(), dir, model.Options{})
	require.NoError(t, err)
	idx := NewCrossIndex()
	idx.Add(Project(scan.Roots, Options{Placeholder: testPlaceholder, LiteralKeys: s3Keys}))
	n := 0
	for _, byPath := range idx.byKey {
		for _, byValue := range byPath {
			for _, list := range byValue {
				for _, loc := range list {
					n++
					require.Nil(t, loc.Term)
					require.NotNil(t, loc.Block)
				}
			}
		}
	}
	require.NotZero(t, n)
}

func TestCrossRootLiterals(t *testing.T) {
	iam := LiteralKeys{"aws_iam_role_policy": {"role": {"aws_iam_role": {"name"}}}}
	provider := func(region string) string {
		return "provider \"aws\" {\n  region = \"" + region + "\"\n}\n"
	}
	t.Run("a global name matches in the same partition", func(t *testing.T) {
		p, _ := crossProject(t, map[string]string{
			"prod/main.tf": provider("us-east-1") + `resource "aws_s3_bucket" "b" { bucket = "acme" }`,
			"ops/main.tf":  provider("eu-west-1") + `resource "aws_s3_bucket_versioning" "v" { bucket = "acme" }`,
			"cn/main.tf":   provider("cn-north-1") + `resource "aws_s3_bucket_versioning" "v" { bucket = "acme" }`,
		}, s3Keys)
		list := relatedOf(t, p["prod"], "aws_s3_bucket", "aws_s3_bucket_versioning", "bucket")
		require.Equal(t, []any{"ops/aws_s3_bucket_versioning.v"}, list)
		require.Len(t, p["prod"].Cross, 1)
		require.Contains(t, get(dd(t, p["prod"]), "by_id"), "ops/aws_s3_bucket_versioning.v")
	})
	t.Run("another name needs the same provider configuration", func(t *testing.T) {
		p, _ := crossProject(t, map[string]string{
			"prod/main.tf": provider("us-east-1") + `resource "aws_iam_role" "r" { name = "app" }`,
			"same/main.tf": provider("us-east-1") + `resource "aws_iam_role_policy" "p" { role = "app" }`,
			"far/main.tf":  provider("eu-west-1") + `resource "aws_iam_role_policy" "p" { role = "app" }`,
		}, iam)
		list := relatedOf(t, p["prod"], "aws_iam_role", "aws_iam_role_policy", "role")
		require.Equal(t, []any{"same/aws_iam_role_policy.p"}, list)
	})
	t.Run("other credential configuration separates the accounts", func(t *testing.T) {
		group := LiteralKeys{"aws_iam_group_membership": {"group": {"aws_iam_group": {"name"}}}}
		provider := func(extra string) string {
			return "provider \"aws\" {\n  region = \"us-east-1\"\n" + extra + "\n}\n"
		}
		p, _ := crossProject(t, map[string]string{
			"prod/main.tf":  provider(`  access_key = "AKIAPROD"`) + `resource "aws_iam_group" "g" { name = "admins" }`,
			"same/main.tf":  provider(`  access_key = "AKIAPROD"`) + `resource "aws_iam_group_membership" "m" { group = "admins" }`,
			"other/main.tf": provider(`  access_key = "AKIAOTHER"`) + `resource "aws_iam_group_membership" "m" { group = "admins" }`,
			"files/main.tf": provider(`  shared_credentials_files = ["/other/credentials"]`) + `resource "aws_iam_group_membership" "m" { group = "admins" }`,
			"ids/main.tf":   provider(`  allowed_account_ids = ["222222222222"]`) + `resource "aws_iam_group_membership" "m" { group = "admins" }`,
			"var/main.tf": `variable "key" {}
` + provider(`  secret_key = var.key`) + `resource "aws_iam_group_membership" "m" { group = "admins" }`,
			"neutral/main.tf": provider(`  access_key = "AKIAPROD"
  default_tags {
    tags = { team = "x" }
  }
`) + `resource "aws_iam_group_membership" "m" { group = "admins" }`,
		}, group)
		list := relatedOf(t, p["prod"], "aws_iam_group", "aws_iam_group_membership", "group")
		require.ElementsMatch(t, []any{"same/aws_iam_group_membership.m", "neutral/aws_iam_group_membership.m"}, list)
	})
	t.Run("a companion with an unknown count gives no evidence", func(t *testing.T) {
		p, _ := crossProject(t, map[string]string{
			"prod/main.tf": `resource "aws_s3_bucket" "b" { bucket = "acme" }`,
			"ops/main.tf": `variable "n" {}
resource "aws_s3_bucket_versioning" "v" {
  count  = var.n
  bucket = "acme"
}`,
		}, s3Keys)
		require.Empty(t, relatedOf(t, p["prod"], "aws_s3_bucket", "aws_s3_bucket_versioning", "bucket"))
	})
}
