/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package contract

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

func BenchmarkBuildIntraRootRelationFanIn(b *testing.B) {
	for _, n := range []int{500, 1000, 4000} {
		b.Run(fmt.Sprintf("resources-%d", n), func(b *testing.B) {
			target := &policy.Resource{ID: "target", Type: "aws_target", ResourceKey: "aws_target"}
			sources := make([]*policy.Resource, n)
			for i := range sources {
				sources[i] = &policy.Resource{
					ID:          fmt.Sprintf("source-%d", i),
					Type:        "aws_source",
					ResourceKey: "aws_source",
				}
			}
			unit := &policy.Unit{ScopeComplete: true, Resources: append(sources, target)}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, source := range sources {
					source.Relations = nil
				}
				target.Relations = nil
				for _, source := range sources {
					addRelationEdge(unit, source, target, "target", true)
				}
				sortUnitRelations(unit)
			}
		})
	}
}

func TestRelationIDDeduplicationPreservesLegacyOutput(t *testing.T) {
	cases := []struct {
		name          string
		ids           []string
		scopeComplete bool
		completeness  []bool
	}{
		{name: "empty", scopeComplete: true},
		{name: "repeated", ids: []string{"b", "a", "b", "c", "a"}, scopeComplete: true, completeness: []bool{true, true, false, true, true}},
		{name: "incomplete-scope", ids: []string{"z", "z", "x", "y", "x"}, scopeComplete: false, completeness: []bool{true, true, true, false, true}},
		{name: "single", ids: []string{"only"}, scopeComplete: true, completeness: []bool{false}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got, legacy policy.RelationList
			for i, id := range tc.ids {
				complete := tc.completeness[i]
				got = appendRelationID(got, i > 0, id, tc.scopeComplete, complete)
				legacy = appendLegacyRelationID(legacy, i > 0, id, tc.scopeComplete, complete)
			}
			got.IDs = sortUniqueRelationIDs(got.IDs)
			sort.Strings(legacy.IDs)
			require.Equal(t, legacy, got)
		})
	}
}

func appendLegacyRelationID(list policy.RelationList, exists bool, id string, scopeComplete, complete bool) policy.RelationList {
	if !exists {
		list.Complete = scopeComplete
	}
	for _, existing := range list.IDs {
		if existing == id {
			list.Complete = list.Complete && complete
			return list
		}
	}
	list.IDs = append(list.IDs, id)
	list.Complete = list.Complete && complete
	return list
}

func TestBuildIntraRootRelationsHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resource := &policy.Resource{ID: "source", Type: "aws_source", ResourceKey: "aws_source"}
	unit := &policy.Unit{ScopeComplete: true, Resources: []*policy.Resource{resource}}
	metas := []*hclResourceMeta{{res: resource}}

	buildIntraRootRelations(ctx, unit, metas, nil, nil)

	require.Nil(t, resource.Relations)
}

// countingCancelCtx is canceled by its cancelAt-th Err() call.
type countingCancelCtx struct {
	context.Context
	cancel   context.CancelFunc
	cancelAt int
	calls    int
}

func newCountingCancelCtx(cancelAt int) *countingCancelCtx {
	ctx, cancel := context.WithCancel(context.Background())
	return &countingCancelCtx{Context: ctx, cancel: cancel, cancelAt: cancelAt}
}

func (c *countingCancelCtx) Err() error {
	c.calls++
	if c.calls >= c.cancelAt {
		c.cancel()
	}
	return c.Context.Err()
}

func wideRelationBody(t *testing.T, attrs int) *hclsyntax.Body {
	t.Helper()
	var src strings.Builder
	src.WriteString("resource \"aws_source\" \"wide\" {\n")
	for i := range attrs {
		fmt.Fprintf(&src, "  a%d = [aws_target.t.id, \"literal-%d\"]\n", i, i)
	}
	src.WriteString("}\n")
	file, diags := hclsyntax.ParseConfig([]byte(src.String()), "wide.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), "%s", diags.Error())
	return file.Body.(*hclsyntax.Body).Blocks[0].Body
}

// Once the context is canceled mid-walk, the relation walkers must not visit
// the events that remain, whichever walker runs, and a structural walk whose
// collection was canceled must not be cached (or marked uncacheable).
func TestRelationWalkStopsWhenCanceledMidBuild(t *testing.T) {
	const attrs = 500
	body := wideRelationBody(t, attrs)
	getEvalCtx := func() *hcl.EvalContext { return &hcl.EvalContext{} }
	full := 0
	walkBodyAttrRefs(context.Background(), body, nil, "", getEvalCtx, false,
		func(string, hcl.Expression, func() *hcl.EvalContext, bool) { full++ }, nil)
	require.Equal(t, 3*attrs, full, "each attribute and its two tuple elements are events")

	for _, tc := range []struct {
		name          string
		cache         func() *relationWalkCache
		uncertainOnly bool
	}{
		{name: "cached walk", cache: func() *relationWalkCache {
			cache := newRelationWalkCache()
			_, ok := cache.events(context.Background(), body)
			require.True(t, ok)
			return cache
		}},
		{name: "uncached walk", cache: func() *relationWalkCache { return nil }},
		{name: "uncertain-only walk", cache: newRelationWalkCache, uncertainOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			visited := 0
			walkBodyAttrRefsCached(ctx, tc.cache(), body, nil, "", getEvalCtx, tc.uncertainOnly,
				func(string, hcl.Expression, func() *hcl.EvalContext, bool) {
					visited++
					cancel() // traversal has started
				}, nil)
			require.Equal(t, 1, visited, "no event after the cancellation may be visited")
		})
	}

	t.Run("cache construction", func(t *testing.T) {
		cache := newRelationWalkCache()
		ctx := newCountingCancelCtx(10)
		visited := 0
		walkBodyAttrRefsCached(ctx, cache, body, nil, "", getEvalCtx, false,
			func(string, hcl.Expression, func() *hcl.EvalContext, bool) { visited++ }, nil)
		require.Zero(t, visited, "a canceled collection must not fall back to the uncached walker")
		require.Less(t, ctx.calls, 20, "collection must stop at the first check that sees the cancellation")
		require.Empty(t, cache.byBody, "a partial structural walk must not be cached")
		require.Empty(t, cache.uncacheable, "a canceled collection says nothing about cacheability")
		events, ok := cache.events(context.Background(), body)
		require.True(t, ok)
		require.Len(t, events, 3*attrs)
	})
}

// A cancellation that arrives while the builder walks one very large body
// stops that walk instead of finishing it.
func TestBuildIntraRootRelationsStopsInsideLargeBody(t *testing.T) {
	const attrs = 10000
	resource := &policy.Resource{ID: "aws_source.wide", Type: "aws_source", ResourceKey: "aws_source", Kind: address.KindResource}
	unit := &policy.Unit{ScopeComplete: true, Resources: []*policy.Resource{resource}}
	metas := []*hclResourceMeta{{res: resource, body: wideRelationBody(t, attrs)}}
	ctx := newCountingCancelCtx(4) // after the entry and per-loop checks

	buildIntraRootRelations(ctx, unit, metas, nil, nil)

	require.Less(t, ctx.calls, 20, "the builder must return promptly, not after walking all %d attributes", attrs)
}

func TestEvaluateRootMarksDroppedConfigurationIncomplete(t *testing.T) {
	fs := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf":   []byte(`resource "aws_s3_bucket" "b" { bucket = "logs" }`),
		"/repo/broken.tf": []byte("{{ broken }}"),
	})
	unit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(fs), "/repo", &RootOptions{FS: fs, RepoPath: "/repo"})
	require.NoError(t, err)
	require.False(t, unit.ScopeComplete, "a skipped Terraform configuration file cannot establish absence")
}

func TestEvaluateRootContractV2Features(t *testing.T) {
	fs := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
variable "unknown_enc" {}
variable "unknown_cidr" {}

provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      Team = "security"
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "logs" {
  bucket = "app-logs"
  acl    = null

  versioning {
    enabled = false
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "disabled" {
  count  = 0
  bucket = "never-created"
}

resource "aws_rds_cluster" "db" {
  storage_encrypted = var.unknown_enc
}

resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = ["0.0.0.0/0", var.unknown_cidr]
  }
}

resource "aws_kms_key" "k" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "kms:*"
      Resource  = "*"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
    }]
  })
}

resource "aws_cloudwatch_log_metric_filter" "f" {
  name    = "unauth"
  pattern = "{ $.errorCode = \"*UnauthorizedOperation\" }"
}
`),
	})

	eval := tfeval.NewWithFS(fs)
	unit, err := EvaluateRoot(context.Background(), eval, "/repo", &RootOptions{
		FS:               fs,
		RepoPath:         "/repo",
		ComputeRelations: true,
		NeedProviders:    true,
		Derive:           DeriveOptions{ParseJSON: true, ParseFilterAST: true},
	})
	require.NoError(t, err)
	require.True(t, unit.ScopeComplete)

	byAddr := map[string]*policy.Resource{}
	for _, r := range unit.Resources {
		byAddr[r.Address] = r
	}

	// 1. count = 0 resource is omitted.
	require.NotContains(t, byAddr, "aws_s3_bucket.disabled")

	// 2. Nested blocks are always arrays; null is tracked in State.Null; BeforeValue works.
	bucket := byAddr["aws_s3_bucket.logs"]
	require.NotNil(t, bucket)
	versioning, ok := bucket.Attributes["versioning"].([]any)
	require.True(t, ok, "single nested block must normalize to array")
	require.Len(t, versioning, 1)
	require.True(t, bucket.State.Null["acl"])
	require.NotContains(t, bucket.Attributes, "acl")
	before, hasBefore := bucket.Source.BeforeValue(policy.Path{policy.Key("versioning"), policy.Index(0), policy.Key("enabled")})
	require.True(t, hasBefore)
	require.Equal(t, "false", before)
	// Provider binding resolves to default aws provider.
	tfMeta := bucket.Platform["terraform"].(map[string]any)
	require.NotEmpty(t, tfMeta["provider_id"])

	// 3. Unknown attributes are omitted from Attributes (no sentinel string) and recorded in State.Unknown.
	rds := byAddr["aws_rds_cluster.db"]
	require.NotNil(t, rds)
	require.NotContains(t, rds.Attributes, "storage_encrypted")
	require.True(t, rds.State.Unknown["storage_encrypted"])
	require.True(t, rds.State.Written["storage_encrypted"])
	// Dynamic expression yields no literal BeforeValue (never drops finding).
	_, hasDynBefore := rds.Source.BeforeValue(policy.Path{policy.Key("storage_encrypted")})
	require.False(t, hasDynBefore)

	// 4. Closed lists with unknown elements preserve exact indices via UnknownSlot without marking list size incomplete.
	sg := byAddr["aws_security_group.sg"]
	require.NotNil(t, sg)
	ing := sg.Attributes["ingress"].([]any)[0].(map[string]any)
	require.Equal(t, []any{"0.0.0.0/0", policy.UnknownSlot()}, ing["cidr_blocks"])
	require.False(t, sg.State.IncompleteCollections["ingress.0.cidr_blocks"], "closed list has known length")
	require.True(t, sg.State.Unknown["ingress.0.cidr_blocks.1"])

	// 5. Intra-root relations link companion <-> target with Complete = true.
	require.NotNil(t, bucket.Relations)
	rel := bucket.Relations.Related["aws_s3_bucket_versioning"]["bucket"]
	require.True(t, rel.Complete)
	require.Len(t, rel.IDs, 1)

	// 6. jsonencode parses known leaves and attaches typed json_refs without regexes.
	kms := byAddr["aws_kms_key.k"]
	require.NotNil(t, kms)
	require.NotNil(t, kms.Derived)
	require.NotNil(t, kms.Derived.JSON["policy"])
	require.True(t, kms.Derived.JSONUnknown["policy"]["Statement.0.Principal.AWS"])
	refs := kms.Derived.JSONRefs["policy"]["Statement.0.Principal.AWS"]
	require.Len(t, refs, 1)
	require.Equal(t, "data", refs[0].Kind)
	require.Equal(t, "aws_caller_identity", refs[0].Type)
	require.Equal(t, "account_id", refs[0].Attr)

	// 7. CloudWatch metric filter AST derived on demand.
	cw := byAddr["aws_cloudwatch_log_metric_filter.f"]
	require.NotNil(t, cw)
	require.NotNil(t, cw.Derived)
	require.NotNil(t, cw.Derived.FilterExpr["pattern"])
}

func TestBuildUnitFromPlanUnifiedShape(t *testing.T) {
	planJSON := []byte(`{
  "format_version": "1.2",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.logs",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "logs",
          "values": {
            "bucket": "plan-logs",
            "tags_all": {"Team": "core"}
          }
        },
        {
          "address": "aws_s3_bucket_versioning.logs",
          "mode": "managed",
          "type": "aws_s3_bucket_versioning",
          "name": "logs",
          "values": {
            "versioning_configuration": [{"status": "Suspended"}]
          }
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_s3_bucket_versioning.logs",
      "change": {
        "actions": ["create"],
        "after_unknown": {"bucket": true}
      }
    }
  ],
  "configuration": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.logs",
          "expressions": {"bucket": {"constant_value": "plan-logs"}}
        },
        {
          "address": "aws_s3_bucket_versioning.logs",
          "expressions": {
            "bucket": {"references": ["aws_s3_bucket.logs.id"]},
            "versioning_configuration": [{"status": {"constant_value": "Suspended"}}]
          }
        }
      ]
    }
  }
}`)

	unit, err := BuildUnitFromPlan("/repo/tfplan.json", planJSON, &RootOptions{
		RepoPath:         "/repo",
		ComputeRelations: true,
		Derive:           DeriveOptions{ParseJSON: true},
	})
	require.NoError(t, err)
	require.True(t, unit.ScopeComplete)
	require.Len(t, unit.Resources, 2)

	var bucket, ver *policy.Resource
	for _, r := range unit.Resources {
		switch r.Address {
		case "aws_s3_bucket.logs":
			bucket = r
		case "aws_s3_bucket_versioning.logs":
			ver = r
		}
	}
	require.NotNil(t, bucket)
	require.NotNil(t, ver)
	// Plan-computed tags_all goes to platform.terraform.computed, not written Attributes.
	require.NotContains(t, bucket.Attributes, "tags_all")
	computed := bucket.Platform["terraform"].(map[string]any)["computed"].(map[string]any)
	require.Equal(t, map[string]any{"Team": "core"}, computed["tags_all"])
	// after_unknown marks bucket as unknown while configuration.expressions still resolves relation!
	require.True(t, ver.State.Unknown["bucket"])
	rel := bucket.Relations.Related["aws_s3_bucket_versioning"]["bucket"]
	require.True(t, rel.Complete)
	require.Equal(t, []string{ver.ID}, rel.IDs)
}

func TestEvaluateRootIndexPreservationProvidersAndDerivations(t *testing.T) {
	fs := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
variable "unk" {}
variable "unk_role" {}

provider "aws" {
  region = "us-east-1"
}

provider "aws" {
  alias  = "west"
  region = "us-west-2"
}

module "child" {
  source    = "./modules/child"
  providers = { aws = aws.west }
}

resource "aws_security_group" "mixed" {
  dynamic "ingress" {
    for_each = [80, 443]
    content {
      from_port   = ingress.value
      cidr_blocks = [var.unk, "0.0.0.0/0"]
    }
  }
  ingress {
    from_port   = 22
    cidr_blocks = [var.unk, "0.0.0.0/0"]
  }
}

locals {
  key_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      var.unk,
      {
        Effect    = "Allow"
        Action    = "kms:*"
        Resource  = "*"
        Principal = { AWS = "*" }
      }
    ]
  })
}

data "aws_iam_policy_document" "partial" {
  statement {
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [var.unk_role, "*"]
    }
  }
}

resource "aws_kms_key" "via_local" {
  policy = local.key_policy
}

resource "aws_kms_key" "via_data" {
  policy = data.aws_iam_policy_document.partial.json
}
`),
		"/repo/modules/child/main.tf": []byte(`
resource "aws_s3_bucket" "child_bucket" {
  bucket = "child-bucket"
}
`),
	})

	eval := tfeval.NewWithFS(fs)
	unit, err := EvaluateRoot(context.Background(), eval, "/repo", &RootOptions{
		FS:            fs,
		RepoPath:      "/repo",
		NeedProviders: true,
		Derive:        DeriveOptions{ParseJSON: true},
	})
	require.NoError(t, err)

	byAddr := map[string]*policy.Resource{}
	for _, r := range unit.Resources {
		byAddr[r.Address] = r
	}

	// 1. Provider remapping resolves child resource to aliased aws.west provider.
	childBucket := byAddr["module.child.aws_s3_bucket.child_bucket"]
	require.NotNil(t, childBucket)
	pid := childBucket.Platform["terraform"].(map[string]any)["provider_id"].(string)
	require.NotEmpty(t, pid)
	prov := unit.ByID[pid]
	require.NotNil(t, prov)
	require.Equal(t, "us-west-2", prov.Attributes["region"])

	// 2. Dynamic-before-static BeforeValue aligns indices accurately and preserves list indices.
	sg := byAddr["aws_security_group.mixed"]
	require.NotNil(t, sg)
	_, dynHasBefore := sg.Source.BeforeValue(policy.Path{policy.Key("ingress"), policy.Index(0), policy.Key("from_port")})
	require.False(t, dynHasBefore, "generated dynamic block must not borrow static block literal")
	staticBefore, staticHasBefore := sg.Source.BeforeValue(policy.Path{policy.Key("ingress"), policy.Index(2), policy.Key("from_port")})
	require.True(t, staticHasBefore)
	require.Equal(t, "22", staticBefore)
	ing2 := sg.Attributes["ingress"].([]any)[2].(map[string]any)
	require.Equal(t, []any{policy.UnknownSlot(), "0.0.0.0/0"}, ing2["cidr_blocks"])

	// 3. local.* jsonencode follows local alias and preserves Statement index 1 after unknown Statement 0.
	kmsLocal := byAddr["aws_kms_key.via_local"]
	require.NotNil(t, kmsLocal.Derived)
	polDoc := kmsLocal.Derived.JSON["policy"].(map[string]any)
	stmts := polDoc["Statement"].([]any)
	require.Len(t, stmts, 2)
	require.True(t, policy.IsUnknownSlot(stmts[0]))
	require.Equal(t, "Allow", stmts[1].(map[string]any)["Effect"])

	// 4. data.aws_iam_policy_document.*.json with unknown identifier derives partial policy JSON.
	kmsData := byAddr["aws_kms_key.via_data"]
	require.NotNil(t, kmsData.Derived)
	dataDoc := kmsData.Derived.JSON["policy"].(map[string]any)
	dataStmts := dataDoc["Statement"].([]any)
	require.Len(t, dataStmts, 1)
	awsPrincipals := dataStmts[0].(map[string]any)["Principal"].(map[string]any)["AWS"].([]any)
	require.Equal(t, []any{policy.UnknownSlot(), "*"}, awsPrincipals)
}

func TestBuildUnitFromPlanParityHardening(t *testing.T) {
	// Sorted JSON: configuration appears before planned_values; includes nested
	// after_unknown, provider_config, for_each module instance, empty expressions,
	// removed data source in prior_state, indexed refs, and unknown companion.
	planJSON := []byte(`{
  "configuration": {
    "provider_config": {
      "aws": { "name": "aws", "expressions": { "region": { "constant_value": "us-east-1" } } }
    },
    "root_module": {
      "module_calls": {
        "app": {
          "module": {
            "resources": [
              {
                "address": "aws_s3_bucket.mod_bucket",
                "provider_config_key": "aws",
                "expressions": { "bucket": { "constant_value": "mod-logs" } }
              },
              {
                "address": "aws_s3_bucket_versioning.mod_ver",
                "expressions": { "bucket": { "references": ["aws_s3_bucket.mod_bucket.id"] } }
              }
            ]
          }
        }
      },
      "resources": [
        {
          "address": "aws_s3_bucket.nested_unk",
          "provider_config_key": "aws",
          "expressions": {
            "versioning": [{ "enabled": { "references": ["var.unk"] } }],
            "tags": { "references": ["var.tags"] }
          }
        },
        {
          "address": "aws_s3_bucket.empty_cfg",
          "expressions": {}
        },
        {
          "address": "aws_s3_bucket.arr",
          "expressions": { "bucket": { "constant_value": "arr" } }
        },
        {
          "address": "aws_s3_bucket_versioning.arr0",
          "expressions": { "bucket": { "references": ["aws_s3_bucket.arr[0].id"] } }
        },
        {
          "address": "aws_s3_bucket_versioning.unk_comp",
          "expressions": { "bucket": { "references": ["var.target_bucket"] } }
        }
      ]
    }
  },
  "format_version": "1.2",
  "planned_values": {
    "root_module": {
      "child_modules": [
        {
          "address": "module.app[\"prod\"]",
          "resources": [
            {
              "address": "module.app[\"prod\"].aws_s3_bucket.mod_bucket",
              "mode": "managed",
              "type": "aws_s3_bucket",
              "name": "mod_bucket",
              "values": { "bucket": "mod-logs", "arn": "arn:aws:s3:::mod-logs" }
            },
            {
              "address": "module.app[\"prod\"].aws_s3_bucket_versioning.mod_ver",
              "mode": "managed",
              "type": "aws_s3_bucket_versioning",
              "name": "mod_ver",
              "values": {}
            }
          ]
        }
      ],
      "resources": [
        {
          "address": "aws_s3_bucket.nested_unk",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "nested_unk",
          "values": { "versioning": [{ "enabled": false }], "tags": { "Env": "placeholder" } }
        },
        {
          "address": "aws_s3_bucket.empty_cfg",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "empty_cfg",
          "values": { "arn": "arn:aws:s3:::empty" }
        },
        {
          "address": "aws_s3_bucket.arr[0]",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "arr",
          "values": { "bucket": "arr-0" }
        },
        {
          "address": "aws_s3_bucket.arr[1]",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "arr",
          "values": { "bucket": "arr-1" }
        },
        {
          "address": "aws_s3_bucket_versioning.arr0",
          "mode": "managed",
          "type": "aws_s3_bucket_versioning",
          "name": "arr0",
          "values": {}
        },
        {
          "address": "aws_s3_bucket_versioning.unk_comp",
          "mode": "managed",
          "type": "aws_s3_bucket_versioning",
          "name": "unk_comp",
          "values": {}
        }
      ]
    }
  },
  "prior_state": {
    "values": {
      "root_module": {
        "resources": [
          {
            "address": "data.aws_s3_bucket.removed_data",
            "mode": "data",
            "type": "aws_s3_bucket",
            "name": "removed_data",
            "values": { "bucket": "old" }
          }
        ]
      }
    }
  },
  "resource_changes": [
    {
      "address": "aws_s3_bucket.nested_unk",
      "change": {
        "actions": ["create"],
        "after_unknown": { "versioning": [{ "enabled": true }], "tags": { "Env": true } }
      }
    },
    {
      "address": "aws_s3_bucket_versioning.unk_comp",
      "change": {
        "actions": ["create"],
        "after_unknown": { "bucket": true }
      }
    }
  ]
}`)

	unit, err := BuildUnitFromPlan("/repo/plan.json", planJSON, &RootOptions{
		RepoPath:         "/repo",
		ComputeRelations: true,
	})
	require.NoError(t, err)

	byAddr := map[string]*policy.Resource{}
	for _, r := range unit.Resources {
		byAddr[r.Address] = r
	}

	// 1. Nested after_unknown stripped from Attributes at every depth.
	nested := byAddr["aws_s3_bucket.nested_unk"]
	require.NotNil(t, nested)
	ver0 := nested.Attributes["versioning"].([]any)[0].(map[string]any)
	require.NotContains(t, ver0, "enabled")
	require.True(t, nested.State.Unknown["versioning.0.enabled"])
	require.NotContains(t, nested.Attributes["tags"].(map[string]any), "Env")
	require.True(t, nested.State.Unknown["tags.Env"])
	// Span points into planned_values (line > 50), not configuration!
	require.Greater(t, nested.Source.BlockSpan.StartLine, 50)
	// Provider block created and linked.
	require.NotEmpty(t, nested.Platform["terraform"].(map[string]any)["provider_id"])

	// 2. for_each module instance strips module key to match configuration.expressions & keeps arn in computed.
	modB := byAddr[`module.app["prod"].aws_s3_bucket.mod_bucket`]
	require.NotNil(t, modB)
	require.NotContains(t, modB.Attributes, "arn")
	require.NotNil(t, modB.Relations)
	require.Len(t, modB.Relations.Related["aws_s3_bucket_versioning"]["bucket"].IDs, 1)

	// 3. Empty config keeps computed arn out of written Attributes; removed data not resurrected.
	require.NotContains(t, byAddr["aws_s3_bucket.empty_cfg"].Attributes, "arn")
	require.NotContains(t, byAddr, "data.aws_s3_bucket.removed_data")

	// 4. Indexed ref arr[0] links ONLY arr[0], NOT arr[1]; unk_comp marks arr[1] incomplete!
	require.Len(t, byAddr["aws_s3_bucket.arr[0]"].Relations.Related["aws_s3_bucket_versioning"]["bucket"].IDs, 1)
	arr1Rel := byAddr["aws_s3_bucket.arr[1]"].Relations.Related["aws_s3_bucket_versioning"]["bucket"]
	require.Empty(t, arr1Rel.IDs)
	require.False(t, arr1Rel.Complete)
}

func TestContractV2DerivesJSONAfterExpandedDynamicBlocks(t *testing.T) {
	findRole := func(t *testing.T, unit *policy.Unit) *policy.Resource {
		t.Helper()
		for _, resource := range unit.Resources {
			if resource.Address == "aws_iam_role.r" {
				return resource
			}
		}
		require.FailNow(t, "aws_iam_role.r not found")
		return nil
	}
	t.Run("hcl", func(t *testing.T) {
		fs := vfs.NewMemFS(map[string][]byte{"/repo/main.tf": []byte(`
variable "acct" {}
resource "aws_iam_role" "r" {
  dynamic "inline_policy" {
    for_each = ["a"]
    content {
      name = "dynamic"
      policy = jsonencode({ Statement = [{ Principal = { AWS = var.acct }, Action = "s3:GetObject" }] })
    }
  }
  inline_policy {
    name = "static"
    policy = jsonencode({ Statement = [{ Principal = { AWS = var.acct }, Action = "*" }] })
  }
}
`)})
		unit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(fs), "/repo", &RootOptions{
			FS: fs, RepoPath: "/repo", ComputeRelations: true, Derive: DeriveOptions{ParseJSON: true},
		})
		require.NoError(t, err)
		role := findRole(t, unit)
		require.NotNil(t, role.Derived)
		require.True(t, role.Derived.JSONUnknown["inline_policy.1.policy"]["Statement.0.Principal.AWS"], "%v", role.Derived.JSONUnknown)
		require.False(t, role.Derived.JSONUnknown["inline_policy.0.policy"]["Statement.0.Principal.AWS"], "%v", role.Derived.JSONUnknown)
	})

	// Every derived JSON document and template under inline_policy.<i> must
	// describe block <i> itself, whichever adapter produced the unit.
	actionByName := map[string]string{"dynamic": "s3:GetObject", "static": "*"}
	requireDerivedOnOwnBlock := func(t *testing.T, role *policy.Resource, wantDocs int) {
		t.Helper()
		require.NotNil(t, role.Derived)
		blocks, _ := role.Attributes["inline_policy"].([]any)
		docs := 0
		for i, raw := range blocks {
			block, _ := raw.(map[string]any)
			name, _ := block["name"].(string)
			prefix := fmt.Sprintf("inline_policy.%d.", i)
			if doc, ok := role.Derived.JSON[prefix+"policy"].(map[string]any); ok {
				docs++
				require.Equal(t, actionByName[name], doc["Action"], "JSON document of block %d (%s): %v", i, name, role.Derived.JSON)
			}
			for path, parts := range role.Derived.TemplateParts {
				if !strings.HasPrefix(path, prefix) {
					continue
				}
				require.Len(t, parts, 1, path)
				require.Equal(t, block[strings.TrimPrefix(path, prefix)], parts[0].Value, "template %s of block %d (%s)", path, i, name)
			}
		}
		require.Equal(t, wantDocs, docs, "%v", role.Derived.JSON)
	}
	t.Run("tf.json", func(t *testing.T) {
		fs := vfs.NewMemFS(map[string][]byte{"/repo/main.tf.json": []byte(`{"resource": {"aws_iam_role": {"r": {
  "dynamic": {"inline_policy": {"for_each": ["a"], "content": {"name": "dynamic", "policy": "{\"Action\":\"s3:GetObject\"}"}}},
  "inline_policy": [{"name": "static", "policy": "{\"Action\":\"*\"}"}]
}}}}`)})
		unit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(fs), "/repo", &RootOptions{
			FS: fs, RepoPath: "/repo", ComputeRelations: true, Derive: DeriveOptions{ParseJSON: true},
		})
		require.NoError(t, err)
		requireDerivedOnOwnBlock(t, findRole(t, unit), 1)
	})

	// Plan configuration omits dynamic blocks, so the single configured block
	// is the second planned element.
	const configured = `"inline_policy": [{"name": {"constant_value": "static"}, "policy": {"constant_value": "{\"Action\":\"*\"}"}}]`
	const static = `{"name": "static", "policy": "{\"Action\":\"*\"}"}`
	for _, tc := range []struct {
		name, dynamic, dynamicUnknown string
		wantDocs                      int
	}{
		{name: "plan", dynamic: `{"name": "dynamic", "policy": "{\"Action\":\"s3:GetObject\"}"}`, dynamicUnknown: `{}`, wantDocs: 2},
		{name: "plan with unknown dynamic policy", dynamic: `{"name": "dynamic"}`, dynamicUnknown: `{"policy": true}`, wantDocs: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := `{"inline_policy": [` + tc.dynamic + `, ` + static + `]}`
			planJSON := []byte(`{"format_version": "1.2",
"configuration": {"root_module": {"resources": [{"address": "aws_iam_role.r", "expressions": {` + configured + `}}]}},
"planned_values": {"root_module": {"resources": [{"address": "aws_iam_role.r", "mode": "managed", "type": "aws_iam_role", "name": "r", "values": ` + values + `}]}},
"resource_changes": [{"address": "aws_iam_role.r", "mode": "managed", "type": "aws_iam_role", "name": "r", "change": {"actions": ["create"],
  "after": ` + values + `, "after_unknown": {"inline_policy": [` + tc.dynamicUnknown + `, {}]}}}]}`)
			unit, err := BuildUnitFromPlan("/repo/plan.json", planJSON, &RootOptions{RepoPath: "/repo", Derive: DeriveOptions{ParseJSON: true}})
			require.NoError(t, err)
			role := findRole(t, unit)
			requireDerivedOnOwnBlock(t, role, tc.wantDocs)
			blocks, _ := role.Attributes["inline_policy"].([]any)
			require.Len(t, blocks, 2)
			dynamicBlock, _ := blocks[0].(map[string]any)
			require.Equal(t, "dynamic", dynamicBlock["name"])
			if tc.wantDocs == 1 {
				require.NotContains(t, dynamicBlock, "policy", "the static block's literal must not fill the dynamic block's unknown policy")
			}
		})
	}
}

// A planned nested element that no configuration block matches (Plan
// configuration omits dynamic blocks) may have been written; its unknown
// leaves must stay unknown instead of reading as unset provider defaults.
func TestContractV2PlanUnmatchedNestedElementsKeepUnknowns(t *testing.T) {
	for _, tc := range []struct {
		name, configured, values, afterUnknown string
		wantBlocks                             int
		wantUnknown, wantNotUnknown            []string
		// When set, the JSON of the inline_policy attribute and of its
		// provider-computed siblings, and the written leaf paths.
		wantAttrs, wantComputed string
		wantWritten             []string
	}{
		{
			name:         "dynamic block before a static block",
			configured:   `[{"name": {"constant_value": "static"}, "policy": {"constant_value": "{}"}}]`,
			values:       `[{"name": "dynamic"}, {"name": "static", "policy": "{}"}]`,
			afterUnknown: `[{"policy": true}, {}]`,
			wantBlocks:   2,
			wantUnknown:  []string{"inline_policy.0.policy"},
		},
		{
			// Without identity fields neither element can be tied to the
			// configured block, so both keep their unknowns.
			name:         "element past the configured count",
			configured:   `[{"name": {"references": ["var.name"]}}]`,
			values:       `[{"name": "a"}, {"name": "b"}]`,
			afterUnknown: `[{"policy": true}, {"policy": true}]`,
			wantBlocks:   2,
			wantUnknown:  []string{"inline_policy.0.policy", "inline_policy.1.policy"},
		},
		{
			name:           "matched element keeps provider-computed unknowns computed",
			configured:     `[{"name": {"constant_value": "static"}}]`,
			values:         `[{"name": "static"}]`,
			afterUnknown:   `[{"policy": true}]`,
			wantBlocks:     1,
			wantNotUnknown: []string{"inline_policy.0.policy"},
		},
		{
			// A static block written only with references, next to a dynamic
			// one: neither element can be tied to the configured block. Only
			// the fields configuration writes stay configured; provider
			// defaults are computed, so is_false must not see a configured
			// false and is_unset still sees an unset field.
			name:         "unmatched elements keep provider defaults computed",
			configured:   `[{"name": {"references": ["var.name"]}}]`,
			values:       `[{"name": "a", "description": "", "enabled": false}, {"name": "b", "description": "", "enabled": true}]`,
			afterUnknown: `[{}, {}]`,
			wantBlocks:   2,
			wantAttrs:    `[{"name": "a"}, {"name": "b"}]`,
			wantComputed: `[{"description": "", "enabled": false}, {"description": "", "enabled": true}]`,
			wantWritten:  []string{"inline_policy.0.name", "inline_policy.1.name"},
		},
		{
			name:           "unmatched element keeps unknowns written and known defaults computed",
			configured:     `[{"name": {"references": ["var.name"]}}]`,
			values:         `[{"name": "a", "enabled": false}, {"name": "b", "enabled": false}]`,
			afterUnknown:   `[{"policy": true}, {"policy": true}]`,
			wantBlocks:     2,
			wantUnknown:    []string{"inline_policy.0.policy", "inline_policy.1.policy"},
			wantNotUnknown: []string{"inline_policy.0.enabled", "inline_policy.1.enabled"},
			wantAttrs:      `[{"name": "a"}, {"name": "b"}]`,
			wantComputed:   `[{"enabled": false}, {"enabled": false}]`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := `{"inline_policy": ` + tc.values + `}`
			planJSON := []byte(`{"format_version": "1.2",
"configuration": {"root_module": {"resources": [{"address": "aws_iam_role.r", "expressions": {"inline_policy": ` + tc.configured + `}}]}},
"planned_values": {"root_module": {"resources": [{"address": "aws_iam_role.r", "mode": "managed", "type": "aws_iam_role", "name": "r", "values": ` + values + `}]}},
"resource_changes": [{"address": "aws_iam_role.r", "mode": "managed", "type": "aws_iam_role", "name": "r", "change": {"actions": ["create"],
  "after": ` + values + `, "after_unknown": {"inline_policy": ` + tc.afterUnknown + `}}}]}`)
			unit, err := BuildUnitFromPlan("/repo/plan.json", planJSON, &RootOptions{RepoPath: "/repo"})
			require.NoError(t, err)
			require.Len(t, unit.Resources, 1)
			role := unit.Resources[0]
			blocks, _ := role.Attributes["inline_policy"].([]any)
			require.Len(t, blocks, tc.wantBlocks)
			for _, path := range tc.wantUnknown {
				require.True(t, role.State.Unknown[path], "%s: %v", path, role.State.Unknown)
			}
			for _, path := range tc.wantNotUnknown {
				require.False(t, role.State.Unknown[path], "%s: %v", path, role.State.Unknown)
			}
			if tc.wantAttrs != "" {
				attrs, err := json.Marshal(blocks)
				require.NoError(t, err)
				require.JSONEq(t, tc.wantAttrs, string(attrs))
			}
			if tc.wantComputed != "" {
				tf, _ := role.Platform["terraform"].(map[string]any)
				computed, _ := tf["computed"].(map[string]any)
				got, err := json.Marshal(computed["inline_policy"])
				require.NoError(t, err)
				require.JSONEq(t, tc.wantComputed, string(got))
			}
			for _, path := range tc.wantWritten {
				require.True(t, role.State.Written[path], "%s: %v", path, role.State.Written)
			}
		})
	}
}

// .tf.json bodies are converted without a schema, so dynamic blocks are not
// expanded there. The generated collection must stay open: absence and
// collection proofs over it cannot succeed.
func TestContractV2JSONDynamicBlocksKeepCollectionsOpen(t *testing.T) {
	for _, tc := range []struct {
		name, resource, address string
		wantOpen                []string
		wantUnknown             []string
		wantClosed              []string
	}{
		{
			name:     "dynamic before static",
			address:  "aws_iam_role.r",
			resource: `"aws_iam_role": {"r": {"dynamic": {"inline_policy": {"for_each": ["a"], "content": {"name": "dynamic"}}}, "inline_policy": [{"name": "static"}]}}`,
			wantOpen: []string{"inline_policy"},
		},
		{
			name:        "dynamic only",
			address:     "aws_iam_role.r",
			resource:    `"aws_iam_role": {"r": {"dynamic": {"inline_policy": {"for_each": ["a"], "content": {"name": "dynamic"}}}}}`,
			wantOpen:    []string{"inline_policy"},
			wantUnknown: []string{"inline_policy"},
		},
		{
			name:     "content uses the iterator",
			address:  "aws_iam_role.r",
			resource: `"aws_iam_role": {"r": {"dynamic": {"inline_policy": {"for_each": "${var.names}", "content": {"name": "${inline_policy.value}"}}}, "inline_policy": [{"name": "static"}]}}`,
			wantOpen: []string{"inline_policy"},
		},
		{
			name:        "list form and several generated types",
			address:     "aws_security_group.sg",
			resource:    `"aws_security_group": {"sg": {"dynamic": {"ingress": [{"for_each": [1], "content": {"from_port": 1}}], "egress": {"for_each": [1], "content": {"from_port": 2}}}}}`,
			wantOpen:    []string{"ingress", "egress"},
			wantUnknown: []string{"ingress", "egress"},
		},
		{
			name:        "dynamic inside a nested block",
			address:     "aws_s3_bucket.b",
			resource:    `"aws_s3_bucket": {"b": {"lifecycle_rule": [{"id": "a", "dynamic": {"transition": {"for_each": [30], "content": {"days": 30}}}}]}}`,
			wantOpen:    []string{"lifecycle_rule.0.transition"},
			wantUnknown: []string{"lifecycle_rule.0.transition"},
			wantClosed:  []string{"lifecycle_rule"},
		},
		{
			name:       "no dynamic block",
			address:    "aws_iam_role.r",
			resource:   `"aws_iam_role": {"r": {"inline_policy": [{"name": "static"}]}}`,
			wantClosed: []string{"inline_policy"},
		},
		{
			name:       "map attribute with a dynamic key",
			address:    "aws_s3_bucket.b",
			resource:   `"aws_s3_bucket": {"b": {"tags": {"dynamic": "yes", "other": {"for_each": "no"}}}}`,
			wantClosed: []string{"tags", "tags.dynamic", "tags.other"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := vfs.NewMemFS(map[string][]byte{"/repo/main.tf.json": []byte(`{"variable": {"names": {}}, "resource": {` + tc.resource + `}}`)})
			unit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(fs), "/repo", &RootOptions{FS: fs, RepoPath: "/repo"})
			require.NoError(t, err)
			var resource *policy.Resource
			for _, candidate := range unit.Resources {
				if candidate.Address == tc.address {
					resource = candidate
				}
			}
			require.NotNil(t, resource)
			for _, path := range tc.wantOpen {
				require.True(t, resource.State.IncompleteCollections[path], "%s must stay open: %v", path, resource.State.IncompleteCollections)
				require.True(t, resource.State.Written[path], path)
			}
			for _, path := range tc.wantUnknown {
				require.True(t, resource.State.Unknown[path], "%s: %v", path, resource.State.Unknown)
			}
			for _, path := range tc.wantClosed {
				require.False(t, resource.State.IncompleteCollections[path], "%s: %v", path, resource.State.IncompleteCollections)
			}
			if len(tc.wantUnknown) == 0 {
				for _, path := range tc.wantOpen {
					require.False(t, resource.State.Unknown[path], "%s keeps its known static blocks", path)
				}
			}
		})
	}
}

// A jsonencode document that is only partly known (Sid depends on an unset
// variable) keeps the explicit nulls of its known part: x is configured as
// null, not absent.
func TestContractV2PartialJSONPreservesNullInKnownSubtree(t *testing.T) {
	fs := vfs.NewMemFS(map[string][]byte{"/repo/main.tf": []byte(`
variable "pending" {}
resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Condition = { StringEquals = { x = null } }, Sid = var.pending }] })
}
`)})
	unit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(fs), "/repo", &RootOptions{
		FS: fs, RepoPath: "/repo", ComputeRelations: true, Derive: DeriveOptions{ParseJSON: true},
	})
	require.NoError(t, err)
	var doc *policy.Resource
	for _, resource := range unit.Resources {
		if resource.Address == "aws_iam_policy.p" {
			doc = resource
			break
		}
	}
	require.NotNil(t, doc)
	require.NotNil(t, doc.Derived)
	require.True(t, doc.Derived.JSONUnknown["policy"]["Statement.0.Sid"], "the document must be partial: %v", doc.Derived.JSONUnknown)
	statement := doc.Derived.JSON["policy"].(map[string]any)["Statement"].([]any)[0].(map[string]any)
	condition := statement["Condition"].(map[string]any)["StringEquals"].(map[string]any)
	require.Contains(t, condition, "x")
	require.Nil(t, condition["x"])
}

func TestContractV2DeepNestingRelationsAndPlanSoundness(t *testing.T) {
	fs := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
variable "unk_alg" {}
variable "unk_rules" {}
variable "unk_owner" {}
variable "unk_vpc" {}
variable "unk_eff" {}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = var.unk_alg
    }
  }
}

resource "aws_security_group" "dyn_only" {
  dynamic "ingress" {
    for_each = var.unk_rules
    content {
      from_port = ingress.value
    }
  }
  dynamic {}
  tags = {
    Owner = var.unk_owner
  }
}

locals {
  buckets = toset(["a", "b"])
  policy_obj = {
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "kms:*"
      Resource = "*"
      Principal = { AWS = var.unk_owner }
    }]
  }
}

resource "aws_s3_bucket" "b" {
  for_each = local.buckets
  bucket   = "my-${each.key}"
}

resource "aws_s3_bucket_versioning" "v" {
  for_each = local.buckets
  bucket   = aws_s3_bucket.b[each.key].id
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_flow_log" "fl" {
  vpc_id = var.unk_vpc
}

data "aws_iam_policy_document" "doc" {
  override_policy_documents = [var.unk_owner]
  statement {
    effect  = var.unk_eff
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = ["o-123"]
    }
  }
}

resource "aws_kms_key" "k1" {
  policy = data.aws_iam_policy_document.doc.json
}

resource "aws_kms_key" "k2" {
  policy = jsonencode(local.policy_obj)
}
`),
	})

	eval := tfeval.NewWithFS(fs)
	unit, err := EvaluateRoot(context.Background(), eval, "/repo", &RootOptions{
		FS:               fs,
		RepoPath:         "/repo",
		ComputeRelations: true,
		Derive:           DeriveOptions{ParseJSON: true},
	})
	require.NoError(t, err)

	byAddr := map[string]*policy.Resource{}
	for _, r := range unit.Resources {
		byAddr[r.Address] = r
	}

	// Depth-2 single nested block normalized to array with indexed State.Unknown.
	sse := byAddr["aws_s3_bucket_server_side_encryption_configuration.sse"]
	require.NotNil(t, sse)
	rule0 := sse.Attributes["rule"].([]any)[0].(map[string]any)
	applyList, ok := rule0["apply_server_side_encryption_by_default"].([]any)
	require.True(t, ok, "depth-2 nested block must normalize to array")
	require.Len(t, applyList, 1)
	require.True(t, sse.State.Unknown["rule.0.apply_server_side_encryption_by_default.0.sse_algorithm"])

	// Unresolved dynamic block without static sibling sets Unknown + IncompleteCollections;
	// unlabeled `dynamic {}` did not panic; map with known keys and unknown value keeps
	// known size (not in IncompleteCollections) while tracking the unknown entry in State.Unknown.
	sg := byAddr["aws_security_group.dyn_only"]
	require.NotNil(t, sg)
	require.True(t, sg.State.Unknown["ingress"])
	require.True(t, sg.State.IncompleteCollections["ingress"])
	require.False(t, sg.State.IncompleteCollections["tags"], "known map keys with unknown values have known map size")
	require.True(t, sg.State.Unknown["tags.Owner"])

	// Dynamic for_each key resolves exact instance without Cartesian product.
	ba := byAddr[`aws_s3_bucket.b["a"]`]
	bb := byAddr[`aws_s3_bucket.b["b"]`]
	va := byAddr[`aws_s3_bucket_versioning.v["a"]`]
	vb := byAddr[`aws_s3_bucket_versioning.v["b"]`]
	require.Equal(t, []string{va.ID}, ba.Relations.Related["aws_s3_bucket_versioning"]["bucket"].IDs)
	require.Equal(t, []string{vb.ID}, bb.Relations.Related["aws_s3_bucket_versioning"]["bucket"].IDs)

	// Non-DefaultLiteralKeys unknown companion (aws_flow_log.vpc_id) marks vpc incomplete.
	vpc := byAddr["aws_vpc.main"]
	require.False(t, vpc.Relations.Related["aws_flow_log"]["vpc_id"].Complete)

	// Partial IAM policy doc preserves merged principals, real conditions, unknown effect deleted, override marked unknown.
	k1 := byAddr["aws_kms_key.k1"]
	require.NotNil(t, k1.Derived)
	doc := k1.Derived.JSON["policy"].(map[string]any)
	stmt0 := doc["Statement"].([]any)[0].(map[string]any)
	require.NotContains(t, stmt0, "Effect", "unknown effect must not default to Allow")
	require.Len(t, stmt0["Principal"].(map[string]any)["AWS"].([]any), 2)
	require.Contains(t, stmt0["Condition"].(map[string]any), "StringEquals")
	require.True(t, k1.Derived.JSONUnknown["policy"]["Statement"])

	// Partially-known jsonencode(local.policy_obj) preserves concrete JSON structure.
	k2 := byAddr["aws_kms_key.k2"]
	require.NotNil(t, k2.Derived)
	require.NotNil(t, k2.Derived.JSON["policy"])
	require.True(t, k2.Derived.JSONUnknown["policy"]["Statement.0.Principal.AWS"])

	// Plan JSON: unwritten Optional+Computed after_unknown stays out of State.Unknown,
	// written unknown is not in State.Null, prior_state:null doesn't break line scan,
	// dotted for_each key + prefix-expanded references stay instance-accurate.
	planJSON := []byte(`{
  "prior_state": null,
  "configuration": {
    "provider_config": {
      "aws": { "name": "aws", "expressions": { "region": { "references": ["var.reg"] } } },
      "aws.west": { "name": "aws", "alias": "west", "expressions": { "region": { "constant_value": "us-west-2" } } },
      "module.child:aws.west": { "name": "aws", "alias": "west", "expressions": { "region": { "constant_value": "eu-west-1" } } }
    },
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.b",
          "provider_config_key": "aws.west",
          "expressions": { "bucket": { "references": ["var.name"] } }
        },
        {
          "address": "aws_s3_bucket_versioning.v",
          "expressions": { "bucket": { "references": ["aws_s3_bucket.b[\"app.prod\"].id", "aws_s3_bucket.b[\"app.prod\"]", "aws_s3_bucket.b"] } }
        }
      ]
    }
  },
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.b[\"app.prod\"]",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "b",
          "values": { "bucket": null, "logging": [], "arn": null }
        },
        {
          "address": "aws_s3_bucket.b[\"app.dev\"]",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "b",
          "values": { "bucket": "dev", "logging": [] }
        },
        {
          "address": "aws_s3_bucket_versioning.v",
          "mode": "managed",
          "type": "aws_s3_bucket_versioning",
          "name": "v",
          "values": { "bucket": null }
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_s3_bucket.b[\"app.prod\"]",
      "change": { "actions": ["create"], "after_unknown": { "bucket": true, "logging": true, "arn": true } }
    },
    {
      "address": "aws_s3_bucket_versioning.v",
      "change": { "actions": ["create"], "after_unknown": { "bucket": true } }
    }
  ]
}`)
	pUnit, err := BuildUnitFromPlan("/repo/plan.json", planJSON, &RootOptions{RepoPath: "/repo", ComputeRelations: true})
	require.NoError(t, err)
	pByAddr := map[string]*policy.Resource{}
	for _, r := range pUnit.Resources {
		pByAddr[r.Address] = r
	}
	prodB := pByAddr[`aws_s3_bucket.b["app.prod"]`]
	devB := pByAddr[`aws_s3_bucket.b["app.dev"]`]
	require.True(t, prodB.State.Unknown["bucket"])
	require.False(t, prodB.State.Null["bucket"], "written unknown must not also be marked State.Null")
	require.False(t, prodB.State.Unknown["logging"], "unwritten Optional+Computed field must not pollute State.Unknown")
	require.Len(t, prodB.Relations.Related["aws_s3_bucket_versioning"]["bucket"].IDs, 1)
	if devB.Relations != nil {
		require.Empty(t, devB.Relations.Related["aws_s3_bucket_versioning"]["bucket"].IDs, "prefix-expanded references must not widen to app.dev")
	}
	// Root aws.west provider must not be clobbered by module.child:aws.west.
	pid := prodB.Platform["terraform"].(map[string]any)["provider_id"].(string)
	require.Equal(t, "us-west-2", pUnit.ByID[pid].Attributes["region"])

	// Plan JSON nested null provenance in ordinary written maps/lists (`tags = { Owner: null }`).
	nullPlan := []byte(`{
  "configuration": {
    "root_module": {
      "resources": [{
        "address": "aws_s3_bucket.b",
        "expressions": { "tags": { "constant_value": { "Owner": null, "Env": "prod" } } }
      }]
    }
  },
  "planned_values": {
    "root_module": {
      "resources": [{
        "address": "aws_s3_bucket.b",
        "mode": "managed",
        "type": "aws_s3_bucket",
        "name": "b",
        "values": { "tags": { "Owner": null, "Env": "prod" } }
      }]
    }
  }
}`)
	nullUnit, err := BuildUnitFromPlan("/repo/null.json", nullPlan, &RootOptions{RepoPath: "/repo"})
	require.NoError(t, err)
	require.Len(t, nullUnit.Resources, 1)
	require.True(t, nullUnit.Resources[0].State.Null["tags.Owner"])
	require.NotContains(t, nullUnit.Resources[0].Attributes["tags"].(map[string]any), "Owner")
	require.Equal(t, "prod", nullUnit.Resources[0].Attributes["tags"].(map[string]any)["Env"])

	// Dynamic-block relation expansion indexes every expanded instance and keeps trailing static block aligned.
	dynRelFS := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
resource "aws_security_group" "target" {
  name = "target"
}
resource "aws_security_group" "caller" {
  dynamic "ingress" {
    for_each = [80, 443]
    content {
      from_port       = ingress.value
      security_groups = [aws_security_group.target.id]
    }
  }
  ingress {
    from_port       = 8080
    security_groups = [aws_security_group.target.id]
  }
}
`),
	})
	dynEval := tfeval.NewWithFS(dynRelFS)
	dynUnit, err := EvaluateRoot(context.Background(), dynEval, "/repo", &RootOptions{
		FS:               dynRelFS,
		RepoPath:         "/repo",
		ComputeRelations: true,
	})
	require.NoError(t, err)
	var callerSG, targetSG *policy.Resource
	for _, r := range dynUnit.Resources {
		switch r.Address {
		case "aws_security_group.caller":
			callerSG = r
		case "aws_security_group.target":
			targetSG = r
		}
	}
	require.NotNil(t, callerSG)
	require.NotNil(t, targetSG)
	require.Equal(t, []string{targetSG.ID}, callerSG.Relations.Targets["ingress.0.security_groups"].IDs)
	require.Equal(t, []string{targetSG.ID}, callerSG.Relations.Targets["ingress.1.security_groups"].IDs)
	require.Equal(t, []string{targetSG.ID}, callerSG.Relations.Targets["ingress.2.security_groups"].IDs)

	// Dynamic iterator bindings isolate per-instance targets (no Cartesian leakage).
	iterFS := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
resource "aws_security_group" "target" {
  count = 2
  name  = "target-${count.index}"
}
resource "aws_security_group" "caller" {
  dynamic "ingress" {
    for_each = [0, 1]
    content {
      security_groups = [aws_security_group.target[ingress.value].id]
    }
  }
}
`),
	})
	iterEval := tfeval.NewWithFS(iterFS)
	iterUnit, err := EvaluateRoot(context.Background(), iterEval, "/repo", &RootOptions{
		FS:               iterFS,
		RepoPath:         "/repo",
		ComputeRelations: true,
	})
	require.NoError(t, err)
	var iterCaller, iterT0, iterT1 *policy.Resource
	for _, r := range iterUnit.Resources {
		switch r.Address {
		case "aws_security_group.caller":
			iterCaller = r
		case "aws_security_group.target[0]":
			iterT0 = r
		case "aws_security_group.target[1]":
			iterT1 = r
		}
	}
	require.NotNil(t, iterCaller)
	require.NotNil(t, iterT0)
	require.NotNil(t, iterT1)
	require.Equal(t, []string{iterT0.ID}, iterCaller.Relations.Targets["ingress.0.security_groups"].IDs)
	require.Equal(t, []string{iterT1.ID}, iterCaller.Relations.Targets["ingress.1.security_groups"].IDs)

	// Unresolved dynamic block (n < 0) propagates relation uncertainty without inventing definite edges;
	// known-empty dynamic block (n == 0) keeps referrers complete.
	unresDynFS := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
variable "rules" {}
resource "aws_security_group" "target" {
  name = "target"
}
resource "aws_security_group" "caller" {
  dynamic "ingress" {
    for_each = var.rules
    content {
      security_groups = [aws_security_group.target.id]
    }
  }
}
`),
	})
	unresDynEval := tfeval.NewWithFS(unresDynFS)
	unresDynUnit, err := EvaluateRoot(context.Background(), unresDynEval, "/repo", &RootOptions{
		FS:               unresDynFS,
		RepoPath:         "/repo",
		ComputeRelations: true,
	})
	require.NoError(t, err)
	var uCaller, uTarget *policy.Resource
	for _, r := range unresDynUnit.Resources {
		switch r.Address {
		case "aws_security_group.caller":
			uCaller = r
		case "aws_security_group.target":
			uTarget = r
		}
	}
	require.NotNil(t, uCaller)
	require.NotNil(t, uTarget)
	require.Empty(t, uCaller.Relations.Targets["ingress.0.security_groups"].IDs, "unresolved dynamic block must not invent definite edges")
	require.False(t, uCaller.Relations.Targets["ingress.0.security_groups"].Complete, "unresolved dynamic block must mark target incomplete")
	require.False(t, uTarget.Relations.Referrers["ingress.0.security_groups"].Complete, "unresolved dynamic block must mark target referrer incomplete")

	// Speculative prepass unresolved-module rollback: an optional remote module whose
	// count starts unknown during sibling prepass and resolves to 0 must leave ScopeComplete=true.
	specFS := vfs.NewMemFS(map[string][]byte{
		"/repo/cfg/main.tf": []byte(`
output "enable" {
  value = false
}
`),
		"/repo/main.tf": []byte(`
module "optional" {
  count  = module.cfg.enable ? 1 : 0
  source = "registry.terraform.io/example/unresolvable/aws"
}
module "cfg" {
  source = "./cfg"
}
resource "aws_s3_bucket" "b" {
  bucket = "ok"
}
`),
	})
	specEval := tfeval.NewWithFS(specFS)
	specUnit, err := EvaluateRoot(context.Background(), specEval, "/repo", &RootOptions{
		FS:       specFS,
		RepoPath: "/repo",
	})
	require.NoError(t, err)
	require.True(t, specUnit.ScopeComplete, "rolled-back speculative unresolved module with final count=0 must not poison ScopeComplete")
}

func TestRelationWalkCacheReusesStructureWithoutCachingScope(t *testing.T) {
	parseBody := func(source, filename string) *hclsyntax.Body {
		t.Helper()
		file, diags := hclsyntax.ParseConfig([]byte(source), filename, hcl.Pos{Line: 1, Column: 1})
		require.False(t, diags.HasErrors(), "%s", diags.Error())
		body, ok := file.Body.(*hclsyntax.Body)
		require.True(t, ok)
		require.NotEmpty(t, body.Blocks)
		return body.Blocks[0].Body
	}
	body := parseBody(`resource "example" "item" {
  value = {
    direct = aws_s3_bucket.logs.id
    nested = [aws_s3_bucket.other.id]
  }
  settings {
    name = var.name
  }
  lifecycle {
    ignore_changes = [value]
  }
}`, "one.tf")
	cache := newRelationWalkCache()

	type observed struct {
		path   string
		range_ hcl.Range
		scope  string
	}
	collect := func(walkCache *relationWalkCache, cached bool, scope string) []observed {
		ctx := &hcl.EvalContext{Variables: map[string]cty.Value{"scope_marker": cty.StringVal(scope)}}
		getEvalCtx := func() *hcl.EvalContext { return ctx }
		var got []observed
		visit := func(path string, expr hcl.Expression, exprEvalCtx func() *hcl.EvalContext, _ bool) {
			got = append(got, observed{path: path, range_: expr.Range(), scope: exprEvalCtx().Variables["scope_marker"].AsString()})
		}
		if cached {
			walkBodyAttrRefsCached(context.Background(), walkCache, body, nil, "", getEvalCtx, false, visit, nil)
		} else {
			walkBodyAttrRefs(context.Background(), body, nil, "", getEvalCtx, false, visit, nil)
		}
		sort.Slice(got, func(i, j int) bool { return got[i].path < got[j].path })
		return got
	}

	wantFirst := collect(cache, false, "module-a")
	gotFirst := collect(cache, true, "module-a")
	gotSecond := collect(cache, true, "module-b")
	require.Equal(t, wantFirst, gotFirst)
	require.Len(t, gotSecond, len(gotFirst))
	for _, event := range gotSecond {
		require.Equal(t, "module-b", event.scope, "cached structure must use the current module scope")
	}
	require.Len(t, cache.byBody, 1, "one parsed body is cached once across resource instances")

	concurrentCache := newRelationWalkCache()
	type walkResult struct {
		scope  string
		events []observed
	}
	results := make(chan walkResult, 8)
	for i := range 8 {
		go func(i int) {
			scope := fmt.Sprintf("module-%d", i)
			results <- walkResult{scope: scope, events: collect(concurrentCache, true, scope)}
		}(i)
	}
	for range 8 {
		result := <-results
		for _, event := range result.events {
			require.Equal(t, result.scope, event.scope)
		}
	}
	require.Len(t, concurrentCache.byBody, 1, "concurrent callers share one immutable structural entry")

	otherBody := parseBody(`resource "example" "other" { different = "value" }`, "two.tf")
	_, ok := cache.events(context.Background(), otherBody)
	require.True(t, ok)
	require.Len(t, cache.byBody, 2, "a different parsed body has a separate structural entry")

	dynamicBody := parseBody(`resource "example" "dynamic" {
  dynamic "setting" {
    for_each = var.settings
    content { name = each.value }
  }
}`, "dynamic.tf")
	_, ok = cache.events(context.Background(), dynamicBody)
	require.False(t, ok, "dynamic expansion remains per-scope and falls back to the uncached walker")
}

func TestLiteralRelationProviderScopes(t *testing.T) {
	fs := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
provider "aws" {
  alias = "a"
  region = "us-east-1"
}
provider "aws" {
  alias = "b"
  region = "eu-west-1"
}
resource "aws_iam_role" "a" {
  provider = aws.a
  name = "app"
}
resource "aws_iam_role" "b" {
  provider = aws.b
  name = "app"
}
resource "aws_iam_role_policy" "literal" {
  provider = aws.a
  role = "app"
}
resource "aws_iam_role_policy" "explicit" {
  provider = aws.a
  role = aws_iam_role.b.name
}
resource "aws_s3_bucket" "bucket" {
  provider = aws.b
  bucket = "globally-unique"
}
resource "aws_s3_bucket_versioning" "versioning" {
  provider = aws.a
  bucket = "globally-unique"
}
`),
	})
	unit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(fs), "/repo", &RootOptions{FS: fs, RepoPath: "/repo", ComputeRelations: true})
	require.NoError(t, err)
	byAddr := map[string]*policy.Resource{}
	for _, r := range unit.Resources {
		byAddr[r.Address] = r
	}
	require.Equal(t, []string{byAddr["aws_iam_role.a"].ID}, byAddr["aws_iam_role_policy.literal"].Relations.Targets["role"].IDs)
	// The explicit reference remains authoritative even across provider aliases.
	require.Contains(t, byAddr["aws_iam_role_policy.explicit"].Relations.Targets["role"].IDs, byAddr["aws_iam_role.b"].ID)
	require.Equal(t, []string{byAddr["aws_s3_bucket.bucket"].ID}, byAddr["aws_s3_bucket_versioning.versioning"].Relations.Targets["bucket"].IDs)

	// Exercise the Plan relation builder with the same provider identities and
	// known literals, without relying on HCL's reference walker.
	for _, r := range unit.Resources {
		r.Relations = nil
	}
	items := []planResourceRefs{}
	for _, r := range unit.Resources {
		if r.Kind == "resource" && r.Address != "aws_iam_role_policy.explicit" {
			items = append(items, planResourceRefs{res: r})
		}
	}
	buildPlanRelations(unit, items, nil, nil)
	require.Equal(t, []string{byAddr["aws_iam_role.a"].ID}, byAddr["aws_iam_role_policy.literal"].Relations.Targets["role"].IDs)
	require.Equal(t, []string{byAddr["aws_s3_bucket.bucket"].ID}, byAddr["aws_s3_bucket_versioning.versioning"].Relations.Targets["bucket"].IDs)

	// Unknown registered target names make only matching provider scopes
	// incomplete. Repeated literal sources must each retain forward uncertainty,
	// without inventing an edge to either unknown or unrelated targets.
	literalKeys := LiteralKeyMap{
		"example_attachment": {
			"target_name": {"example_target": {"name"}},
			"empty_name":  {"example_target": {"name"}},
		},
	}
	unknownFS := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
variable "unknown_name_a" {}
variable "unknown_name_b" {}
provider "example" { alias = "a" }
provider "example" { alias = "b" }
provider "example" { alias = "c" }

resource "example_target" "unknown_a" {
  provider = example.a
  name     = var.unknown_name_a
}
resource "example_target" "unknown_b" {
  provider = example.b
  name     = var.unknown_name_b
}
resource "example_target" "known_a" {
  provider = example.a
  name     = "unrelated"
}
resource "example_target" "known_b" {
  provider = example.b
  name     = "known-b"
}

resource "example_attachment" "source_a" {
  provider     = example.a
  target_name  = "missing"
  description  = "descriptive only"
}
resource "example_attachment" "source_a_repeat" {
  provider    = example.a
  target_name = "missing"
}
resource "example_attachment" "empty_a" {
  provider   = example.a
  empty_name = ""
}
resource "example_attachment" "source_c" {
  provider    = example.c
  target_name = "missing"
}
`),
	})
	unknownUnit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(unknownFS), "/repo", &RootOptions{
		FS: unknownFS, RepoPath: "/repo", ComputeRelations: true, LiteralKeys: literalKeys,
	})
	require.NoError(t, err)
	unknownByAddr := make(map[string]*policy.Resource, len(unknownUnit.Resources))
	for _, resource := range unknownUnit.Resources {
		unknownByAddr[resource.Address] = resource
	}
	unknownTargetA := unknownByAddr["example_target.unknown_a"]
	unknownTargetB := unknownByAddr["example_target.unknown_b"]
	knownTargetA := unknownByAddr["example_target.known_a"]
	knownTargetB := unknownByAddr["example_target.known_b"]
	sourceA := unknownByAddr["example_attachment.source_a"]
	sourceARepeat := unknownByAddr["example_attachment.source_a_repeat"]
	emptySourceA := unknownByAddr["example_attachment.empty_a"]
	sourceC := unknownByAddr["example_attachment.source_c"]
	require.NotNil(t, unknownTargetA)
	require.NotNil(t, unknownTargetB)
	require.NotNil(t, knownTargetA)
	require.NotNil(t, knownTargetB)
	require.NotNil(t, sourceA)
	require.NotNil(t, sourceARepeat)
	require.NotNil(t, emptySourceA)
	require.NotNil(t, sourceC)
	require.False(t, unknownTargetA.Relations.Related["example_attachment"]["target_name"].Complete)
	require.Empty(t, unknownTargetA.Relations.Related["example_attachment"]["target_name"].IDs)
	require.False(t, unknownTargetA.Relations.Referrers["target_name"].Complete)
	require.Empty(t, unknownTargetA.Relations.Referrers["target_name"].IDs)
	for _, source := range []*policy.Resource{sourceA, sourceARepeat} {
		require.False(t, source.Relations.Targets["target_name"].Complete)
		require.Empty(t, source.Relations.Targets["target_name"].IDs)
	}
	require.NotContains(t, knownTargetA.Relations.Related, "example_attachment", "known unrelated target must not inherit unknown-name uncertainty")
	require.NotContains(t, knownTargetA.Relations.Referrers, "target_name")
	require.NotContains(t, knownTargetB.Relations.Related, "example_attachment", "unknown names in another provider scope must not taint known targets")
	require.NotContains(t, unknownTargetB.Relations.Related, "example_attachment", "provider-a sources must not taint provider-b unknown targets")
	require.True(t, emptySourceA.Relations.Targets["empty_name"].Complete)
	require.Empty(t, emptySourceA.Relations.Targets["empty_name"].IDs)
	require.NotContains(t, unknownTargetA.Relations.Related["example_attachment"], "empty_name")
	require.True(t, sourceC.Relations.Targets["target_name"].Complete)
	require.Empty(t, sourceC.Relations.Targets["target_name"].IDs)
	require.True(t, sourceA.Relations.Targets["description"].Complete)
	require.Empty(t, sourceA.Relations.Targets["description"].IDs)
	require.NotContains(t, unknownTargetA.Relations.Referrers, "description")

	// The Plan adapter sees the same literal sources, with the unknown target
	// represented at the root path rather than at its individual name attribute.
	for _, resource := range unknownUnit.Resources {
		resource.Relations = nil
	}
	unknownTargetA.State.Unknown = map[string]bool{"": true}
	planItems := make([]planResourceRefs, 0, len(unknownUnit.Resources))
	for _, resource := range unknownUnit.Resources {
		if resource.Kind == "resource" {
			planItems = append(planItems, planResourceRefs{res: resource})
		}
	}
	buildPlanRelations(unknownUnit, planItems, literalKeys, nil)
	require.False(t, unknownTargetA.Relations.Related["example_attachment"]["target_name"].Complete)
	require.Empty(t, unknownTargetA.Relations.Related["example_attachment"]["target_name"].IDs)
	require.False(t, unknownTargetA.Relations.Referrers["target_name"].Complete)
	require.Empty(t, unknownTargetA.Relations.Referrers["target_name"].IDs)
	for _, source := range []*policy.Resource{sourceA, sourceARepeat} {
		require.False(t, source.Relations.Targets["target_name"].Complete)
		require.Empty(t, source.Relations.Targets["target_name"].IDs)
	}
	require.Nil(t, knownTargetA.Relations)
	require.Nil(t, knownTargetB.Relations)
	require.Nil(t, unknownTargetB.Relations)
	assertCompleteOrAbsentTarget := func(resource *policy.Resource, path string) {
		if resource.Relations == nil {
			return
		}
		if list, ok := resource.Relations.Targets[path]; ok {
			require.True(t, list.Complete)
			require.Empty(t, list.IDs)
		}
	}
	assertCompleteOrAbsentTarget(emptySourceA, "empty_name")
	assertCompleteOrAbsentTarget(sourceC, "target_name")
	require.NotContains(t, sourceA.Relations.Targets, "description")
	require.NotContains(t, unknownTargetA.Relations.Referrers, "description")
}

func TestHCLModuleOutputOnlyForEachRelationsAreInstanceScoped(t *testing.T) {
	fs := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
resource "aws_s3_bucket" "primary" {
  bucket = "primary-bucket"
}
resource "aws_s3_bucket" "secondary" {
  bucket = "secondary-bucket"
}
module "relay" {
  source   = "./modules/relay"
  for_each = {
    primary   = aws_s3_bucket.primary.bucket
    secondary = aws_s3_bucket.secondary.bucket
  }
  selected = each.value
}
resource "aws_s3_bucket_versioning" "primary" {
  bucket = module.relay["primary"].selected
}
resource "aws_s3_bucket_versioning" "secondary" {
  bucket = module.relay["secondary"].selected
}
resource "terraform_data" "tagged" {
  input = {
    owner = aws_s3_bucket.primary.bucket
    note  = "descriptive only"
  }
}
output "selected_bucket" {
  value = module.relay["primary"].selected
}
`),
		"/repo/modules/relay/main.tf": []byte(`
variable "selected" {}
output "selected" {
  value = var.selected
}
`),
	})
	unit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(fs), "/repo", &RootOptions{
		FS: fs, RepoPath: "/repo", ComputeRelations: true,
	})
	require.NoError(t, err)
	byAddr := map[string]*policy.Resource{}
	for _, resource := range unit.Resources {
		byAddr[resource.Address] = resource
	}
	primary := byAddr["aws_s3_bucket_versioning.primary"]
	secondary := byAddr["aws_s3_bucket_versioning.secondary"]
	require.NotNil(t, primary)
	require.NotNil(t, secondary)
	require.Equal(t, []string{byAddr["aws_s3_bucket.primary"].ID}, primary.Relations.Targets["bucket"].IDs)
	require.Equal(t, []string{byAddr["aws_s3_bucket.secondary"].ID}, secondary.Relations.Targets["bucket"].IDs)
	require.Equal(t, []string{byAddr["aws_s3_bucket.primary"].ID}, primary.Relations.TargetsVia["bucket"]["bucket"].IDs)
	require.Equal(t, []string{byAddr["aws_s3_bucket.secondary"].ID}, secondary.Relations.TargetsVia["bucket"]["bucket"].IDs)
	require.True(t, primary.Relations.Targets["bucket"].Complete)
	require.True(t, secondary.Relations.Targets["bucket"].Complete)
	tagged := byAddr["terraform_data.tagged"]
	require.Equal(t, []string{byAddr["aws_s3_bucket.primary"].ID}, tagged.Relations.Targets["input"].IDs)
	require.Equal(t, []string{byAddr["aws_s3_bucket.primary"].ID}, tagged.Relations.Targets["input.owner"].IDs)
	require.Empty(t, tagged.Relations.Targets["input.note"].IDs)
	require.True(t, tagged.Relations.Targets["input.note"].Complete)
	output := byAddr["output.selected_bucket"]
	require.NotNil(t, output, "relation scans include output sources even when static-block expansion was not requested")
	require.Contains(t, byAddr["aws_s3_bucket.primary"].Relations.Referrers["value"].IDs, output.ID)
}

func TestHCLForEachInstanceSetCompleteness(t *testing.T) {
	fs := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
variable "unknown_key" {}
variable "unknown_name" {}
variable "unknown_count" {}

resource "aws_security_group" "partial" {
  for_each = toset(["dev", var.unknown_key])
  name     = each.key
}

resource "aws_security_group" "known_map_keys" {
  for_each = {
    dev  = var.unknown_name
    prod = var.unknown_name
  }
  name = each.key
}

resource "aws_security_group" "known_set" {
  for_each = toset(["dev", "prod"])
  name     = each.key
}

resource "aws_security_group" "unknown_count" {
  count = var.unknown_count
  name  = "unknown-${count.index}"
}

resource "aws_security_group" "known_count" {
  count = 2
  name  = "known-${count.index}"
}
`),
	})

	unit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(fs), "/repo", &RootOptions{
		FS: fs, RepoPath: "/repo", ComputeRelations: true,
	})
	require.NoError(t, err)

	completeFor := func(resource *policy.Resource) bool {
		terraformMeta, _ := resource.Platform[terraformPlatform].(map[string]any)
		complete, exists := terraformMeta["instance_set_complete"].(bool)
		return !exists || complete
	}
	var partial, knownMap, knownSet, unknownCount, knownCount []*policy.Resource
	for _, resource := range unit.Resources {
		switch resource.Name {
		case "partial":
			partial = append(partial, resource)
		case "known_map_keys":
			knownMap = append(knownMap, resource)
		case "known_set":
			knownSet = append(knownSet, resource)
		case "unknown_count":
			unknownCount = append(unknownCount, resource)
		case "known_count":
			knownCount = append(knownCount, resource)
		}
	}
	require.NotEmpty(t, partial)
	require.NotEmpty(t, knownMap)
	require.NotEmpty(t, knownSet)
	require.NotEmpty(t, unknownCount)
	require.Len(t, knownCount, 2)
	for _, resource := range partial {
		require.False(t, completeFor(resource), resource.Address)
	}
	for _, resource := range knownMap {
		require.True(t, completeFor(resource), resource.Address)
	}
	for _, resource := range knownSet {
		require.True(t, completeFor(resource), resource.Address)
	}
	for _, resource := range unknownCount {
		require.False(t, completeFor(resource), resource.Address)
	}
	for _, resource := range knownCount {
		require.True(t, completeFor(resource), resource.Address)
	}

	t.Run("shared body cache distinguishes module scopes", func(t *testing.T) {
		moduleFS := vfs.NewMemFS(map[string][]byte{
			"/repo/main.tf": []byte(`
variable "unknown_count" { type = number }

module "unknown" {
  source      = "./child"
  count_value = var.unknown_count
}

module "known" {
  source      = "./child"
  count_value = 2
}
`),
			"/repo/child/main.tf": []byte(`
variable "count_value" { type = number }

resource "terraform_data" "expanded" {
  count = var.count_value
  input = count.index
}
`),
		})
		ctx := context.Background()
		evaluator := tfeval.NewWithFS(moduleFS)
		inputs := evaluator.LoadRootVarsWithContext(ctx, "/repo")
		resolved, _, _, evalErr := evaluator.EvaluateModule(ctx, "/repo", inputs)
		require.NoError(t, evalErr)

		var known, unknown []*tfeval.ResolvedResource
		for i := range resolved {
			resource := &resolved[i]
			if resource.Type != "terraform_data" || tfeval.ResourceBaseName(resource.Name) != "expanded" {
				continue
			}
			switch {
			case strings.HasPrefix(resource.ModuleAddress, "module.known"):
				known = append(known, resource)
			case strings.HasPrefix(resource.ModuleAddress, "module.unknown"):
				unknown = append(unknown, resource)
			}
		}
		require.Len(t, known, 2)
		require.NotEmpty(t, unknown)
		require.Same(t, known[0].Body, known[1].Body, "expanded instances share their parsed block body")
		require.Same(t, known[0].Scope, known[1].Scope, "expanded instances share their module scope")
		require.Same(t, known[0].Body, unknown[0].Body, "module calls reuse the parsed child body")
		require.NotSame(t, known[0].Scope, unknown[0].Scope, "module calls with different inputs have distinct scopes")

		orders := [][]tfeval.ResolvedResource{resolved, append([]tfeval.ResolvedResource(nil), resolved...)}
		for left, right := 0, len(orders[1])-1; left < right; left, right = left+1, right-1 {
			orders[1][left], orders[1][right] = orders[1][right], orders[1][left]
		}
		for _, ordered := range orders {
			unit := BuildUnitFromEval("/repo", ordered, &RootOptions{FS: moduleFS, RepoPath: "/repo"})
			var knownCount, unknownCount int
			for _, resource := range unit.Resources {
				if resource.Type != "terraform_data" || resource.Name != "expanded" {
					continue
				}
				terraformMeta, _ := resource.Platform[terraformPlatform].(map[string]any)
				complete, exists := terraformMeta["instance_set_complete"].(bool)
				if strings.HasPrefix(resource.Address, "module.known") {
					knownCount++
					require.True(t, !exists || complete, resource.Address)
				} else if strings.HasPrefix(resource.Address, "module.unknown") {
					unknownCount++
					require.True(t, exists && !complete, resource.Address)
				}
			}
			require.Equal(t, 2, knownCount)
			require.NotZero(t, unknownCount)
		}
	})
}

func TestHCLInstanceScopedLocalAndEachRelations(t *testing.T) {
	fs := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
locals {
  role_indexes = [0]
}

resource "example_role" "indexed" {
  count = 1
  name  = "indexed-role"
}

resource "example_policy" "indexed" {
  count = 1
  role  = example_role.indexed[local.role_indexes[count.index]].id
}

module "network" {
  source = "./modules/network"
}
`),
		"/repo/modules/network/main.tf": []byte(`
resource "example_subnet" "protected" {
  for_each = toset(["a", "b"])
  name     = each.key
}

resource "example_association" "protected" {
  for_each = example_subnet.protected
  subnet_id = each.value.id
}

resource "example_subnet" "unsecured" {
  name = "unsecured"
}
`),
	})
	unit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(fs), "/repo", &RootOptions{
		FS: fs, RepoPath: "/repo", ComputeRelations: true,
	})
	require.NoError(t, err)

	protectedIDs := map[string]bool{}
	var unsecured *policy.Resource
	var policyResource *policy.Resource
	var indexedRole *policy.Resource
	var associations []*policy.Resource
	for _, resource := range unit.Resources {
		switch {
		case resource.Type == "example_subnet" && strings.Contains(resource.Address, ".protected["):
			protectedIDs[resource.ID] = true
		case resource.Type == "example_subnet" && strings.HasSuffix(resource.Address, ".unsecured"):
			unsecured = resource
		case resource.Type == "example_association":
			associations = append(associations, resource)
		case resource.Type == "example_role" && strings.HasSuffix(resource.Address, ".indexed[0]"):
			indexedRole = resource
		case resource.Type == "example_policy" && strings.HasSuffix(resource.Address, ".indexed[0]"):
			policyResource = resource
		}
	}
	require.Len(t, protectedIDs, 2)
	require.Len(t, associations, 2)
	for _, association := range associations {
		got := association.Relations.Targets["subnet_id"]
		require.Len(t, got.IDs, 1, association.Address)
		require.True(t, protectedIDs[got.IDs[0]], association.Address)
		require.True(t, got.Complete, association.Address)
	}
	require.NotNil(t, unsecured)
	require.Empty(t, unsecured.Relations.Related["example_association"]["subnet_id"].IDs)
	require.True(t, unit.ScopeComplete)
	require.NotNil(t, indexedRole)
	require.NotNil(t, policyResource)
	require.Equal(t, []string{indexedRole.ID}, policyResource.Relations.Targets["role"].IDs)
	require.True(t, policyResource.Relations.Targets["role"].Complete)
	require.Equal(t, []string{policyResource.ID}, indexedRole.Relations.Related["example_policy"]["role"].IDs)
	require.True(t, indexedRole.Relations.Related["example_policy"]["role"].Complete)
}

func TestPlanModuleOutputInputRelationsAndReadPaths(t *testing.T) {
	planJSON := []byte(`{
  "configuration": {
    "root_module": {
      "outputs": {
        "bucket_id": {"expression":{"references":["aws_s3_bucket.source.id","aws_s3_bucket.source"]}}
      },
      "resources": [
        {"address":"aws_s3_bucket.source","expressions":{"bucket":{"constant_value":"logs"}}},
        {"address":"aws_s3_bucket_versioning.consumer","expressions":{
          "bucket":{"references":["module.relay.selected"]},
          "location":{"references":["module.relay.direct"]},
          "indexed":{"references":["module.relay.direct[0]","module.relay.direct"]}
        }}
      ],
      "module_calls": {
        "relay": {
          "expressions": {"selected":{"references":["aws_s3_bucket.source.bucket","aws_s3_bucket.source"]}},
          "module": {
            "resources":[{"address":"aws_s3_bucket.child","count_expression":{"constant_value":2},"expressions":{"bucket":{"constant_value":"child-logs"}}}],
            "outputs":{
              "selected":{"expression":{"references":["var.selected"]}},
              "direct":{"expression":{"references":["aws_s3_bucket.child.bucket","aws_s3_bucket.child"]}}
            }
          }
        }
      }
    }
  },
  "planned_values": {
    "root_module": {
      "resources": [
        {"address":"aws_s3_bucket.source","mode":"managed","type":"aws_s3_bucket","name":"source","values":{"bucket":"logs"}},
        {"address":"aws_s3_bucket_versioning.consumer","mode":"managed","type":"aws_s3_bucket_versioning","name":"consumer","values":{}}
      ],
      "child_modules": [{"address":"module.relay","resources":[
        {"address":"module.relay.aws_s3_bucket.child[0]","mode":"managed","type":"aws_s3_bucket","name":"child","values":{"bucket":"child-logs"}},
        {"address":"module.relay.aws_s3_bucket.child[1]","mode":"managed","type":"aws_s3_bucket","name":"child","values":{"bucket":"child-logs"}}
      ]}]
    }
  },
  "format_version":"1.2"
}`)
	unit, err := BuildUnitFromPlan("/repo/plan.json", planJSON, &RootOptions{RepoPath: "/repo", ComputeRelations: true})
	require.NoError(t, err)
	byAddr := map[string]*policy.Resource{}
	for _, resource := range unit.Resources {
		byAddr[resource.Address] = resource
	}
	consumer := byAddr["aws_s3_bucket_versioning.consumer"]
	require.NotNil(t, consumer)
	source := byAddr["aws_s3_bucket.source"]
	require.Equal(t, []string{source.ID}, consumer.Relations.Targets["bucket"].IDs)
	require.Equal(t, []string{source.ID}, consumer.Relations.TargetsVia["bucket"]["bucket"].IDs)
	require.True(t, consumer.Relations.Targets["bucket"].Complete)
	output := byAddr["output.bucket_id"]
	require.NotNil(t, output)
	selectedOutput := byAddr["module.relay.output.selected"]
	require.NotNil(t, selectedOutput)
	require.Equal(t, []string{output.ID, selectedOutput.ID}, source.Relations.Referrers["value"].IDs)
	require.Equal(t, []string{
		byAddr["module.relay.aws_s3_bucket.child[0]"].ID,
		byAddr["module.relay.aws_s3_bucket.child[1]"].ID,
	}, consumer.Relations.Targets["location"].IDs)
	require.Equal(t, []string{
		byAddr["module.relay.aws_s3_bucket.child[0]"].ID,
		byAddr["module.relay.aws_s3_bucket.child[1]"].ID,
	}, consumer.Relations.TargetsVia["location"]["bucket"].IDs)
	require.Empty(t, consumer.Relations.Targets["indexed"].IDs, "unknown collection selection does not create definite target edges")
	require.False(t, consumer.Relations.Targets["indexed"].Complete)

	require.Equal(t, "metric_transformation.name", planRefReadPath("aws_cloudwatch_log_metric_filter.example.metric_transformation[0].name"))
	require.Equal(t, "tags.Owner", planRefReadPath(`aws_s3_bucket.example.tags["Owner"]`))
}

func TestPlanNestedAttributeRangesPointToJSONValues(t *testing.T) {
	planJSON := []byte(`{
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "example_workload.test",
          "mode": "managed",
          "type": "example_workload",
          "name": "test",
          "values": {
            "spec": [
              {
                "container": [
                  {
                    "resources": [
                      {
                        "limits": {
                          "cpu": "500m"
                        }
                      }
                    ]
                  }
                ],
                "host_pid": true
              }
            ]
          }
        }
      ]
    }
  },
  "configuration": {
    "root_module": {
      "resources": [{
        "address": "example_workload.test",
        "expressions": {
          "unresolved": {"references": ["var.link"]}
        }
      }]
    }
  }
}`)

	unit, err := BuildUnitFromPlan("/repo/plan.json", planJSON, &RootOptions{RepoPath: "/repo"})
	require.NoError(t, err)
	require.Len(t, unit.Resources, 1)
	resource := unit.Resources[0]
	expressionLine := 1 + strings.Count(string(planJSON[:strings.Index(string(planJSON), `"unresolved":`)]), "\n")
	require.Equal(t, expressionLine, resource.Source.Range(policy.Path{policy.Key("unresolved")}).StartLine)
	require.Equal(t, 10, resource.Source.Range(policy.Path{}).StartLine)
	require.Equal(t, 24, resource.Source.Range(policy.Path{
		policy.Key("spec"), policy.Index(0), policy.Key("host_pid"),
	}).StartLine)
	require.Equal(t, 18, resource.Source.Range(policy.Path{
		policy.Key("spec"), policy.Index(0), policy.Key("container"), policy.Index(0),
		policy.Key("resources"), policy.Index(0), policy.Key("limits"), policy.Key("cpu"),
	}).StartLine)
}

func TestMissingExplicitPlanTargetDoesNotInvalidateUnrelatedReverseRelations(t *testing.T) {
	planJSON := []byte(`{
  "configuration": {
    "root_module": {
      "resources": [{
        "address": "example_link.missing",
        "expressions": {
          "target_id": {
            "references": [
              "example_target.missing.id",
              "example_target.missing"
            ]
          }
        }
      }]
    }
  },
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "example_link.missing",
          "mode": "managed",
          "type": "example_link",
          "name": "missing",
          "values": {"target_id": null}
        },
        {
          "address": "example_target.other",
          "mode": "managed",
          "type": "example_target",
          "name": "other",
          "values": {"name": "other"}
        }
      ]
    }
  },
  "resource_changes": [{
    "address": "example_link.missing",
    "change": {"actions": ["create"], "after_unknown": {"target_id": true}}
  }]
}`)
	unit, err := BuildUnitFromPlan("/repo/plan.json", planJSON, &RootOptions{
		RepoPath: "/repo", ComputeRelations: true,
	})
	require.NoError(t, err)
	byAddress := make(map[string]*policy.Resource, len(unit.Resources))
	for _, resource := range unit.Resources {
		byAddress[resource.Address] = resource
	}
	authorizer := byAddress["example_link.missing"]
	otherAPI := byAddress["example_target.other"]
	require.NotNil(t, authorizer)
	require.NotNil(t, otherAPI)
	require.False(t, authorizer.Relations.Targets["target_id"].Complete)
	require.Nil(t, otherAPI.Relations, "an omitted explicit target cannot invalidate another API's reverse relation set")
}

func TestMissingExplicitHCLTargetDoesNotInvalidateUnrelatedReverseRelations(t *testing.T) {
	fs := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
resource "example_link" "missing" {
  target_id = example_target.missing.id
}

resource "example_target" "other" {
  name = "other"
}
`),
	})
	unit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(fs), "/repo", &RootOptions{
		FS: fs, RepoPath: "/repo", ComputeRelations: true,
	})
	require.NoError(t, err)
	byAddress := make(map[string]*policy.Resource, len(unit.Resources))
	for _, resource := range unit.Resources {
		byAddress[resource.Address] = resource
	}
	authorizer := byAddress["example_link.missing"]
	otherAPI := byAddress["example_target.other"]
	require.NotNil(t, authorizer)
	require.NotNil(t, otherAPI)
	require.False(t, authorizer.Relations.Targets["target_id"].Complete)
	require.NotContains(t, otherAPI.Relations.Related, "example_link",
		"a missing explicit reference cannot invalidate another API's reverse relation set")
	require.NotContains(t, otherAPI.Relations.Referrers, "target_id",
		"a missing explicit reference cannot invalidate another API's referrer set")
}

func TestIncompleteRootScopePreservesDefiniteHCLRelations(t *testing.T) {
	fs := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
module "unavailable" {
	  source  = "example/remote/module"
	  version = "1.0.0"
}

resource "example_trail" "audit" {
  bucket_id = example_bucket.logs.id
}

resource "example_trail" "module_ref" {
  bucket_id = module.unavailable.bucket_id
}

resource "example_bucket" "logs" {
  name = "audit-logs"
}

resource "example_bucket_acl" "public" {
  bucket = example_bucket.logs.id
  acl    = "public-read"
}

`),
	})
	unit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(fs), "/repo", &RootOptions{
		FS: fs, RepoPath: "/repo", ComputeRelations: true,
	})
	require.NoError(t, err)
	require.False(t, unit.ScopeComplete)
	byAddr := map[string]*policy.Resource{}
	for _, resource := range unit.Resources {
		byAddr[resource.Address] = resource
	}
	trail := byAddr["example_trail.audit"]
	moduleTrail := byAddr["example_trail.module_ref"]
	bucket := byAddr["example_bucket.logs"]
	acl := byAddr["example_bucket_acl.public"]
	require.NotNil(t, trail)
	require.NotNil(t, moduleTrail)
	require.NotNil(t, bucket)
	require.NotNil(t, acl)
	require.Equal(t, []string{bucket.ID}, trail.Relations.Targets["bucket_id"].IDs)
	require.False(t, trail.Relations.Targets["bucket_id"].Complete)
	require.False(t, moduleTrail.Relations.Targets["bucket_id"].Complete)
	require.Equal(t, []string{acl.ID}, bucket.Relations.Related["example_bucket_acl"]["bucket"].IDs)
	require.False(t, bucket.Relations.Related["example_bucket_acl"]["bucket"].Complete)
}

func TestUnknownLocalIndexDoesNotInventDefiniteTargets(t *testing.T) {
	fs := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
variable "selected" {}
resource "aws_s3_bucket" "first" { bucket = "first" }
resource "aws_s3_bucket" "second" { bucket = "second" }
locals {
  buckets = [aws_s3_bucket.first.bucket, aws_s3_bucket.second.bucket]
}
resource "aws_s3_bucket_versioning" "unknown" {
  bucket = local.buckets[var.selected]
}
`),
	})
	unit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(fs), "/repo", &RootOptions{
		FS: fs, RepoPath: "/repo", ComputeRelations: true,
	})
	require.NoError(t, err)
	var consumer *policy.Resource
	for _, resource := range unit.Resources {
		if resource.Address == "aws_s3_bucket_versioning.unknown" {
			consumer = resource
		}
	}
	require.NotNil(t, consumer)
	require.Empty(t, consumer.Relations.Targets["bucket"].IDs)
	require.False(t, consumer.Relations.Targets["bucket"].Complete)
}

func TestPlanNestedWrittenAndComputedStates(t *testing.T) {
	source := []byte(`{
 "configuration":{"root_module":{"resources":[{
  "address":"example_workload.test",
  "provisioners":[{"type":"local-exec","expressions":{"command":{"constant_value":"echo configured"},"environment":{"references":["var.environment"]},"working_dir":{"constant_value":null}}}],
  "expressions":{"script":{"constant_value":"configured text"},"management":{"constant_value":null},"explicit":{"constant_value":"configured"},"pending":{"references":["var.pending"]},"dynamic":{"references":["var.dynamic"]},"settings":{"constant_value":{"configured":true,"nested_null":null}},"spec":[{"container":[
   {"name":{"constant_value":"first"},"literal":{"constant_value":""},"nil_literal":{"constant_value":null},"options":{"references":["var.options"]}},
   {"name":{"constant_value":"second"},"resources":[{"requests":{"constant_value":{"cpu":"1"}}}]}
  ]}]}
 }]}},
 "planned_values":{"root_module":{"resources":[{
  "address":"example_workload.test","type":"example_workload","name":"test","mode":"managed",
  "values":{"script":"provider-normalized-digest","management":"provider-default","explicit":"provider-normalized","pending":null,"dynamic":null,"settings":{"configured":true,"nested_null":"defaulted"},"spec":[{"container":[
   {"name":"first","literal":"","nil_literal":null,"resources":[],"options":{"known":"yes","pending":null},"defaulted":false},
   {"name":"second","resources":[{"requests":{"cpu":"1"},"limits":null}]}
  ]}]}
 }]}},
 "resource_changes":[{"address":"example_workload.test","change":{"after_unknown":{"pending":true,"dynamic":true,"spec":[{"container":[
  {"resources":true,"literal":true,"nil_literal":true,"options":{"pending":true}},
  {"resources":[{"limits":true,"requests":{}}]}
 ]}]}}}]
 }`)
	unit, err := BuildUnitFromPlan("/repo/plan.json", source, &RootOptions{RepoPath: "/repo", Derive: DeriveOptions{ParseJSON: true}})
	require.NoError(t, err)
	require.Len(t, unit.Resources, 1)
	resource := unit.Resources[0]
	require.Equal(t, "provider-normalized-digest", resource.Attributes["script"])
	require.Equal(t, []policy.TemplatePart{{Known: true, Value: "configured text"}}, resource.Derived.TemplateParts["script"])
	provisioner := resource.Attributes["provisioner"].([]any)[0].(map[string]any)["local-exec"].([]any)[0].(map[string]any)
	require.Equal(t, "echo configured", provisioner["command"])
	require.NotContains(t, provisioner, "environment")
	require.True(t, resource.State.Unknown["provisioner.0.local-exec.0.environment"])
	require.True(t, resource.State.Null["provisioner.0.local-exec.0.working_dir"])
	require.True(t, resource.State.Written["provisioner.0.local-exec.0.command"])
	provisionerLine := 1 + strings.Count(string(source[:strings.Index(string(source), `"provisioners":`)]), "\n")
	require.Equal(t, provisionerLine, resource.Source.Range(policy.Path{policy.Key("provisioner"), policy.Index(0), policy.Key("local-exec"), policy.Index(0)}).StartLine)
	containers := resource.Attributes["spec"].([]any)[0].(map[string]any)["container"].([]any)
	first := containers[0].(map[string]any)
	second := containers[1].(map[string]any)
	require.Equal(t, "", first["literal"])
	require.NotContains(t, first, "nil_literal")
	require.True(t, resource.State.Null["spec.0.container.0.nil_literal"])
	require.False(t, resource.State.Unknown["spec.0.container.0.literal"])
	require.False(t, resource.State.Unknown["spec.0.container.0.nil_literal"])
	require.NotContains(t, first, "resources")
	require.NotContains(t, first, "defaulted")
	require.False(t, resource.State.Unknown["spec.0.container.0.resources"])
	require.False(t, resource.State.Unknown["spec.0.container.1.resources.0.limits"])
	require.True(t, resource.State.Unknown["spec.0.container.0.options.pending"])
	require.NotContains(t, first["options"].(map[string]any), "pending")
	require.NotContains(t, second["resources"].([]any)[0].(map[string]any), "limits")
	require.True(t, resource.State.Written["spec.0.container.1.resources.0.requests"])
	computed := resource.Platform["terraform"].(map[string]any)["computed"].(map[string]any)
	computedFirst := computed["spec"].([]any)[0].(map[string]any)["container"].([]any)[0].(map[string]any)
	require.Equal(t, false, computedFirst["defaulted"])
	require.NotContains(t, computedFirst, "resources", "unknown computed defaults remain unavailable")
	computedState := resource.Platform["terraform"].(map[string]any)["computed_state"].(map[string]any)
	require.Equal(t, true, computedState["unknown"].(map[string]any)["spec.0.container.0.resources"])
	computedSecond := computed["spec"].([]any)[0].(map[string]any)["container"].([]any)[1].(map[string]any)
	require.NotContains(t, computedSecond["resources"].([]any)[0].(map[string]any), "limits")
	sourceNull := resource.Platform["terraform"].(map[string]any)["source_null"].(map[string]bool)
	require.Equal(t, map[string]bool{
		"management":                             true,
		"provisioner.0.local-exec.0.working_dir": true,
		"settings.nested_null":                   true,
		"spec.0.container.0.nil_literal":         true,
	}, sourceNull)
	require.Equal(t, "provider-default", resource.Attributes["management"], "known provider defaults remain in runtime attributes")
	require.Equal(t, "provider-normalized", resource.Attributes["explicit"])
	require.True(t, resource.State.Unknown["pending"])
	require.True(t, resource.State.Unknown["dynamic"])

}

func TestPlanCountIndexRelationsAreInstanceScoped(t *testing.T) {
	raw := []byte(`{
 "configuration":{"root_module":{"resources":[
  {"address":"example_link.counted","type":"example_link","name":"counted","count_expression":{"constant_value":1},"expressions":{"target":{"references":["example_subnet.app[count.index].id"]}}},
  {"address":"example_link.dynamic","type":"example_link","name":"dynamic","expressions":{"target":{"references":["example_subnet.app[var.selected].id"]}}},
  {"address":"example_link.mixed","type":"example_link","name":"mixed","count_expression":{"constant_value":1},"expressions":{"target":{"references":["example_subnet.app[count.index][var.selected].id"]}}}
 ]}},
 "planned_values":{"root_module":{"resources":[
  {"address":"example_subnet.app[0]","mode":"managed","type":"example_subnet","name":"app","values":{"id":"subnet-0"}},
  {"address":"example_subnet.app[1]","mode":"managed","type":"example_subnet","name":"app","values":{"id":"subnet-1"}},
  {"address":"example_link.counted[0]","mode":"managed","type":"example_link","name":"counted","values":{"target":null}},
  {"address":"example_link.dynamic","mode":"managed","type":"example_link","name":"dynamic","values":{"target":null}},
  {"address":"example_link.mixed[0]","mode":"managed","type":"example_link","name":"mixed","values":{"target":null}}
 ]}},
 "resource_changes":[
  {"address":"example_link.counted[0]","change":{"after_unknown":{"target":true}}},
  {"address":"example_link.dynamic","change":{"after_unknown":{"target":true}}},
  {"address":"example_link.mixed[0]","change":{"after_unknown":{"target":true}}}
 ]
}`)
	unit, err := BuildUnitFromPlan("/repo/plan.json", raw, &RootOptions{RepoPath: "/repo", ComputeRelations: true})
	require.NoError(t, err)
	byAddress := make(map[string]*policy.Resource, len(unit.Resources))
	for _, resource := range unit.Resources {
		byAddress[resource.Address] = resource
	}
	counted := byAddress["example_link.counted[0]"]
	dynamic := byAddress["example_link.dynamic"]
	mixed := byAddress["example_link.mixed[0]"]
	require.NotNil(t, counted)
	require.NotNil(t, dynamic)
	require.NotNil(t, mixed)
	require.Equal(t, []string{byAddress["example_subnet.app[0]"].ID}, counted.Relations.Targets["target"].IDs)
	require.True(t, counted.Relations.Targets["target"].Complete)
	require.Empty(t, dynamic.Relations.Targets["target"].IDs, "an unresolved selector must not invent a definite edge")
	require.False(t, dynamic.Relations.Targets["target"].Complete)
	require.Empty(t, mixed.Relations.Targets["target"].IDs, "an unresolved selector remains unknown after binding a separate count.index")
	require.False(t, mixed.Relations.Targets["target"].Complete)
}

func TestPlanCountIndexBindingRequiresNumericSourceInstance(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sourceAddr string
		ref        string
		want       string
		unbound    bool
	}{
		{
			name:       "numeric count instance",
			sourceAddr: "example_link.counted[2]",
			ref:        "example_target.app[count.index].id",
			want:       "example_target.app[2].id",
		},
		{
			name:       "string keyed source remains dynamic",
			sourceAddr: `example_link.for_each["2"]`,
			ref:        "example_target.app[count.index].id",
			want:       "example_target.app[count.index].id",
			unbound:    true,
		},
		{
			name:       "count token inside literal key is unchanged",
			sourceAddr: "example_link.counted[2]",
			ref:        `example_target.app["[count.index]"].id`,
			want:       `example_target.app["[count.index]"].id`,
		},
		{
			name:       "unresolved selector remains after binding count index",
			sourceAddr: "example_link.counted[2]",
			ref:        "example_target.app[count.index][var.selected].id",
			want:       "example_target.app[2][var.selected].id",
			unbound:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := bindPlanCountIndex(tc.ref, tc.sourceAddr)
			require.Equal(t, tc.want, got)
			require.Equal(t, tc.unbound, hasUnboundPlanIndex(got))
		})
	}
	require.False(t, hasUnboundPlanIndex(`example_target.app["[count.index]"]`))
	require.True(t, hasUnboundPlanIndex("example_target.app[var.selected]"))
	require.True(t, hasUnboundPlanIndex("example_target.app[count.index]"))
}

func TestPlanConfigurationRangesForModuleInstances(t *testing.T) {
	raw := []byte(`{
 "planned_values":{"root_module":{"child_modules":[{
  "address":"module.child[\"key\"]",
  "resources":[{"address":"module.child[\"key\"].example_resource.test","type":"example_resource","name":"test","mode":"managed","values":{}}]
 }]}},
 "configuration":{"root_module":{"module_calls":{"child":{"module":{"resources":[{
  "address":"example_resource.test",
  "expressions":{
   "target_id":{"references":["var.target_id"]}
  }
 }]}}}}}
 }`)
	unit, err := BuildUnitFromPlan("/repo/plan.json", raw, &RootOptions{RepoPath: "/repo"})
	require.NoError(t, err)
	require.Len(t, unit.Resources, 1)
	expectedLine := 1 + strings.Count(string(raw[:strings.Index(string(raw), `"target_id":`)]), "\n")
	require.Equal(t, expectedLine, unit.Resources[0].Source.Range(policy.Path{policy.Key("target_id")}).StartLine)
}

func TestEmbeddedJSONAttributeSourceRanges(t *testing.T) {
	cases := map[string]string{
		"jsonencode": `payload = jsonencode({
 items = [
  { name = "first" },
  { name = var.unknown }
 ]
})`,
		"heredoc": `payload = <<JSON

{
 "items": [
  {"name": "first"},
  {"name": "second"}
 ]
}
JSON`,
		"partial_heredoc": `payload = <<JSON
{
 "items": [
  {"name": "first"},
  {"name": "${var.unknown}"}
 ]
}
JSON`,
	}
	for name, expression := range cases {
		t.Run(name, func(t *testing.T) {
			raw := "variable \"unknown\" {}\nresource \"example_resource\" \"test\" {\n" + expression + "\n}\n"
			fs := vfs.NewMemFS(map[string][]byte{"/repo/main.tf": []byte(raw)})
			evaluator := tfeval.NewWithFS(fs)
			defer evaluator.ReleaseCaches()
			unit, err := EvaluateRoot(context.Background(), evaluator, "/repo", &RootOptions{FS: fs, RepoPath: "/repo"})
			require.NoError(t, err)
			require.Len(t, unit.Resources, 1)
			var expected []int
			for index, line := range strings.Split(raw, "\n") {
				if strings.Contains(line, "name") {
					expected = append(expected, index+1)
				}
			}
			require.Len(t, expected, 2)
			for index, line := range expected {
				path := policy.Path{policy.Key("payload"), policy.Key("items"), policy.Index(int64(index)), policy.Key("name")}
				require.Equal(t, line, unit.Resources[0].Source.Range(path).StartLine)
			}
		})
	}
}

func TestPlanNestedSetsMatchWrittenFieldsByKnownIdentity(t *testing.T) {
	raw := []byte(`{
 "configuration":{"root_module":{"resources":[{
  "address":"example_resource.test", "expressions":{"rule":[
   {"name":{"constant_value":"first"},"optional":{"references":["var.optional"]},"enabled":{"constant_value":null}},
   {"name":{"constant_value":"second"}}
  ]}
 }]}},
 "planned_values":{"root_module":{"resources":[{
  "address":"example_resource.test","mode":"managed","type":"example_resource","name":"test",
  "values":{"rule":[{"name":"second","enabled":"provider-default"},{"name":"first","enabled":"provider-default"}]}
 }]}},
 "resource_changes":[{"address":"example_resource.test","change":{"after_unknown":{"rule":[{"optional":true},{"optional":true}]}}}]
 }`)
	unit, err := BuildUnitFromPlan("/repo/plan.json", raw, &RootOptions{RepoPath: "/repo"})
	require.NoError(t, err)
	require.Len(t, unit.Resources, 1)
	state := unit.Resources[0].State
	require.False(t, state.Written["rule.0.optional"])
	require.False(t, state.Unknown["rule.0.optional"])
	require.True(t, state.Written["rule.1.optional"])
	require.True(t, state.Unknown["rule.1.optional"])
	sourceNull := unit.Resources[0].Platform["terraform"].(map[string]any)["source_null"].(map[string]bool)
	require.Equal(t, map[string]bool{"rule.1.enabled": true}, sourceNull,
		"the source null follows its matching nested set element after provider reordering")
	expectedLine := 1 + strings.Count(string(raw[:strings.Index(string(raw), `"optional":{"references"`)]), "\n")
	require.Equal(t, expectedLine, unit.Resources[0].Source.Range(policy.Path{policy.Key("rule"), policy.Index(1), policy.Key("optional")}).StartLine)
}

func TestPlanStaticDeclarationsPreserveDescriptionAndScope(t *testing.T) {
	raw := []byte(`{
 "planned_values":{"outputs":{"root":{"value":"ok"}},"root_module":{"resources":[]}},
 "configuration":{"root_module":{
  "variables":{"root":{"description":"root variable","default":"ok"}},
  "outputs":{"root":{"expression":{"references":["var.root"]}}},
  "module_calls":{"child":{"source":"git::https://example.invalid/module.git","expressions":{},"module":{
   "variables":{"inner":{"default":null}},
   "outputs":{"inner":{"description":"child output","expression":{"constant_value":"ok"}}}
  }}}
 }}
 }`)
	without, err := BuildUnitFromPlan("/repo/plan.json", raw, &RootOptions{RepoPath: "/repo"})
	require.NoError(t, err)
	require.Empty(t, without.Resources)
	unit, err := BuildUnitFromPlan("/repo/plan.json", raw, &RootOptions{RepoPath: "/repo", NeedStaticBlocks: true})
	require.NoError(t, err)
	require.Len(t, unit.Resources, 5)
	byAddress := map[string]*policy.Resource{}
	for _, resource := range unit.Resources {
		byAddress[resource.Address] = resource
	}
	require.Equal(t, "root variable", byAddress["var.root"].Attributes["description"])
	require.True(t, byAddress["var.root"].State.Unknown["type"], "Plan format cannot prove an omitted source type constraint")
	require.True(t, byAddress["module.child.var.inner"].State.Null["default"])
	require.Equal(t, "git::https://example.invalid/module.git", byAddress["module.child"].Attributes["source"])
	require.Equal(t, "child output", byAddress["module.child.output.inner"].Attributes["description"])
	require.True(t, byAddress["module.child.output.inner"].Source.StaticInModule)
	require.Equal(t, 2, byAddress["output.root"].Source.Range(nil).StartLine)
}

func TestPlanDeferredDataInputsAndInstanceBoundaries(t *testing.T) {
	raw := []byte(`{
 "planned_values":{"root_module":{
  "resources":[{"address":"example_link.test","type":"example_link","name":"test","values":{"target":null}}],
  "child_modules":[
   {"address":"module.expanded[\"known\"]","resources":[]},
   {"address":"module.truncated[\"observed\"]","resources":[]},
   {"address":"module.outer[\"parent\"]","resources":[],"child_modules":[
    {"address":"module.outer[\"parent\"].module.inner[\"child\"]","resources":[]}
   ]},
   {"address":"module.dual[\"a\"]","resources":[]},
   {"address":"module.dual[\"b\"]","resources":[],"child_modules":[
    {"address":"module.dual[\"b\"].module.child","resources":[]}
   ]}
  ]
 }},
 "configuration":{"root_module":{
  "resources":[
   {"address":"example_link.test","type":"example_link","name":"test","expressions":{"target":{"references":["data.example_lookup.key.id"]}}},
   {"address":"data.example_lookup.key","type":"example_lookup","mode":"data","name":"key","expressions":{"selector":{"constant_value":"named-key"},"pending":{"references":["var.pending"]}}},
   {"address":"data.example_lookup.zero","type":"example_lookup","mode":"data","name":"zero","count_expression":{"constant_value":0},"expressions":{}},
   {"address":"data.example_lookup.keys","type":"example_lookup","mode":"data","name":"keys","for_each_expression":{"references":["var.keys"]},"expressions":{}},
   {"address":"example_managed.absent","type":"example_managed","name":"absent","expressions":{}}
  ],
  "module_calls":{
   "static":{"module":{"resources":[{"address":"data.example_lookup.child","type":"example_lookup","mode":"data","name":"child","expressions":{"selector":{"constant_value":"static"}}}]}},
   "expanded":{"for_each_expression":{"references":["var.keys"]},"module":{"resources":[{"address":"data.example_lookup.child","type":"example_lookup","mode":"data","name":"child","expressions":{"selector":{"constant_value":"expanded"}}}]}},
   "unobserved":{"count_expression":{"constant_value":0},"module":{"resources":[{"address":"data.example_lookup.child","type":"example_lookup","mode":"data","name":"child","expressions":{}}]}},
   "truncated":{"module":{"resources":[{"address":"data.example_lookup.child","type":"example_lookup","mode":"data","name":"child","expressions":{"selector":{"constant_value":"truncated"}}}]}},
   "outer":{"module":{"module_calls":{"inner":{"module":{"resources":[{"address":"data.example_lookup.child","type":"example_lookup","mode":"data","name":"child","expressions":{"selector":{"constant_value":"nested"}}}]}}}}},
   "dual":{"module":{"module_calls":{"child":{"module":{"resources":[{"address":"data.example_lookup.child","type":"example_lookup","mode":"data","name":"child","expressions":{"selector":{"constant_value":"dual"}}}]}}}}}
  }
 }},
 "resource_changes":[{"address":"example_link.test","change":{"after_unknown":{"target":true}}}]
 }`)
	unit, err := BuildUnitFromPlan("/repo/plan.json", raw, &RootOptions{RepoPath: "/repo", ComputeRelations: true})
	require.NoError(t, err)
	resources := map[string]*policy.Resource{}
	moduleCalls := map[string]*policy.Resource{}
	for _, resource := range unit.Resources {
		if resource.Kind == address.KindModule {
			moduleCalls[resource.Address] = resource
			continue
		}
		resources[resource.Address] = resource
	}
	require.Len(t, resources, 8, "relation computation keeps the evaluated resource/data set unchanged")
	require.Len(t, moduleCalls, 8, "relation computation models each plan module call")
	require.Contains(t, moduleCalls, "module.static")
	lookup := resources["data.example_lookup.key"]
	require.NotNil(t, lookup)
	require.Equal(t, "named-key", lookup.Attributes["selector"])
	require.True(t, lookup.State.Written["selector"])
	require.True(t, lookup.State.Unknown["pending"])
	computedState := lookup.Platform["terraform"].(map[string]any)["computed_state"].(map[string]any)
	require.Equal(t, true, computedState["unknown"].(map[string]any)[""])
	require.Equal(t, []string{lookup.ID}, resources["example_link.test"].Relations.Targets["target"].IDs)
	require.Contains(t, resources, "module.static.data.example_lookup.child")
	require.Contains(t, resources, `module.expanded["known"].data.example_lookup.child`)
	require.Contains(t, resources, `module.truncated["observed"].data.example_lookup.child`)
	require.NotContains(t, resources, "module.truncated.data.example_lookup.child")
	require.Contains(t, resources, `module.outer["parent"].module.inner["child"].data.example_lookup.child`)
	require.NotContains(t, resources, "module.outer.data.example_lookup.child")
	require.NotContains(t, resources, `module.outer["parent"].module.inner.data.example_lookup.child`)
	require.Contains(t, resources, `module.dual["a"].module.child.data.example_lookup.child`,
		"an unkeyed child under a different keyed parent must not suppress scalar child discovery")
	require.Contains(t, resources, `module.dual["b"].module.child.data.example_lookup.child`)
	require.NotContains(t, resources, "module.dual.data.example_lookup.child")
}

func TestOverrideContractSourceAndRemediation(t *testing.T) {
	for name, source := range map[string]string{
		"override.tf":      "resource \"example_resource\" \"test\" {\n  enabled = false\n}\n",
		"override.tf.json": `{ "resource": { "example_resource": { "test": { "enabled": false } } } }`,
	} {
		t.Run(name, func(t *testing.T) {
			fs := vfs.NewMemFS(map[string][]byte{
				"/repo/main.tf": []byte("# declaration\nresource \"example_resource\" \"test\" {\n  enabled = true\n}\n"),
				"/repo/" + name: []byte(source),
			})
			evaluator := tfeval.NewWithFS(fs)
			defer evaluator.ReleaseCaches()
			unit, err := EvaluateRoot(t.Context(), evaluator, "/repo", &RootOptions{RepoPath: "/repo", FS: fs})
			require.NoError(t, err)
			require.Len(t, unit.Resources, 1)
			resource := unit.Resources[0]
			require.Equal(t, false, resource.Attributes["enabled"])
			require.Equal(t, 2, resource.Source.OverrideInventoryLine)
			require.Equal(t, "/repo/"+name, filepath.ToSlash(resource.Source.Range(policy.Path{policy.Key("enabled")}).File))
			before, known := resource.Source.BeforeValue(policy.Path{policy.Key("enabled")})
			require.True(t, known)
			require.Equal(t, "false", before)
		})
	}
}

func TestOverrideFileVarsDriveRelationsAndPartialJSON(t *testing.T) {
	fs := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf": []byte(`
variable "selected" { default = 0 }
variable "action" { default = "s3:ListBucket" }
variable "unknown_value" {}

locals {
  targets = [example_target.first.id, example_target.second.id]
}

resource "example_target" "first" {
  name = "first"
}

resource "example_target" "second" {
  name = "second"
}

resource "example_link" "base" {
  target = local.targets[var.selected]
  policy = jsonencode({
    Statement = [{ Action = var.action, Resource = var.unknown_value }]
  })
}

resource "example_link" "overridden" {
  target = local.targets[0]
  policy = jsonencode({
    Statement = [{ Action = var.action, Resource = var.unknown_value }]
  })
}
`),
		"/repo/override.tf": []byte(`// kics_terraform_vars: selected.tfvars
resource "example_link" "overridden" {
  target = local.targets[var.selected]
  policy = jsonencode({
    Statement = [{ Action = var.action, Resource = var.unknown_value }]
  })
}
`),
		"/repo/selected.tfvars": []byte("selected = 1\naction = \"s3:GetObject\"\n"),
	})

	unit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(fs), "/repo", &RootOptions{
		FS: fs, RepoPath: "/repo", ComputeRelations: true,
		Derive: DeriveOptions{ParseJSON: true},
	})
	require.NoError(t, err)
	byAddress := make(map[string]*policy.Resource, len(unit.Resources))
	for _, resource := range unit.Resources {
		byAddress[resource.Address] = resource
	}
	first := byAddress["example_target.first"]
	second := byAddress["example_target.second"]
	base := byAddress["example_link.base"]
	overridden := byAddress["example_link.overridden"]
	require.NotNil(t, first)
	require.NotNil(t, second)
	require.NotNil(t, base)
	require.NotNil(t, overridden)
	require.Equal(t, []string{first.ID}, base.Relations.Targets["target"].IDs,
		"the declaration uses the variable default and indexes the first target")
	require.Equal(t, []string{second.ID}, overridden.Relations.Targets["target"].IDs,
		"the override expression uses selected.tfvars and indexes the second target")

	require.NotNil(t, overridden.Derived)
	statement := overridden.Derived.JSON["policy"].(map[string]any)["Statement"].([]any)[0].(map[string]any)
	require.Equal(t, "s3:GetObject", statement["Action"],
		"partial JSON derivation uses the selected file's known variable value")
	require.True(t, overridden.Derived.JSONUnknown["policy"]["Statement.0.Resource"],
		"the unresolved JSON leaf remains explicitly unknown")
	require.True(t, overridden.Relations.Targets["target"].Complete, "target relation: %+v", overridden.Relations.Targets["target"])

	t.Run("dynamic block expansion uses its source file bindings", func(t *testing.T) {
		fs := vfs.NewMemFS(map[string][]byte{
			"/repo/main.tf": []byte(`
variable "selected_indexes" { default = [0] }
locals { targets = [example_target.first.id, example_target.second.id] }
resource "example_target" "first" {}
resource "example_target" "second" {}
resource "example_link" "dynamic" {}
`),
			"/repo/override.tf": []byte(`// kics_terraform_vars: selected.tfvars
resource "example_link" "dynamic" {
  dynamic "association" {
    for_each = var.selected_indexes
    content {
      target_id = local.targets[association.value]
    }
  }
}
`),
			"/repo/selected.tfvars": []byte("selected_indexes = [1]\n"),
		})
		unit, err := EvaluateRoot(context.Background(), tfeval.NewWithFS(fs), "/repo", &RootOptions{
			FS: fs, RepoPath: "/repo", ComputeRelations: true,
		})
		require.NoError(t, err)
		byAddress := make(map[string]*policy.Resource, len(unit.Resources))
		for _, resource := range unit.Resources {
			byAddress[resource.Address] = resource
		}
		link := byAddress["example_link.dynamic"]
		target := byAddress["example_target.second"]
		require.NotNil(t, link)
		require.NotNil(t, target)
		require.Equal(t, []string{target.ID}, link.Relations.Targets["association.0.target_id"].IDs)
	})
}

func BenchmarkBuildUnitInstanceSet(b *testing.B) {
	for _, n := range []int{100, 1000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			fs := vfs.NewMemFS(map[string][]byte{"/repo/main.tf": []byte(fmt.Sprintf(`resource "example_item" "many" { for_each = { for i in range(%d) : tostring(i) => i } }`, n))})
			evaluator := tfeval.NewWithFS(fs)
			defer evaluator.ReleaseCaches()
			ctx := context.Background()
			resources, _, _, err := evaluator.EvaluateModule(ctx, "/repo", evaluator.LoadRootVarsWithContext(ctx, "/repo"))
			require.NoError(b, err)
			require.Len(b, resources, n)
			opts := &RootOptions{RootScope: evaluator.LastRootScope()}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				BuildUnitFromEval("/repo", resources, opts)
			}
		})
	}
}
