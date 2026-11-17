/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/schedule"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/unknowngate"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/stretchr/testify/require"
	"time"
)

// Gate failures must stop decoding, including the deferred path used for relational roots.
func TestGateErrorsFailBeforeFindingDecode(t *testing.T) {
	buildErr := errors.New("gate construction failed")
	for _, mode := range []string{"immediate", "deferred"} {
		for _, failure := range []string{"construction", "evaluation", "cancellation"} {
			t.Run(mode+"/"+failure, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var reachedGate bool
				newGate := func() (*unknowngate.Gate, error) {
					reachedGate = true
					if failure == "construction" {
						return nil, buildErr
					}
					gate := failingEvaluationGate(t)
					if failure == "cancellation" {
						cancel()
					}
					return gate, nil
				}
				ins, qCtx, decodes := gateFailureContext(t, ctx, newGate)
				qCtx.deferDecode = mode == "deferred"
				findings, _, _, err := ins.doRun(ctx, qCtx)
				require.True(t, reachedGate)
				require.Error(t, err)
				require.Empty(t, findings)
				require.Nil(t, qCtx.deferred, "unchecked results must not be queued for later decoding")
				require.Zero(t, *decodes, "a gate error must stop before the vulnerability builder")
				switch failure {
				case "construction":
					require.ErrorIs(t, err, buildErr)
				case "evaluation":
					require.ErrorContains(t, err, "check Terraform unknown values")
					require.ErrorContains(t, err, "eval_conflict_error")
				case "cancellation":
					require.True(t, isQueryCancellation(err), "%v", err)
				}
			})
		}
	}
}

func failingEvaluationGate(t *testing.T) *unknowngate.Gate {
	t.Helper()
	gate, err := unknowngate.New(unknowngate.Options{
		Placeholder: "ph", Query: "data.check.DatadogPolicy",
		Modules: map[string]*ast.Module{"check": ast.MustParseModule(`package check
import rego.v1
choice := 1 if input._dd.placeholder == "ph"
choice := 2 if input._dd.placeholder == "ph"
DatadogPolicy contains {"_dd_id": "b1"} if choice > 0
`)},
	})
	require.NoError(t, err)
	return gate
}

func gateFailureContext(
	t *testing.T, ctx context.Context, newGate func() (*unknowngate.Gate, error),
) (*Inspector, *QueryContext, *int) {
	t.Helper()
	query, err := rego.New(rego.Query(`result := [{"_dd_id": "b1"}]`)).PrepareForEval(ctx)
	require.NoError(t, err)
	metadata := model.QueryMetadata{Query: "failing", Platform: "Terraform", Metadata: map[string]interface{}{"id": "failing-id"}}
	input := ast.MustParseTerm(`{"_dd": {"placeholder": "ph"}}`).Value
	block := ast.MustParseTerm(`{"_dd_meta": {"id": "b1"}, "value": "ph"}`)
	in := &terraformInput{
		projection: &project.Projection{Input: input, Blocks: map[string]*project.Located{
			"b1": {Placeholder: true, Kind: "resource", Type: "test_resource", Term: block},
		}},
		placeholder: "ph",
		rules: &terraformRules{byKey: map[string]*terraformRule{
			terraformQueryKey(&metadata): {harvest: schedule.Rule{Class: schedule.Anchored}, newGate: newGate},
		}},
	}
	decodes := new(int)
	ins := newTestInspector(t, inspectorOpts{vb: func(
		_ context.Context, _ *QueryContext, _ Tracker, _ interface{}, _ *detector.DetectLine, _ bool, _ time.Duration,
	) (*model.Vulnerability, error) {
		*decodes++
		return nil, ErrNoResult
	}})
	qCtx := &QueryContext{Ctx: ctx, Query: &PreparedQuery{Metadata: metadata, OpaQuery: query}, payload: &input, terraform: in}
	return ins, qCtx, decodes
}

func TestGateCancellationAbortsWorkerPools(t *testing.T) {
	for _, mode := range []string{"ordinary", "relational"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background() // The parent stays active; the query itself reports cancellation.
			ins, qCtx, decodes := gateFailureContext(t, ctx, func() (*unknowngate.Gate, error) {
				return nil, &topdown.Error{Code: topdown.CancelErr, Message: "evaluation canceled"}
			})
			queries := []model.QueryMetadata{qCtx.Query.Metadata}
			run := newQueryRun("gate-cancellation", nil, queries)
			run.sharedQueries = map[int]*rego.PreparedEvalQuery{0: &qCtx.Query.OpaQuery}
			payload := platformPayloads{full: *qCtx.payload, terraform: qCtx.terraform}
			var err error
			if mode == "ordinary" {
				err = ins.executeQueries(ctx, run, payload, nil, 1)
			} else {
				key := terraformQueryKey(&queries[0])
				plan := schedule.Plan{Relational: []schedule.RootRun{{Root: "root", Rules: []string{key}}}}
				roots := map[string]*terraformRoot{"root": {input: qCtx.terraform}}
				_, err = ins.evalRelationalRoots(ctx, &terraformRun{ready: queries, queries: run}, plan, roots, map[string]int{key: 0})
			}
			require.True(t, topdown.IsCancel(err), "%v", err)
			require.NoError(t, ctx.Err())
			require.Zero(t, *decodes)
			require.Empty(t, run.tally, "canceled work must not reach successful aggregation")
			require.Empty(t, run.findings(false))
		})
	}
}

func TestGateRejectsUncheckedResults(t *testing.T) {
	_, qCtx, _ := gateFailureContext(t, context.Background(), func() (*unknowngate.Gate, error) {
		return nil, errors.New("unexpected gate construction")
	})
	in := qCtx.terraform
	for _, results := range []rego.ResultSet{nil, {{Bindings: rego.Vars{"result": []interface{}{}}}}} {
		require.NoError(t, in.gateResults(context.Background(), qCtx, *qCtx.payload, results))
	}
	in.rules = nil
	results := rego.ResultSet{{Bindings: rego.Vars{"result": []interface{}{map[string]interface{}{"_dd_id": "b1"}}}}}
	require.ErrorContains(t, in.gateResults(context.Background(), qCtx, *qCtx.payload, results), "unknown gate missing")
}

const relationalFixture = `
resource "aws_s3_bucket" "b" {
  bucket = "b"
}
resource "aws_s3_bucket_versioning" "v" {
  bucket = aws_s3_bucket.b.id
}
resource "aws_s3_bucket" "other" {
  bucket = "other"
}
resource "aws_instance" "unrelated" {}
`

func projectFixture(t *testing.T, files map[string]string) *terraformInput {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	scan, err := tfmodel.Load(context.Background(), dir, &tfmodel.Options{})
	require.NoError(t, err)
	proj := project.Project(scan.Roots, project.Options{Placeholder: "ph"})
	return &terraformInput{projection: proj, placeholder: "ph"}
}

// The minimal input of a relational rule holds the blocks of the types it
// reads, what they relate to, and nothing else.
func TestRelationalInputHoldsTheReadTypesAndTheirRelations(t *testing.T) {
	in := projectFixture(t, map[string]string{"main.tf": relationalFixture})
	var root string
	for _, loc := range in.projection.Blocks {
		root = loc.Root
	}
	types := []schedule.TypeKey{{Kind: schedule.KindResource, Type: "aws_s3_bucket"}}

	narrow := in.relationalInput(root, types, in.projection.Input)

	raw, err := ast.JSON(narrow)
	require.NoError(t, err)
	dd := raw.(map[string]any)["_dd"].(map[string]any)
	buckets := dd["blocks"].(map[string]any)["resource"].(map[string]any)
	require.Len(t, buckets["aws_s3_bucket"], 2)
	require.NotContains(t, buckets, "aws_instance")
	require.NotContains(t, buckets, "aws_s3_bucket_versioning")

	byID := dd["by_id"].(map[string]any)
	var companion string
	for id, v := range byID {
		if v.(map[string]any)["_dd_meta"].(map[string]any)["type"] == "aws_s3_bucket_versioning" {
			companion = id
		}
	}
	require.NotEmpty(t, companion, "the companion is reachable through the relation")
	for id, loc := range in.projection.Blocks {
		if loc.Type == "aws_instance" {
			require.NotContains(t, byID, id)
		}
	}
	require.NotEmpty(t, dd["related"])
	require.Equal(t, "ph", dd["placeholder"])
}

// A nested block list is read by key, so the minimal inputs of the anchored
// and relational rules keep the entry of each block they hold.
func TestMinimalInputsKeepNestedBlocks(t *testing.T) {
	in := projectFixture(t, map[string]string{"main.tf": `
resource "aws_security_group" "sg" {
  ingress {
    from_port = 1
  }
}
resource "aws_s3_bucket" "b" {
  bucket = "b"
}
`})
	var sgID string
	var sg *project.Located
	for id, loc := range in.projection.Blocks {
		if loc.Type == "aws_security_group" {
			sgID, sg = id, loc
		}
	}
	require.NotEmpty(t, sgID)

	nestedOf := func(v ast.Value) map[string]any {
		raw, err := ast.JSON(v)
		require.NoError(t, err)
		dd := raw.(map[string]any)["_dd"].(map[string]any)
		return dd["nested"].(map[string]any)
	}

	anchored := nestedOf(anchoredInput(sg, in.projection.Input))
	require.Contains(t, anchored, sgID)
	require.Contains(t, anchored[sgID], "ingress")

	types := []schedule.TypeKey{{Kind: schedule.KindResource, Type: "aws_security_group"}}
	var root string
	for _, loc := range in.projection.Blocks {
		root = loc.Root
	}
	relational := nestedOf(in.relationalInput(root, types, in.projection.Input))
	require.Contains(t, relational, sgID)
	require.Contains(t, relational[sgID], "ingress")
}

// A placeholder inside a nested block is substituted at stage 2, so the
// substitution scope of a block holds its _dd.nested entry.
func TestSubstitutionScopeHoldsNestedBlocks(t *testing.T) {
	in := projectFixture(t, map[string]string{"main.tf": `
variable "port" {}
resource "aws_security_group" "sg" {
  ingress {
    from_port = var.port
  }
}
`})
	var sg *project.Located
	for _, loc := range in.projection.Blocks {
		if loc.Type == "aws_security_group" {
			sg = loc
		}
	}
	require.NotNil(t, sg)
	require.True(t, sg.Placeholder)
	entry := field(ddIndex(in.projection.Input, "nested"), blockID(sg))
	require.NotNil(t, entry)
	for name, scope := range map[string][]ast.Value{
		"anchored":   blockScope(nil, sg, in.projection.Input),
		"relational": in.linkedScope(sg, in.projection.Input),
	} {
		require.Contains(t, scope, entry, name)
	}
}

func TestTerraformQueriesWithSameBasenameKeepDistinctIDs(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "main.tf", `
variable "unresolved" {}

resource "aws_s3_bucket" "bucket" {
  bucket = "generic-public-bucket"
  tags   = { marker = var.unresolved }
}

resource "azurerm_storage_account" "account" {
  name = "genericstorage"
  tags = { marker = var.unresolved }
}
`)
	files := parseTerraform(t, path)

	aws := referenceQuery("shared_check", "aws-bucket-check", `package datadog

import rego.v1
import data.generic.common as common
import data.generic.terraform as tf

DatadogPolicy contains result if {
  some b in tf.blocks("aws_s3_bucket")
  result := common.finding(b, ["bucket"], {})
}
`)
	azure := referenceQuery("shared_check", "azure-account-check", `package datadog

import rego.v1
import data.generic.common as common
import data.generic.terraform as tf

DatadogPolicy contains result if {
  some b in tf.blocks("azurerm_storage_account")
  result := common.finding(b, ["name"], {})
}
`)
	for _, queries := range [][]model.QueryMetadata{{aws, azure}, {azure, aws}} {
		for _, reference := range []bool{false, true} {
			ins := newTestInspector(t, inspectorOpts{
				querySource:   &referenceQueriesSource{queries: queries},
				repoPath:      dir,
				vb:            DefaultVulnerabilityBuilder,
				tracker:       &tracker.CITracker{},
				flagEvaluator: featureflags.NewLocalEvaluator(),
			})
			ins.SetTerraformReferenceMode(reference)
			vulns, err := ins.Inspect(context.Background(), "same-basename", files, []string{"terraform"})
			require.NoError(t, err)
			require.Empty(t, ins.GetFailedQueries())

			got := findingKeys(vulns)
			require.Equal(t, []findingKey{
				{QueryID: "aws-bucket-check", File: filepath.ToSlash(path), ResourceType: "aws_s3_bucket", ResourceName: "bucket", SearchKey: "aws_s3_bucket.bucket.bucket", Line: 5},
				{QueryID: "azure-account-check", File: filepath.ToSlash(path), ResourceType: "azurerm_storage_account", ResourceName: "account", SearchKey: "azurerm_storage_account.account.name", Line: 10},
			}, got, "both same-basename queries should survive; order=%v reference=%v", []string{queries[0].Metadata["id"].(string), queries[1].Metadata["id"].(string)}, reference)
		}
	}
}

func TestFailedPluralLegacyIDRetractsOnlyUnknownIDFindings(t *testing.T) {
	dir := t.TempDir()
	good := writeFile(t, filepath.Join(dir, "01-good"), "main.tf", `resource "aws_s3_bucket" "good" {
  bucket = "good"
  acl = "private"
}`)
	failing := writeFile(t, filepath.Join(dir, "02-failing"), "main.tf", `resource "aws_s3_bucket" "bad" {
  bucket = "bad"
  acl = "private"
  tags = { conflict = "yes" }
}`)
	files := append(parseTerraform(t, good), parseTerraform(t, failing)...)
	failingRule := referenceQuery("conflicting", "", `package datadog
 import rego.v1
 import data.generic.common as common
 import data.generic.terraform as tf
 kind(b) := "private" if b.acl == "private"
 kind(b) := "conflict" if b.tags.conflict == "yes"
 DatadogPolicy contains result if {
  some b in tf.blocks("aws_s3_bucket")
  count(tf.blocks("aws_s3_bucket")) > 0
  kind(b) == "private"
  result := common.finding(b, ["bucket"], {})
 }`)
	delete(failingRule.Metadata, "id")
	failingRule.Metadata["legacyIds"] = []string{"historical-rule-id"}
	survivor := referenceQuery("survivor", "survivor-id", referenceBucketRule)
	survivor.Metadata["legacyIds"] = []string{"historical-rule-id"}
	builder := func(
		ctx context.Context, qCtx *QueryContext, tr Tracker, result interface{}, detector *detector.DetectLine,
		oldSeverities bool, duration time.Duration,
	) (*model.Vulnerability, error) {
		v, err := DefaultVulnerabilityBuilder(ctx, qCtx, tr, result, detector, oldSeverities, duration)
		if v != nil {
			v.QueryName = "renamed-by-builder"
		}
		return v, err
	}
	source := &referenceQueriesSource{queries: []model.QueryMetadata{failingRule, survivor}}
	for _, reference := range []bool{false, true} {
		ins := newTestInspector(t, inspectorOpts{
			querySource: source, repoPath: dir, vb: builder,
			tracker: &tracker.CITracker{}, flagEvaluator: featureflags.NewLocalEvaluator(),
		})
		ins.SetTerraformReferenceMode(reference)
		vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
		require.NoError(t, err)
		require.Contains(t, ins.GetFailedQueries(), "conflicting")
		rules := ins.newTerraformRules(context.Background(), []model.QueryMetadata{failingRule}, "placeholder", nil)
		require.Equal(t, schedule.Relational, rules.rule(terraformQueryKey(&failingRule)).harvest.Class)
		require.Len(t, vulns, 2, "findings with the failed rule's plural alias are retracted")
		for _, v := range vulns {
			require.Equal(t, "survivor-id", v.QueryID)
			require.Equal(t, []string{"historical-rule-id"}, v.LegacyQueryIDs)
			require.Equal(t, "renamed-by-builder", v.QueryName)
		}
	}
}
