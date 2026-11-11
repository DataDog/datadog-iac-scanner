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

// computedPlan plans a bucket named by bucket_prefix, so its bucket name is
// computed, and a companion that writes that name.
const computedPlan = `{"format_version":"1.2","terraform_version":"1.6.0",
 "planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","provider_name":"registry.terraform.io/hashicorp/aws","schema_version":0,"values":{"bucket":"acme-1","bucket_prefix":"acme-"},"sensitive_values":{}},
  {"address":"aws_s3_bucket_versioning.v","mode":"managed","type":"aws_s3_bucket_versioning","name":"v","provider_name":"registry.terraform.io/hashicorp/aws","schema_version":0,"values":{"bucket":"acme-1"},"sensitive_values":{}}]}},
 "resource_changes":[
  {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":null,"after":{"bucket":"acme-1","bucket_prefix":"acme-"},"after_unknown":{"arn":true}}},
  {"address":"aws_s3_bucket_versioning.v","mode":"managed","type":"aws_s3_bucket_versioning","name":"v","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":null,"after":{"bucket":"acme-1"},"after_unknown":{}}}],
 "configuration":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","provider_config_key":"aws","expressions":{"bucket_prefix":{"constant_value":"acme-"}},"schema_version":0},
  {"address":"aws_s3_bucket_versioning.v","mode":"managed","type":"aws_s3_bucket_versioning","name":"v","provider_config_key":"aws","expressions":{"bucket":{"constant_value":"acme-1"}},"schema_version":0}]}}}
`

func TestPlanComputedValues(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "tfplan.json")
	require.NoError(t, os.WriteFile(plan, []byte(computedPlan), 0o600))
	scan, err := model.Load(context.Background(), dir, model.Options{Plans: []string{plan}, PlansOnly: true})
	require.NoError(t, err)
	p := Project(scan.Roots, Options{Placeholder: testPlaceholder, LiteralKeys: s3Keys})

	var bucket string
	for id, loc := range p.Blocks {
		if loc.Type == "aws_s3_bucket" {
			bucket = id
		}
	}
	require.NotEmpty(t, bucket)
	block := get(dd(t, p), "by_id", bucket)
	require.Equal(t, map[string]any{"bucket": "acme-1", "arn": testPlaceholder}, get(block, "_dd_meta", "computed"))
	require.ElementsMatch(t, []any{"bucket_prefix"}, get(block, "_dd_meta", "written"))
	require.Nil(t, get(block, "bucket"))
	require.True(t, p.Blocks[bucket].Placeholder)

	list := relatedOf(t, p, "aws_s3_bucket", "aws_s3_bucket_versioning", "bucket")
	require.Len(t, list, 1)
	require.Contains(t, list[0], "aws_s3_bucket_versioning.v")
}

// barePlan lists its resources in a configuration without expressions: the
// companion names its bucket by the planned literal.
const barePlan = `{"format_version":"1.2",
 "planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","values":{"bucket":"acme"}},
  {"address":"aws_s3_bucket.other","mode":"managed","type":"aws_s3_bucket","name":"other","values":{"bucket":"other"}},
  {"address":"aws_s3_bucket_versioning.v","mode":"managed","type":"aws_s3_bucket_versioning","name":"v","values":{"bucket":"acme"}}]}},
 "configuration":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","provider_config_key":"aws"},
  {"address":"aws_s3_bucket.other","mode":"managed","type":"aws_s3_bucket","name":"other","provider_config_key":"aws"},
  {"address":"aws_s3_bucket_versioning.v","mode":"managed","type":"aws_s3_bucket_versioning","name":"v","provider_config_key":"aws"}]}}}`

func TestPlanBareConfigurationLiteralCompanions(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "tfplan.json")
	require.NoError(t, os.WriteFile(plan, []byte(barePlan), 0o600))
	scan, err := model.Load(context.Background(), dir, model.Options{Plans: []string{plan}, PlansOnly: true})
	require.NoError(t, err)
	p := Project(scan.Roots, Options{Placeholder: testPlaceholder, LiteralKeys: s3Keys})

	related := get(dd(t, p), "related")
	require.Equal(t, []any{"tfplan.json/aws_s3_bucket_versioning.v"},
		get(related, "tfplan.json/aws_s3_bucket.b", "aws_s3_bucket_versioning", "bucket"))
	require.Nil(t, get(related, "tfplan.json/aws_s3_bucket.other"))
	require.Equal(t, []any{"tfplan.json/aws_s3_bucket.b"},
		get(dd(t, p), "targets", "tfplan.json/aws_s3_bucket_versioning.v", "bucket"))
}
