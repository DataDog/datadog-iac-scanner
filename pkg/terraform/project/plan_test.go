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
	scan, err := model.Load(context.Background(), dir, &model.Options{Plans: []string{plan}, PlansOnly: true})
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

func TestPlanRangesDistinguishDottedObjectKeyFromNestedPath(t *testing.T) {
	const plan = `{
 "format_version":"1.2",
 "planned_values":{"root_module":{"resources":[
  {"address":"aws_example.x","mode":"managed","type":"aws_example","name":"x","values":{
   "payload":{
    "a.b":"dotted",
    "a":{
     "b":"nested"
    }
   }
  }}
 ]}},
 "configuration":{"root_module":{"resources":[
  {"address":"aws_example.x","mode":"managed","type":"aws_example","name":"x","expressions":{"payload":{"constant_value":{"a.b":"dotted","a":{"b":"nested"}}}}}
 ]}}
}`
	dir := t.TempDir()
	path := filepath.Join(dir, "tfplan.json")
	require.NoError(t, os.WriteFile(path, []byte(plan), 0o600))
	scan, err := model.Load(context.Background(), dir, &model.Options{Plans: []string{path}, PlansOnly: true})
	require.NoError(t, err)
	p := Project(scan.Roots, Options{Placeholder: testPlaceholder})
	loc := p.Blocks["tfplan.json/aws_example.x"]
	require.NotNil(t, loc)
	require.Equal(t, 6, loc.Range([]any{"payload", "a.b"}).Start.Line)
	require.Equal(t, 8, loc.Range([]any{"payload", "a", "b"}).Start.Line)
}

func TestPlanRangesDistinguishNumericObjectKeyFromIndex(t *testing.T) {
	const plan = `{
 "format_version":"1.2",
 "planned_values":{"root_module":{"resources":[
  {"address":"aws_example.x","mode":"managed","type":"aws_example","name":"x","values":{
   "payload":{
    "0":{"foo":"literal zero key"},
    "foo":"other value"
   }
  }}
 ]}},
 "configuration":{"root_module":{"resources":[
  {"address":"aws_example.x","mode":"managed","type":"aws_example","name":"x","expressions":{"payload":{"constant_value":{"0":{"foo":"literal zero key"},"foo":"other value"}}}}
 ]}}
}`
	dir := t.TempDir()
	path := filepath.Join(dir, "tfplan.json")
	require.NoError(t, os.WriteFile(path, []byte(plan), 0o600))
	scan, err := model.Load(context.Background(), dir, &model.Options{Plans: []string{path}, PlansOnly: true})
	require.NoError(t, err)
	loc := Project(scan.Roots, Options{Placeholder: testPlaceholder}).Blocks["tfplan.json/aws_example.x"]
	require.NotNil(t, loc)
	require.Equal(t, 6, loc.Range([]any{"payload", "0", "foo"}).Start.Line, "string key \"0\"")
	require.Equal(t, 5, loc.Range([]any{"payload", 0, "foo"}).Start.Line, "index 0 should fall back to its parent")
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
	scan, err := model.Load(context.Background(), dir, &model.Options{Plans: []string{plan}, PlansOnly: true})
	require.NoError(t, err)
	p := Project(scan.Roots, Options{Placeholder: testPlaceholder, LiteralKeys: s3Keys})

	related := get(dd(t, p), "related")
	require.Equal(t, []any{"tfplan.json/aws_s3_bucket_versioning.v"},
		get(related, "tfplan.json/aws_s3_bucket.b", "aws_s3_bucket_versioning", "bucket"))
	require.Nil(t, get(related, "tfplan.json/aws_s3_bucket.other"))
	require.Equal(t, []any{"tfplan.json/aws_s3_bucket.b"},
		get(dd(t, p), "targets", "tfplan.json/aws_s3_bucket_versioning.v", "bucket"))
}

// A plan whose alarm metric_name references a metric filter's .arn lists that
// filter under targets for metric_name, and under the attribute-qualified key
// metric_name#arn only: a rule can tell the ARN from the name the metric
// carries.
func TestAlarmMetricNameARNTargetsFilterByARN(t *testing.T) {
	const plan = `{"format_version":"1.2","terraform_version":"1.6.0","complete":true,
 "planned_values":{"root_module":{"resources":[
  {"address":"aws_cloudwatch_log_metric_filter.f","mode":"managed","type":"aws_cloudwatch_log_metric_filter","name":"f","provider_name":"registry.terraform.io/hashicorp/aws","values":{"name":"M","pattern":"{ $.x = 1 }","log_group_name":"g","metric_transformation":[{"name":"M","namespace":"NS","value":"1"}]}},
  {"address":"aws_cloudwatch_metric_alarm.a","mode":"managed","type":"aws_cloudwatch_metric_alarm","name":"a","provider_name":"registry.terraform.io/hashicorp/aws","values":{"alarm_name":"A","comparison_operator":"GreaterThanOrEqualToThreshold","evaluation_periods":1,"namespace":"NS","period":300,"statistic":"Sum","threshold":1}}
 ]}},
 "resource_changes":[
  {"address":"aws_cloudwatch_log_metric_filter.f","mode":"managed","type":"aws_cloudwatch_log_metric_filter","name":"f","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":null,"after":{"name":"M","pattern":"{ $.x = 1 }","log_group_name":"g","metric_transformation":[{"name":"M","namespace":"NS","value":"1"}]},"after_unknown":{"id":true}}},
  {"address":"aws_cloudwatch_metric_alarm.a","mode":"managed","type":"aws_cloudwatch_metric_alarm","name":"a","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":null,"after":{"alarm_name":"A","comparison_operator":"GreaterThanOrEqualToThreshold","evaluation_periods":1,"namespace":"NS","period":300,"statistic":"Sum","threshold":1},"after_unknown":{"id":true,"metric_name":true,"arn":true}}}
 ],
 "configuration":{"root_module":{"resources":[
  {"address":"aws_cloudwatch_log_metric_filter.f","mode":"managed","type":"aws_cloudwatch_log_metric_filter","name":"f","provider_config_key":"aws","expressions":{"name":{"constant_value":"M"},"pattern":{"constant_value":"{ $.x = 1 }"},"log_group_name":{"constant_value":"g"},"metric_transformation":[{"name":{"constant_value":"M"},"namespace":{"constant_value":"NS"},"value":{"constant_value":"1"}}]}},
  {"address":"aws_cloudwatch_metric_alarm.a","mode":"managed","type":"aws_cloudwatch_metric_alarm","name":"a","provider_config_key":"aws","expressions":{"alarm_name":{"constant_value":"A"},"comparison_operator":{"constant_value":"GreaterThanOrEqualToThreshold"},"evaluation_periods":{"constant_value":1},"metric_name":{"references":["aws_cloudwatch_log_metric_filter.f.arn","aws_cloudwatch_log_metric_filter.f"]},"namespace":{"constant_value":"NS"},"period":{"constant_value":300},"statistic":{"constant_value":"Sum"},"threshold":{"constant_value":1}}}
 ]}}}`

	dir := t.TempDir()
	path := filepath.Join(dir, "tfplan.json")
	require.NoError(t, os.WriteFile(path, []byte(plan), 0o600))
	scan, err := model.Load(context.Background(), dir, &model.Options{Plans: []string{path}})
	require.NoError(t, err)
	p := Project(scan.Roots, Options{Placeholder: testPlaceholder})
	idx := dd(t, p)
	require.Equal(t, []any{"tfplan.json/aws_cloudwatch_log_metric_filter.f"},
		get(idx, "targets", "tfplan.json/aws_cloudwatch_metric_alarm.a", "metric_name"))
	require.Equal(t, []any{"tfplan.json/aws_cloudwatch_log_metric_filter.f"},
		get(idx, "targets", "tfplan.json/aws_cloudwatch_metric_alarm.a", "metric_name#arn"))
	require.Nil(t, get(idx, "targets", "tfplan.json/aws_cloudwatch_metric_alarm.a", "metric_name#name"))
	require.Equal(t, []any{"tfplan.json/aws_cloudwatch_metric_alarm.a"},
		get(idx, "related", "tfplan.json/aws_cloudwatch_log_metric_filter.f", "aws_cloudwatch_metric_alarm", "metric_name"))
}
