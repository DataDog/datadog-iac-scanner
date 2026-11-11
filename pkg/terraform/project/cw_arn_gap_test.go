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
	scan, err := model.Load(context.Background(), dir, model.Options{Plans: []string{path}})
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
