/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/test"
	"github.com/stretchr/testify/require"
)

var OriginalDataCICD = `name: Web Page To Markdown
on:
  issues:
    types: [opened]
jobs:
  WebPageToMarkdown:
    runs-on: ubuntu-latest
    steps:
      - name: Does the issue need to be converted to markdown
        run: |
          if [ "${{ github.event.issue.body }}" ]; then
            if [[ "${{ github.event.issue.title }}" =~ ^\[Auto\]* ]]; then
              :
            else
              echo "This issue does not need to generate a markdown file." 1>&2
              exit 1;
            fi;
          else
            echo "The description of the issue is empty." 1>&2
            exit 1;
          fi;
        shell: bash
      - name: Checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
      - name: Crawl pages and generate Markdown files
        uses: freeCodeCamp-China/article-webpage-to-markdown-action@v0.1.8
        with:
          newsLink: '${{ github.event.issue.body }}'
          markDownFilePath: './chinese/articles/'
          githubToken: ${{ github.token }}
      - name: Git Auto Commit
        uses: stefanzweifel/git-auto-commit-action@v4.9.2
        with:
          commit_message: '${{ github.event.issue.title }}'
          file_pattern: chinese/articles/*.md
          commit_user_name: PageToMarkdown Bot
          commit_user_email: PageToMarkdown-bot@freeCodeCamp.org
	  `

// Test_detectLine tests the functions [detectLine()] and all the methods called by them
func Test_detectLineCICD(t *testing.T) { //nolint
	type args struct {
		file      *model.FileMetadata
		searchKey string
	}
	type fields struct {
		outputLines int
	}
	tests := []struct {
		name   string
		args   args
		fields fields
		want   model.VulnerabilityLines
	}{
		{
			name: "detect_line",
			args: args{
				file: &model.FileMetadata{
					ScanID:            "scanID",
					ID:                "Test",
					Kind:              model.KindYAML,
					OriginalData:      OriginalDataCICD,
					LinesOriginalData: utils.SplitLines(OriginalDataCICD),
				},
				searchKey: "uses={{freeCodeCamp-China/article-webpage-to-markdown-action@v0.1.8}}",
			},
			fields: fields{
				outputLines: 3,
			},
			want: model.VulnerabilityLines{
				Line: 28,
				VulnLines: &[]model.CodeLine{
					{
						Position: 27,
						Line:     `      - name: Crawl pages and generate Markdown files`,
					},
					{
						Position: 28,
						Line:     `        uses: freeCodeCamp-China/article-webpage-to-markdown-action@v0.1.8`,
					},
					{
						Position: 29,
						Line:     "        with:",
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 28,
						Col:  8,
					},
					End: model.ResourceLine{
						Line: 28,
						Col:  74,
					},
				},
			},
		},
		{
			name: "detect_line_with_curly_brackets",
			args: args{
				file: &model.FileMetadata{
					ScanID:            "scanID",
					ID:                "Test",
					Kind:              model.KindYAML,
					OriginalData:      OriginalDataCICD,
					LinesOriginalData: utils.SplitLines(OriginalDataCICD),
				},
				searchKey: `run={{if [ "${{ github.event.issue.body }}" ]; then
  if [[ "${{ github.event.issue.title }}" =~ ^\[Auto\]* ]]; then
    :
  else
    echo "This issue does not need to generate a markdown file." 1>&2
    exit 1;
  fi;
else
  echo "The description of the issue is empty." 1>&2
  exit 1;
fi;
}}`,
			},
			fields: fields{
				outputLines: 3,
			},
			want: model.VulnerabilityLines{
				Line: 10,
				VulnLines: &[]model.CodeLine{
					{
						Position: 9,
						Line:     `      - name: Does the issue need to be converted to markdown`,
					},
					{
						Position: 10,
						Line:     `        run: |`,
					},
					{
						Position: 11,
						Line:     `          if [ "${{ github.event.issue.body }}" ]; then`,
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 10,
						Col:  8,
					},
					End: model.ResourceLine{
						Line: 21,
						Col:  14,
					},
				},
			},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		detector := NewDetectLine(tt.fields.outputLines)
		t.Run(tt.name, func(t *testing.T) {
			got := detector.defaultDetector.DetectLine(ctx, tt.args.file, tt.args.searchKey, 3)
			gotStrVulnerabilities, err := test.StringifyStruct(got)
			require.Nil(t, err)
			wantStrVulnerabilities, err := test.StringifyStruct(tt.want)
			require.Nil(t, err)
			if !reflect.DeepEqual(gotStrVulnerabilities, wantStrVulnerabilities) {
				t.Errorf("detectLine() = %v, want %v", gotStrVulnerabilities, wantStrVulnerabilities)
			}
		})
	}
}

var OriginalDataK8s = `apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  privileged: true
  allowPrivilegeEscalation: true
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
  hostPID: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'

---
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged2
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  privileged: true
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
  hostPID: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
	  `

// Test_detectLine tests the functions [detectLine()] and all the methods called by them
func Test_detectLineK8s(t *testing.T) { //nolint
	type args struct {
		file      *model.FileMetadata
		searchKey string
	}
	type fields struct {
		outputLines int
	}
	tests := []struct {
		name   string
		args   args
		fields fields
		want   model.VulnerabilityLines
	}{
		{
			name: "detect_line",
			args: args{
				file: &model.FileMetadata{
					ScanID:            "scanID",
					ID:                "Test",
					Kind:              model.KindYAML,
					OriginalData:      OriginalDataK8s,
					LinesOriginalData: utils.SplitLines(OriginalDataK8s),
				},
				searchKey: "metadata.name={{privileged}}.spec.allowPrivilegeEscalation",
			},
			fields: fields{
				outputLines: 3,
			},
			want: model.VulnerabilityLines{
				Line: 9,
				VulnLines: &[]model.CodeLine{
					{
						Position: 8,
						Line:     `  privileged: true`,
					},
					{
						Position: 9,
						Line:     `  allowPrivilegeEscalation: true`,
					},
					{
						Position: 10,
						Line:     "  hostNetwork: true",
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 9,
						Col:  2,
					},
					End: model.ResourceLine{
						Line: 9,
						Col:  32,
					},
				},
			},
		},
		{
			name: "detect_line_2",
			args: args{
				file: &model.FileMetadata{
					ScanID:            "scanID",
					ID:                "Test",
					Kind:              model.KindYAML,
					OriginalData:      OriginalDataK8s,
					LinesOriginalData: utils.SplitLines(OriginalDataK8s),
				},
				searchKey: `metadata.name={{privileged}}.spec.supplementalGroups.rule`,
			},
			fields: fields{
				outputLines: 3,
			},
			want: model.VulnerabilityLines{
				Line: 21,
				VulnLines: &[]model.CodeLine{
					{
						Position: 20,
						Line:     `  supplementalGroups:`,
					},
					{
						Position: 21,
						Line:     `    rule: 'RunAsAny'`,
					},
					{
						Position: 22,
						Line:     `  fsGroup:`,
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 21,
						Col:  4,
					},
					End: model.ResourceLine{
						Line: 21,
						Col:  20,
					},
				},
			},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		detector := NewDetectLine(tt.fields.outputLines)
		t.Run(tt.name, func(t *testing.T) {
			got := detector.defaultDetector.DetectLine(ctx, tt.args.file, tt.args.searchKey, 3)
			gotStrVulnerabilities, err := test.StringifyStruct(got)
			require.Nil(t, err)
			wantStrVulnerabilities, err := test.StringifyStruct(tt.want)
			require.Nil(t, err)
			if !reflect.DeepEqual(gotStrVulnerabilities, wantStrVulnerabilities) {
				t.Errorf("detectLine() = %v, want %v", gotStrVulnerabilities, wantStrVulnerabilities)
			}
		})
	}
}

func Test_terraformPlanPath(t *testing.T) {
	tests := []struct {
		name      string
		searchKey string
		want      []string
	}{
		{
			name:      "resource_and_attribute",
			searchKey: "alicloud_db_instance[example].address",
			want:      []string{"resource", "alicloud_db_instance", "example", "address"},
		},
		{
			name:      "already_prefixed",
			searchKey: "resource.aws_s3_bucket[b].acl",
			want:      []string{"resource", "aws_s3_bucket", "b", "acl"},
		},
		{
			name:      "array_index_and_value_anchor",
			searchKey: "aws_security_group[sg].ingress[0].cidr_blocks=0.0.0.0/0",
			want:      []string{"resource", "aws_security_group", "sg", "ingress", "0", "cidr_blocks"},
		},
		{
			name:      "resource_only",
			searchKey: "azurerm_sql_firewall_rule[positive1]",
			want:      []string{"resource", "azurerm_sql_firewall_rule", "positive1"},
		},
		{
			// Module resources are keyed "name[N]" (count/for_each index), so the
			// resource-name bracket itself can contain a nested "[0]" suffix.
			name:      "module_resource_with_count_index",
			searchKey: "aws_dynamodb_table[this[0]].server_side_encryption",
			want:      []string{"resource", "aws_dynamodb_table", "this[0]", "server_side_encryption"},
		},
		{
			// Module-prefixed keys contain dots inside the bracket.
			name:      "module_prefixed_resource",
			searchKey: "aws_s3_bucket[module.app1.data].bucket",
			want:      []string{"resource", "aws_s3_bucket", "module.app1.data", "bucket"},
		},
		{
			// Module-prefixed key combined with a for_each index suffix.
			name:      "module_prefixed_resource_with_for_each_index",
			searchKey: `aws_s3_bucket[module.app1.data["prod"]].bucket`,
			want:      []string{"resource", "aws_s3_bucket", `module.app1.data["prod"]`, "bucket"},
		},
		{
			// Some Rego rules wrap the resource name in "{{ }}" templating.
			name:      "curly_brace_wrapped_name",
			searchKey: "aws_s3_bucket_object[{{this[0]}}]",
			want:      []string{"resource", "aws_s3_bucket_object", "this[0]"},
		},
		{
			// Curly-brace templating combined with a module-prefixed name.
			name:      "curly_brace_wrapped_module_prefixed_name",
			searchKey: "aws_s3_bucket_object[{{module.s3_object.this[0]}}]",
			want:      []string{"resource", "aws_s3_bucket_object", "module.s3_object.this[0]"},
		},
		{
			// A for_each key is an arbitrary quoted HCL string that may itself
			// contain a literal "]", which must not be mistaken for the group's
			// own closing bracket.
			name:      "for_each_key_containing_literal_bracket",
			searchKey: `aws_secretsmanager_secret[module.secrets["prod]eu"].test].kms_key_id`,
			want:      []string{"resource", "aws_secretsmanager_secret", `module.secrets["prod]eu"].test`, "kms_key_id"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, _ := terraformPlanPath(tt.searchKey)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("terraformPlanPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

var OriginalDataTFPlan = `{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "alicloud_db_instance.example",
          "mode": "managed",
          "type": "alicloud_db_instance",
          "name": "example",
          "values": {
            "engine": "MySQL",
            "address": "0.0.0.0/0"
          }
        }
      ]
    }
  },
  "terraform_version": "1.9.0"
}`

// Test_detectLineTerraformPlan verifies attribute-level plan searchKeys.
func Test_detectLineTerraformPlan(t *testing.T) {
	p := &jsonParser.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(OriginalDataTFPlan), "plan.json", false, 1)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	file := &model.FileMetadata{
		ScanID:            "scanID",
		ID:                "Test",
		Kind:              model.KindTerraformPlan,
		OriginalData:      OriginalDataTFPlan,
		LineInfoDocument:  docs[0],
		LinesOriginalData: utils.SplitLines(OriginalDataTFPlan),
	}

	d := defaultDetectLine{}
	got := d.DetectLine(context.Background(), file, "alicloud_db_instance[example].address", 0)
	require.Equal(t, 13, got.Line)
}

func Test_detectLineTerraformPlanResourceLevel(t *testing.T) {
	plan := `{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {
      "resources": [{
        "address": "aws_api_gateway_deployment.positive1",
        "type": "aws_api_gateway_deployment",
        "name": "positive1",
        "values": {
          "rest_api_id": "some rest api id",
          "stage_name": "some name"
        }
      }]
    }
  },
  "terraform_version": "1.9.0"
}`
	p := &jsonParser.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(plan), "plan.json", false, 1)
	require.NoError(t, err)

	shown, err := p.StringifyContent([]byte(plan))
	require.NoError(t, err)
	file := &model.FileMetadata{
		Kind:              model.KindTerraformPlan,
		LineInfoDocument:  docs[0],
		LinesOriginalData: utils.SplitLines(shown),
	}
	got := defaultDetectLine{}.DetectLine(context.Background(), file, "resource.aws_api_gateway_deployment[positive1]", 0)
	require.Equal(t, `"values": {`, strings.TrimSpace((*file.LinesOriginalData)[got.Line-1]))
}

func Test_detectLineTerraformPlanModuleResourceWithCountIndex(t *testing.T) {
	plan := `{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {
      "resources": [],
      "child_modules": [{
        "address": "module.dynamodb_table",
        "resources": [{
          "address": "module.dynamodb_table.aws_dynamodb_table.this[0]",
          "type": "aws_dynamodb_table",
          "name": "this",
          "index": 0,
          "values": {
            "name": "my-table",
            "server_side_encryption": {
              "enabled": true
            }
          }
        }]
      }]
    }
  },
  "terraform_version": "1.9.0"
}`
	p := &jsonParser.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(plan), "plan.json", false, 1)
	require.NoError(t, err)

	shown, err := p.StringifyContent([]byte(plan))
	require.NoError(t, err)
	file := &model.FileMetadata{
		Kind:              model.KindTerraformPlan,
		LineInfoDocument:  docs[0],
		LinesOriginalData: utils.SplitLines(shown),
	}
	// Child-module keys are module-prefixed plus the index suffix, so the
	// searchKey bracket contents contain dots and a nested "[0]".
	got := defaultDetectLine{}.DetectLine(
		context.Background(), file, "aws_dynamodb_table[module.dynamodb_table.this[0]].server_side_encryption", 0,
	)
	require.Equal(t, `"server_side_encryption": {`, strings.TrimSpace((*file.LinesOriginalData)[got.Line-1]))
}

func Test_detectLineTerraformPlanSiblingModulesSameTypeAndName(t *testing.T) {
	// Two resources sharing type+name in sibling modules must both stay
	// resolvable via distinct module-prefixed keys, not collide.
	plan := `{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {
      "resources": [],
      "child_modules": [
        {
          "address": "module.app1",
          "resources": [{
            "address": "module.app1.aws_s3_bucket.data",
            "type": "aws_s3_bucket",
            "name": "data",
            "values": {
              "bucket": "app1-data",
              "acl": "private"
            }
          }]
        },
        {
          "address": "module.app2",
          "resources": [{
            "address": "module.app2.aws_s3_bucket.data",
            "type": "aws_s3_bucket",
            "name": "data",
            "values": {
              "bucket": "app2-data",
              "acl": "public-read"
            }
          }]
        }
      ]
    }
  },
  "terraform_version": "1.9.0"
}`
	p := &jsonParser.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(plan), "plan.json", false, 1)
	require.NoError(t, err)

	file := &model.FileMetadata{
		Kind:              model.KindTerraformPlan,
		LineInfoDocument:  docs[0],
		LinesOriginalData: utils.SplitLines(plan),
	}

	d := defaultDetectLine{}
	app1 := d.DetectLine(context.Background(), file, "aws_s3_bucket[module.app1.data].acl", 0)
	app2 := d.DetectLine(context.Background(), file, "aws_s3_bucket[module.app2.data].acl", 0)

	require.Greater(t, app1.Line, 1)
	require.Greater(t, app2.Line, 1)
	require.NotEqual(t, app1.Line, app2.Line)
}

const planWithUnknownsAndConfig = `{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_instance.web",
          "mode": "managed",
          "type": "aws_instance",
          "name": "web",
          "values": {
            "ami": "ami-1",
            "description": null
          }
        },
        {
          "address": "aws_security_group.sg",
          "mode": "managed",
          "type": "aws_security_group",
          "name": "sg",
          "values": {
            "ingress": [
              {
                "from_port": 22
              }
            ]
          }
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_instance.web",
      "mode": "managed",
      "type": "aws_instance",
      "name": "web",
      "change": {
        "actions": ["create"],
        "after": {"ami": "ami-1", "description": null},
        "after_unknown": {
          "arn": true
        }
      }
    }
  ],
  "configuration": {
    "root_module": {
      "resources": [
        {
          "address": "aws_security_group.sg",
          "mode": "managed",
          "type": "aws_security_group",
          "name": "sg",
          "expressions": {
            "ingress": [
              {
                "description": {"constant_value": "ssh"}
              }
            ]
          }
        },
        {
          "address": "aws_instance.web",
          "mode": "managed",
          "type": "aws_instance",
          "name": "web",
          "expressions": {
            "arn": {"references": ["var.arn"]},
            "description": {"constant_value": null}
          }
        }
      ]
    }
  },
  "terraform_version": "1.9.0"
}`

func detectPlanWithUnknownsAndConfig(t *testing.T, searchKey string) int {
	t.Helper()
	p := &jsonParser.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(planWithUnknownsAndConfig), "plan.json", false, 1)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	file := &model.FileMetadata{
		Kind:              model.KindTerraformPlan,
		LineInfoDocument:  docs[0],
		LinesOriginalData: utils.SplitLines(planWithUnknownsAndConfig),
	}
	return defaultDetectLine{}.DetectLine(context.Background(), file, searchKey, 0).Line
}

func Test_detectLineTerraformPlanUnknownAttributeUsesHeader(t *testing.T) {
	require.Equal(t, 11, detectPlanWithUnknownsAndConfig(t, "aws_instance[web].arn"))
}

func Test_detectLineTerraformPlanMissingNestedUsesAncestor(t *testing.T) {
	require.Equal(t, 24, detectPlanWithUnknownsAndConfig(t, "aws_security_group[sg].ingress.0.description"))
}

func Test_detectLineTerraformPlanDroppedNullKeepsOwnLine(t *testing.T) {
	require.Equal(t, 13, detectPlanWithUnknownsAndConfig(t, "aws_instance[web].description"))
}

func Test_detectLineTerraformPlanUnknownAttributeUsesInstanceHeader(t *testing.T) {
	plan := `{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_instance.web[0]",
          "type": "aws_instance",
          "name": "web",
          "index": 0,
          "values": {
            "ami": "ami-0"
          }
        },
        {
          "address": "aws_instance.web[1]",
          "type": "aws_instance",
          "name": "web",
          "index": 1,
          "values": {
            "ami": "ami-1"
          }
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_instance.web[1]",
      "change": {"after_unknown": {"arn": true}}
    }
  ],
  "terraform_version": "1.9.0"
}`
	p := &jsonParser.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(plan), "plan.json", false, 1)
	require.NoError(t, err)
	file := &model.FileMetadata{
		Kind:              model.KindTerraformPlan,
		LineInfoDocument:  docs[0],
		LinesOriginalData: utils.SplitLines(plan),
	}
	d := defaultDetectLine{}
	require.Equal(t, 11, d.DetectLine(context.Background(), file, "aws_instance[web[0]].arn", 0).Line)
	require.Equal(t, 20, d.DetectLine(context.Background(), file, "aws_instance[web[1]].arn", 0).Line)
}

// planLineText parses plan as the scanner does and returns the trimmed text of
// the line each search key resolves to.
func planLineText(t *testing.T, plan string, searchKeys ...string) []string {
	t.Helper()
	p := &jsonParser.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(plan), "plan.json", false, 1)
	require.NoError(t, err)
	shown, err := p.StringifyContent([]byte(plan))
	require.NoError(t, err)
	file := &model.FileMetadata{
		Kind:              model.KindTerraformPlan,
		LineInfoDocument:  docs[0],
		LinesOriginalData: utils.SplitLines(shown),
	}
	texts := make([]string, 0, len(searchKeys))
	for _, key := range searchKeys {
		got := defaultDetectLine{}.DetectLine(context.Background(), file, key, 0).Line
		require.Positive(t, got, key)
		texts = append(texts, strings.TrimSpace((*file.LinesOriginalData)[got-1]))
	}
	return texts
}

func Test_detectLineTerraformPlanMinified(t *testing.T) {
	minified := `{"format_version":"1.0","planned_values":{"root_module":{"resources":[{"address":"alicloud_db_instance.example","type":"alicloud_db_instance","name":"example","values":{"address":"0.0.0.0/0","port":"3306"}}]}},"terraform_version": "1.9.0"}`
	require.Equal(t,
		[]string{`"address": "0.0.0.0/0",`, `"port": "3306"`},
		planLineText(t, minified, "alicloud_db_instance[example].address", "alicloud_db_instance[example].port"))
}

func Test_detectLineTerraformPlanListElementAfterEqualValue(t *testing.T) {
	plan := `{"format_version":"1.2","planned_values":{"root_module":{"resources":[
{"address":"aws_lb_listener.l","mode":"managed","type":"aws_lb_listener","name":"l","values":{
"default_action":[{"order":1,"type":"redirect"},{"order":2,"redirect":[{"port":"443"}],"type":"redirect"}],
"port":80}}]}},
  "terraform_version": "1.9.0"
}`
	require.Equal(t,
		[]string{`"redirect": [`, `"redirect": [`, `"order": 2,`, `"port": 80`},
		planLineText(t, plan,
			"aws_lb_listener[l].default_action[1].redirect",
			"aws_lb_listener[l].default_action.redirect",
			"aws_lb_listener[l].default_action[1]",
			"aws_lb_listener[l].port"))
}

func Test_detectLineTerraformPlanDataSource(t *testing.T) {
	plan := `{"format_version":"1.2",
"planned_values":{"root_module":{"resources":[
{"address":"data.aws_iam_policy_document.d","mode":"data","type":"aws_iam_policy_document","name":"d","values":{"json":"PLANNED"}}]}},
"prior_state":{"format_version":"1.0","values":{"root_module":{"resources":[
{"address":"data.aws_caller_identity.me","mode":"data","type":"aws_caller_identity","name":"me","values":{"account_id":"PRIOR"}}]}}},
  "terraform_version": "1.9.0"
}`
	require.Equal(t,
		[]string{`"json": "PLANNED"`, `"values": {`, `"account_id": "PRIOR"`},
		planLineText(t, plan,
			"data.aws_iam_policy_document[d].json",
			"data.aws_iam_policy_document[d]",
			"data.aws_caller_identity[me].account_id"))
}

func Test_detectLineTerraformPlanConfigurationSections(t *testing.T) {
	plan := `{"format_version":"1.2","planned_values":{"root_module":{}},
"configuration":{
"provider_config":{"aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","expressions":{"region":{"constant_value":"us-east-1"}}}},
"root_module":{
"outputs":{"o":{"expression":{"constant_value":"x"}}},
"module_calls":{"m":{"source":"git::https://example.com/m.git","expressions":{"name":{"constant_value":"n"}},"module":{}}},
"variables":{"v":{"default":"d"}}}},
  "terraform_version": "1.9.0"
}`
	require.Equal(t,
		[]string{`"expression": {`, `"o": {`, `"source": "git::https://example.com/m.git",`, `"name": {`, `"default": "d"`, `"v": {`, `"region": {`},
		planLineText(t, plan,
			"output[o].value",
			"output[o].description",
			"module[m].source",
			"module[m].name",
			"variable[v].default",
			"variable[v].description",
			"provider[aws].region"))
}

func Test_terraformPlanPathRootsAtSection(t *testing.T) {
	for _, tc := range []struct {
		key      string
		path     []string
		blockLen int
	}{
		{"aws_s3_bucket[b].acl", []string{"resource", "aws_s3_bucket", "b", "acl"}, 3},
		{"resource.aws_s3_bucket[b]", []string{"resource", "aws_s3_bucket", "b"}, 3},
		{"data.aws_ami[a].owners", []string{"data", "aws_ami", "a", "owners"}, 3},
		{"output[o].description", []string{"output", "o", "description"}, 2},
		{"module[m].source", []string{"module", "m", "source"}, 2},
		{"variable[v]", []string{"variable", "v"}, 2},
	} {
		path, blockLen, _ := terraformPlanPath(tc.key)
		require.Equal(t, tc.path, path, tc.key)
		require.Equal(t, tc.blockLen, blockLen, tc.key)
	}
}

func Test_detectLineTerraformPlanSectionBlocks(t *testing.T) {
	lines := make([]string, 12)
	for i := range lines {
		lines[i] = "line"
	}
	lineTable := func(entries map[string]int) map[string]interface{} {
		table := map[string]interface{}{}
		for key, line := range entries {
			table["_dd_"+key] = map[string]interface{}{"_dd_line": float64(line)}
		}
		return table
	}
	doc := model.Document{
		"output": map[string]interface{}{
			"_dd_lines": lineTable(map[string]int{"o": 3}),
			"o":         map[string]interface{}{"value": "x", "_dd_lines": lineTable(map[string]int{"value": 4})},
		},
		"module": map[string]interface{}{
			"_dd_lines": lineTable(map[string]int{"m": 7}),
			"m":         map[string]interface{}{"source": "git::x", "_dd_lines": lineTable(map[string]int{"source": 8})},
		},
	}
	file := &model.FileMetadata{Kind: model.KindTerraformPlan, LineInfoDocument: doc, LinesOriginalData: &lines}
	detect := func(key string) int {
		return defaultDetectLine{}.DetectLine(context.Background(), file, key, 0).Line
	}
	require.Equal(t, 4, detect("output[o].value"))
	require.Equal(t, 3, detect("output[o].description"))
	require.Equal(t, 8, detect("module[m].source"))
	require.Equal(t, 7, detect("module[m].version"))
}

const planWithListBlocks = `{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_dynamodb_table.t",
          "type": "aws_dynamodb_table",
          "name": "t",
          "values": {
            "point_in_time_recovery": [
              {
                "enabled": false
              }
            ],
            "ttl": [
              {
                "attribute_name": "a"
              },
              {
                "attribute_name": "b",
                "enabled": false
              }
            ]
          }
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_dynamodb_table.t",
      "change": {"after_unknown": {"ttl": [{"kms_key_arn": true}]}}
    }
  ],
  "configuration": {
    "root_module": {
      "resources": [
        {
          "address": "aws_dynamodb_table.t",
          "expressions": {"ttl": [{"kms_key_arn": {"constant_value": "k"}}]}
        }
      ]
    }
  },
  "terraform_version": "1.9.0"
}`

func detectPlanWithListBlocks(t *testing.T, searchKey string) int {
	t.Helper()
	p := &jsonParser.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(planWithListBlocks), "plan.json", false, 1)
	require.NoError(t, err)
	file := &model.FileMetadata{
		Kind:              model.KindTerraformPlan,
		LineInfoDocument:  docs[0],
		LinesOriginalData: utils.SplitLines(planWithListBlocks),
	}
	return defaultDetectLine{}.DetectLine(context.Background(), file, searchKey, 0).Line
}

func Test_detectLineTerraformPlanOneElementListBlock(t *testing.T) {
	require.Equal(t, 13, detectPlanWithListBlocks(t, "aws_dynamodb_table[t].point_in_time_recovery.enabled"))
}

func Test_detectLineTerraformPlanMultiElementListBlock(t *testing.T) {
	require.Equal(t, 18, detectPlanWithListBlocks(t, "aws_dynamodb_table[t].ttl.attribute_name"))
	require.Equal(t, 22, detectPlanWithListBlocks(t, "aws_dynamodb_table[t].ttl.enabled"))
}

func Test_detectLineTerraformPlanListBlockMissingKeyUsesListLine(t *testing.T) {
	require.Equal(t, 16, detectPlanWithListBlocks(t, "aws_dynamodb_table[t].ttl.kms_key_arn"))
}

var content = []byte(
	`content1
content2`)

func Test_defaultDetectLine_prepareResolvedFiles(t *testing.T) {
	type args struct {
		resFiles map[string]model.ResolvedFile
	}
	tests := []struct {
		name string
		args args
		want map[string]model.ResolvedFileSplit
	}{
		{
			name: "prepare_resolved_files",
			args: args{
				resFiles: map[string]model.ResolvedFile{
					"file1": {
						Content:      content,
						Path:         "testing/file1",
						LinesContent: utils.SplitLines(string(content)),
					},
				},
			},
			want: map[string]model.ResolvedFileSplit{
				"file1": {
					Path:  "testing/file1",
					Lines: []string{"content1", "content2"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := defaultDetectLine{}
			if got := d.prepareResolvedFiles(tt.args.resFiles); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("prepareResolvedFiles() = %v, want %v", got, tt.want)
			}
		})
	}
}

const planWithNestedListBlocks = `{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "kubernetes_pod.p",
          "type": "kubernetes_pod",
          "name": "p",
          "values": {
            "spec": [
              {
                "container": [
                  {
                    "name": "a",
                    "security_context": [
                      {
                        "privileged": false
                      }
                    ]
                  },
                  {
                    "name": "b",
                    "security_context": [
                      {
                        "privileged": true
                      }
                    ]
                  }
                ]
              }
            ]
          }
        }
      ]
    }
  },
  "terraform_version": "1.9.0"
}`

func Test_detectLineTerraformPlanNestedListBlocks(t *testing.T) {
	p := &jsonParser.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(planWithNestedListBlocks), "plan.json", false, 1)
	require.NoError(t, err)
	file := &model.FileMetadata{
		Kind:              model.KindTerraformPlan,
		LineInfoDocument:  docs[0],
		LinesOriginalData: utils.SplitLines(planWithNestedListBlocks),
	}
	detect := func(searchKey string) int {
		return defaultDetectLine{}.DetectLine(context.Background(), file, searchKey, 0).Line
	}
	require.Equal(t, 18, detect("kubernetes_pod[p].spec.container[0].security_context.privileged"))
	require.Equal(t, 26, detect("kubernetes_pod[p].spec.container[1].security_context.privileged"))
	require.Equal(t, 23, detect("kubernetes_pod[p].spec.container[1].name"))
	require.Equal(t, 15, detect("kubernetes_pod[p].spec.container.name"))
}
