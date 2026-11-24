/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"reflect"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/test"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCloudFormationGeneratedResourceLine(t *testing.T) {
	const source = `Transform: AWS::LanguageExtensions
Resources:
  Fn::ForEach::Environments:
    - Environment
    - [Prod, Dev]
    - Fn::ForEach::Tiers:
        - Tier
        - [Web]
        - ${Environment}${Tier}Bucket:
            Type: AWS::S3::Bucket
            Properties:
              BucketName: !Sub ${Environment}-${Tier}
  ExplicitBucket:
    Type: AWS::S3::Bucket
`
	ctx := context.Background()
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(source), &root))
	var doc model.Document
	require.NoError(t, doc.UnmarshalYAML(ctx, root.Content[0], nil))
	file := &model.FileMetadata{
		FilePath: "stack.yaml", Kind: model.KindYAML, OriginalData: source, LineInfoDocument: doc,
	}
	detector := NewDetectLine(3)
	for _, tc := range []struct {
		key  string
		line int
	}{
		{"Resources.ProdWebBucket.Properties.BucketName", 12},
		{"Resources.DevWebBucket.Properties.BucketName", 12},
		{"Resources.ProdWebBucket.Properties", 11},
		{"Resources.ProdWebBucket.Properties.VersioningConfiguration", 3},
		{"Resources.ExplicitBucket.Type", 14},
	} {
		t.Run(tc.key, func(t *testing.T) {
			result := detector.DetectLine(ctx, file, tc.key)
			require.Equal(t, tc.line, result.Line)
		})
	}
}

func TestCloudFormationGeneratedResourcePropertyLines(t *testing.T) {
	const source = `Transform: AWS::LanguageExtensions
Parameters:
  Names:
    Type: CommaDelimitedList
    Default: Blue,Green
Resources:
  Fn::ForEach::Functions:
    - Name
    - !Ref Names
    - Function${Name}:
        Type: AWS::Lambda::Function
        Properties:
          Tags:
            - Key: Name
              Value: ${Name}
          Environment:
            Variables:
              TOKEN_${Name}: example
        Metadata:
          'label.${Name}=enabled': example
          list:
            - Wrapped${Name}: example
`
	ctx := context.Background()
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(source), &root))
	var doc model.Document
	require.NoError(t, doc.UnmarshalYAML(ctx, root.Content[0], nil))
	file := &model.FileMetadata{
		FilePath: "stack.yaml", Kind: model.KindYAML, OriginalData: source, LineInfoDocument: doc,
	}
	detector := NewDetectLine(3)
	for _, tc := range []struct {
		key  string
		line int
	}{
		{"Resources.FunctionBlue.Properties.Tags.0.{{Value}}", 15},
		{"Resources[{{FunctionBlue}}].Properties.Tags[0].{{Value}}", 15},
		{"Resources.FunctionBlue.Properties.Environment.Variables.TOKEN_Blue", 18},
		{"Resources.FunctionGreen.Properties.Environment.Variables.TOKEN_Green", 18},
		{"Resources.FunctionBlue.Metadata.{{label.Blue=enabled}}", 20},
		{"Resources.FunctionBlue.Metadata.list[0].WrappedBlue", 22},
	} {
		t.Run(tc.key, func(t *testing.T) {
			require.Equal(t, tc.line, detector.DetectLine(ctx, file, tc.key).Line)
		})
	}
}

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
			got, _ := terraformPlanPath(tt.searchKey)
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
  }
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

// Test_detectLineTerraformPlanEncodedPolicy checks that a searchKey into a
// JSON-encoded attribute, which rules read decoded, points at the attribute.
func Test_detectLineTerraformPlanEncodedPolicy(t *testing.T) {
	plan := `{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_iam_role.deploy",
          "type": "aws_iam_role",
          "name": "deploy",
          "values": {
            "name": "deploy",
            "assume_role_policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"123456789012\"}}]}"
          }
        }
      ]
    }
  }
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
	require.Equal(t, 12, d.DetectLine(context.Background(), file, "aws_iam_role[deploy].assume_role_policy.Statement[0]", 0).Line)
	require.Equal(t, 12, d.DetectLine(context.Background(), file, "aws_iam_role[deploy].assume_role_policy.Statement[0].Principal.AWS", 0).Line)
	// A missing attribute is not mistaken for an encoded one.
	require.NotEqual(t, 12, d.DetectLine(context.Background(), file, "aws_iam_role[deploy].missing.Statement[0]", 0).Line)
}

// Test_detectLineTerraformPlanDeclarations checks that output and variable
// findings point at their declarations in the plan's configuration.
func Test_detectLineTerraformPlanDeclarations(t *testing.T) {
	plan := `{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {}
  },
  "configuration": {
    "root_module": {
      "outputs": {
        "bucket": {
          "expression": {}
        }
      },
      "module_calls": {
        "a": {
          "module": {
            "outputs": {
              "name": {}
            },
            "variables": {
              "region": {}
            }
          }
        },
        "b": {
          "module": {
            "outputs": {
              "name": {}
            }
          }
        }
      }
    }
  }
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
	detect := func(searchKey string) int {
		return d.DetectLine(context.Background(), file, searchKey, 0).Line
	}
	require.Equal(t, 9, detect("output[bucket]"))
	require.Equal(t, 10, detect("output[bucket].expression"))
	require.Equal(t, 20, detect("variable[region]"))
	require.Equal(t, 17, detect("configuration.root_module.module_calls.a.module.outputs.name"))
	require.Equal(t, 27, detect("configuration.root_module.module_calls.b.module.outputs.name"))
	// Declared by two modules: only the full path tells them apart.
	require.NotContains(t, []int{17, 27}, detect("output[name]"))
}

// Test_detectLineTerraformPlanAnchoredChange checks that an anchored
// searchKey into resource_changes finds the same line in the document of a
// scan's line-info reparse as in a whole parse.
func Test_detectLineTerraformPlanAnchoredChange(t *testing.T) {
	plan := `{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {}
  },
  "resource_changes": [
    {
      "address": "aws_s3_bucket.logs",
      "change": {
        "actions": [
          "no-op"
        ]
      }
    },
    {
      "address": "aws_s3_bucket.main",
      "change": {
        "actions": [
          "delete",
          "create"
        ]
      }
    }
  ]
}`
	p := &jsonParser.Parser{}
	_, whole, _, _, err := p.Parse(context.Background(), []byte(plan), "plan.json", false, 1)
	require.NoError(t, err)
	lineInfo, ok := p.ParseLineInfo([]byte(plan), "plan.json")
	require.True(t, ok)

	// The scan's line-info document gets the change list when a key needs it.
	changes, ok := p.ParseLineInfoSection([]byte(plan), "plan.json", "resource_changes")
	require.True(t, ok)
	require.Equal(t, []string{"data", "resource_changes"},
		LineInfoSections(model.KindTerraformPlan, "address={{aws_s3_bucket.main}}.change.actions[1]"))
	lineInfo[0]["resource_changes"] = changes

	for name, doc := range map[string]model.Document{"whole parse": whole[0], "line-info reparse": lineInfo[0]} {
		file := &model.FileMetadata{
			Kind:              model.KindTerraformPlan,
			LineInfoDocument:  doc,
			LinesOriginalData: utils.SplitLines(plan),
		}
		got := defaultDetectLine{}.DetectLine(context.Background(), file,
			"address={{aws_s3_bucket.main}}.change.actions[1]", 0)
		require.Equal(t, 20, got.Line, name)
	}
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
  }
}`
	p := &jsonParser.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(plan), "plan.json", false, 1)
	require.NoError(t, err)

	file := &model.FileMetadata{
		Kind:              model.KindTerraformPlan,
		LineInfoDocument:  docs[0],
		LinesOriginalData: utils.SplitLines(plan),
	}
	got := defaultDetectLine{}.DetectLine(context.Background(), file, "resource.aws_api_gateway_deployment[positive1]", 0)
	// The resource's "values" attribute line is injected structurally now,
	// instead of falling back to a text match on the resource address.
	require.Equal(t, 9, got.Line)
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
  }
}`
	p := &jsonParser.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(plan), "plan.json", false, 1)
	require.NoError(t, err)

	file := &model.FileMetadata{
		Kind:              model.KindTerraformPlan,
		LineInfoDocument:  docs[0],
		LinesOriginalData: utils.SplitLines(plan),
	}
	// Child-module keys are module-prefixed plus the index suffix, so the
	// searchKey bracket contents contain dots and a nested "[0]".
	got := defaultDetectLine{}.DetectLine(
		context.Background(), file, "aws_dynamodb_table[module.dynamodb_table.this[0]].server_side_encryption", 0,
	)
	require.Equal(t, 15, got.Line)
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
  }
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

func Test_detectLineTerraformPlanMinified(t *testing.T) {
	// terraform show -json produces minified output; _dd_lines are all 1.
	// After StringifyContent pretty-prints, LinesOriginalData is multi-line.
	// Structural lookup must fall through to text matching.
	minified := `{"format_version":"1.0","planned_values":{"root_module":{"resources":[{"address":"alicloud_db_instance.example","type":"alicloud_db_instance","name":"example","values":{"address":"0.0.0.0/0"}}]}}}`
	p := &jsonParser.Parser{}
	// Parse computes _dd_lines from the minified bytes.
	_, docs, _, _, err := p.Parse(context.Background(), []byte(minified), "plan.json", false, 1)
	require.NoError(t, err)
	// Simulate what StringifyContent produces for LinesOriginalData.
	prettified, _ := p.StringifyContent([]byte(minified))
	file := &model.FileMetadata{
		Kind:              model.KindTerraformPlan,
		LineInfoDocument:  docs[0],
		LinesOriginalData: utils.SplitLines(prettified),
	}
	got := defaultDetectLine{}.DetectLine(context.Background(), file, "alicloud_db_instance[example].address", 0)
	// Must not return line 1 (the opening "{" from minified _dd_lines).
	require.Greater(t, got.Line, 1)
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

func Test_LineInfoSections(t *testing.T) {
	for name, tt := range map[string]struct {
		kind      model.FileKind
		searchKey string
		want      []string
	}{
		"shallow anchored change": {model.KindTerraformPlan, "address={{aws_s3_bucket.main}}.change.actions", nil},
		"anchor without a path":   {model.KindTerraformPlan, "address={{aws_s3_bucket.main}}", nil},
		"anchored change key":     {model.KindTerraformPlan, "address={{aws_s3_bucket.main}}.change.actions[0]", []string{"data", "resource_changes"}},
		"key rooted at data":      {model.KindTerraformPlan, "data.kubernetes_pod[web].capabilities.add[1]", []string{"data"}},
		"key rooted at changes":   {model.KindTerraformPlan, "resource_changes[0].change.actions", []string{"resource_changes"}},
		"resource key":            {model.KindTerraformPlan, "aws_s3_bucket[main].acl", nil},
		"declaration key":         {model.KindTerraformPlan, "configuration.root_module.outputs.name", nil},
		"encoded attribute key":   {model.KindTerraformPlan, "aws_iam_role[deploy].assume_role_policy.Statement[0]", nil},
		"anchored key, not plan":  {model.KindYAML, "name={{task}}.{{module}}.policy.Statement[0]", nil},
		"changes key, not a plan": {model.KindJSON, "resource_changes[0]", nil},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tt.want, LineInfoSections(tt.kind, tt.searchKey))
		})
	}
}

func TestLineInfoSectionsDistinguishesAnchorsFromSections(t *testing.T) {
	for _, key := range []string{"data", "resource_changes", "address", "name"} {
		for _, tail := range []string{"", ".permissions", ".permissions.actions"} {
			searchKey := key + "={{prod}}" + tail
			require.Nil(t, LineInfoSections(model.KindTerraformPlan, searchKey), searchKey)
		}
		for _, tail := range []string{".permissions.actions[1]", ".permissions.actions.1"} {
			searchKey := key + "={{prod}}" + tail
			require.Equal(t, []string{"data", "resource_changes"}, LineInfoSections(model.KindTerraformPlan, searchKey), searchKey)
		}
	}
	require.Equal(t, []string{"data"}, LineInfoSections(model.KindTerraformPlan, "data.test[prod].permissions.actions[1]"))
	require.Equal(t, []string{"resource_changes"}, LineInfoSections(model.KindTerraformPlan, "resource_changes[0].permissions.actions[1]"))
}
