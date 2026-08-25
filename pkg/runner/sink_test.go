/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/default"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestKics_prepareDocument(t *testing.T) {
	type args struct {
		bodyType string
		kind     model.FileKind
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "prepare document simple test",
			args: args{
				bodyType: `
				{
					"document": [
					  {
						"resource": {
						  "aws_cloudwatch_log_metric_filter": {
							"cis_changes_nacl": {
							  "name": "CIS-4.11-Changes-NACL",
							  "pattern": "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }",
							  "log_group_name": "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}",
							  "metric_transformation": {
								"name": "CIS-4.11-Changes-NACL",
								"namespace": "CIS_Metric_Alarm_Namespace",
								"value": "1",
								"_dd_lines": {
								  "_dd__default": {
									"_dd_line": 6
								  },
								  "_dd_name": {
									"_dd_line": 7
								  },
								  "_dd_namespace": {
									"_dd_line": 8
								  },
								  "_dd_value": {
									"_dd_line": 9
								  }
								}
							  },
							  "_dd_lines": {
								"_dd__default": {
								  "_dd_line": 1
								},
								"_dd_log_group_name": {
								  "_dd_line": 4
								},
								"_dd_metric_transformation": {
								  "_dd_line": 6
								},
								"_dd_name": {
								  "_dd_line": 2
								},
								"_dd_pattern": {
								  "_dd_line": 3
								}
							  }
							}
						  }
						},
						"_dd_lines": {
						  "_dd__default": {
							"_dd_line": 0
						  },
						  "_dd_resource": {
							"_dd_line": 1
						  }
						}
					  }
					]
				  }
				`,
				kind: model.KindTerraform,
			},
			want: `
			{
				"document": [
				  {
					"resource": {
					  "aws_cloudwatch_log_metric_filter": {
						"cis_changes_nacl": {
						  "log_group_name": "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}",
						  "metric_transformation": {
							"name": "CIS-4.11-Changes-NACL",
							"namespace": "CIS_Metric_Alarm_Namespace",
							"value": "1"
						  },
						  "name": "CIS-4.11-Changes-NACL",
						  "pattern": "{\"_dd_filter_expr\":{\"_op\":\"||\",\"_left\":{\"_op\":\"||\",\"_left\":{\"_op\":\"||\",\"_left\":{\"_op\":\"||\",\"_left\":{\"_op\":\"||\",\"_left\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"CreateNetworkAcl\"},\"_right\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"CreateNetworkAclEntry\"}},\"_right\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"DeleteNetworkAcl\"}},\"_right\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"DeleteNetworkAclEntry\"}},\"_right\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"ReplaceNetworkAclEntry\"}},\"_right\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"ReplaceNetworkAclAssociation\"}},\"_kics_filter_expr\":{\"_op\":\"||\",\"_left\":{\"_op\":\"||\",\"_left\":{\"_op\":\"||\",\"_left\":{\"_op\":\"||\",\"_left\":{\"_op\":\"||\",\"_left\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"CreateNetworkAcl\"},\"_right\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"CreateNetworkAclEntry\"}},\"_right\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"DeleteNetworkAcl\"}},\"_right\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"DeleteNetworkAclEntry\"}},\"_right\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"ReplaceNetworkAclEntry\"}},\"_right\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"ReplaceNetworkAclAssociation\"}}}"
						}
					  }
					}
				  }
				]
			  }

			`,
		},
		{
			// Flat (not wrapped in "document":[...]) to match sink.go's real per-document input.
			name: "prepare document resolves pattern for terraform plan documents",
			args: args{
				bodyType: `
				{
					"resource": {
					  "aws_cloudwatch_log_metric_filter": {
						"cis_changes_nacl": {
						  "name": "CIS-4.11-Changes-NACL",
						  "pattern": "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) }",
						  "log_group_name": "aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup"
						}
					  }
					},
					"configuration": {
					  "root_module": {
						"resources": [
						  {
							"address": "aws_cloudwatch_log_metric_filter.cis_changes_nacl",
							"expressions": {
							  "pattern": {
								"constant_value": "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) }"
							  }
							}
						  }
						]
					  }
					}
				  }
				`,
				kind: model.KindTerraformPlan,
			},
			want: `
			{
				"resource": {
				  "aws_cloudwatch_log_metric_filter": {
					"cis_changes_nacl": {
					  "log_group_name": "aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup",
					  "name": "CIS-4.11-Changes-NACL",
					  "pattern": "{\"_dd_filter_expr\":{\"_op\":\"||\",\"_left\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"CreateNetworkAcl\"},\"_right\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"CreateNetworkAclEntry\"}},\"_kics_filter_expr\":{\"_op\":\"||\",\"_left\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"CreateNetworkAcl\"},\"_right\":{\"_selector\":\"$.eventName\",\"_op\":\"=\",\"_value\":\"CreateNetworkAclEntry\"}}}"
					}
				  }
				},
				"configuration": {
				  "root_module": {
					"resources": [
					  {
						"address": "aws_cloudwatch_log_metric_filter.cis_changes_nacl",
						"expressions": {
						  "pattern": {
							"constant_value": "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) }"
						  }
						}
					  }
					]
				  }
				}
			  }
			`,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interf := make(map[string]interface{})
			err := json.Unmarshal([]byte(tt.args.bodyType), &interf)
			require.NoError(t, err)

			got := PrepareScanDocument(ctx, interf, tt.args.kind)
			compareJSONLine(t, got, tt.want)
		})
	}
}

// TestSink_TFPlanExposesAfterUnknownAndConfiguration drives a plan through the
// real Parser.Parse -> PrepareScanDocument pipeline used in production.
func TestSink_TFPlanExposesAfterUnknownAndConfiguration(t *testing.T) {
	ctx := context.Background()

	planJSON := []byte(`{
		"format_version": "1.2",
		"terraform_version": "1.5.0",
		"planned_values": {
			"root_module": {
				"resources": [
					{
						"address": "aws_s3_bucket.main",
						"mode": "managed",
						"type": "aws_s3_bucket",
						"name": "main",
						"values": {
							"acl": "private"
						}
					}
				]
			}
		},
		"resource_changes": [
			{
				"address": "aws_s3_bucket.main",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "main",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"acl": "private"
					},
					"after_unknown": {
						"bucket": true,
						"id": true
					}
				}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{
						"address": "aws_s3_bucket.main",
						"mode": "managed",
						"type": "aws_s3_bucket",
						"name": "main",
						"expressions": {
							"bucket": {
								"references": ["random_id.suffix"]
							}
						}
					}
				]
			}
		}
	}`)

	p := &jsonParser.Parser{}
	_, docs, _, _, err := p.Parse(ctx, planJSON, "tfplan.json", false, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	kind, ok := p.KindForContent(planJSON)
	require.True(t, ok)
	require.Equal(t, model.KindTerraformPlan, kind)

	prepared := PrepareScanDocument(ctx, docs[0], kind)

	require.Contains(t, prepared, "resource")
	require.Contains(t, prepared, "resource_changes")
	require.Contains(t, prepared, "configuration")

	b, err := json.Marshal(prepared)
	require.NoError(t, err)
	require.NotContains(t, string(b), "_dd_lines",
		"line-tracking metadata must not leak into resource_changes/configuration")

	require.JSONEq(t, `{
		"resource": {
			"aws_s3_bucket": {
				"main": {
					"acl": "private"
				}
			}
		},
		"_dd_tfplan_meta": {
			"aws_s3_bucket": {
				"main": {
					"address": "aws_s3_bucket.main",
					"after_unknown": {
						"bucket": true,
						"id": true
					},
					"configuration_expressions": {
						"bucket": {
							"references": ["random_id.suffix"]
						}
					}
				}
			}
		},
		"resource_changes": [
			{
				"address": "aws_s3_bucket.main",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "main",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"acl": "private"
					},
					"after_unknown": {
						"bucket": true,
						"id": true
					}
				}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{
						"address": "aws_s3_bucket.main",
						"mode": "managed",
						"type": "aws_s3_bucket",
						"name": "main",
						"expressions": {
							"bucket": {
								"references": ["random_id.suffix"]
							}
						}
					}
				]
			}
		}
	}`, string(b))
}

func TestKics_resolveCRLFFile(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "CRLF File 1",
			body: "Resources:\r\nDemoSecurityGroup:\r\nType: 'AWS::EC2::SecurityGroup'\r\nProperties:\r\nVpcId: !Ref myVPC\r\nGroupDescription: Ports open to the world\r\nSecurityGroupIngress:\r\n- Description: Allowing port 22 for everyone\r\nIpProtocol: tcp\r\nFromPort: 22\r\nToPort: 22\r\nCidrIp: \"0.0.0.0/0\"\r\n# dd-iac-scan ignore-block\r\n- Description: Allowing port 80 for everyone\r\nIpProtocol: tcp\r\nFromPort: 80\r\nToPort: 80\r\nCidrIp: \"0.0.0.0/0\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved := resolveCRLFFile([]byte(tt.body))
			require.NotContains(t, resolved, "\r\n", tt.name+" contains CRLF")
		})
	}
}

func compareJSONLine(t *testing.T, test1 interface{}, test2 string) {
	stringefiedJSON, err := json.Marshal(&test1)
	require.NoError(t, err)
	require.JSONEq(t, test2, string(stringefiedJSON))
}

// TestSink_ParseFailureLogLevel verifies that sink demotes the parse-error log
// from Error to Debug when the file is under a chart that was already recorded
// as a render failure — the central behaviour introduced by this PR.
func TestSink_ParseFailureLogLevel(t *testing.T) {
	ctx := context.Background()

	parsers, err := parser.NewBuilder(ctx).
		Add(&yamlParser.Parser{}).
		Build([]string{""}, []string{""})
	require.NoError(t, err)
	require.NotEmpty(t, parsers)

	tests := []struct {
		name        string
		filename    string
		failedChart string // if non-empty, register before calling sink
		wantLevel   string
	}{
		{
			name:      "not under failed chart logs at error",
			filename:  "/repo/other/deploy.yaml",
			wantLevel: `"level":"error"`,
		},
		{
			name:        "under failed chart logs at debug",
			filename:    "/repo/charts/watchdog/templates/deploy.yaml",
			failedChart: "/repo/charts/watchdog",
			wantLevel:   `"level":"debug"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			testCtx := zerolog.New(&logBuf).WithContext(ctx)

			svc := &Service{
				Parser:      parsers[0],
				Tracker:     noopTracker{},
				MaxFileSize: 1,
			}
			if tt.failedChart != "" {
				svc.recordFailedHelmChart(tt.failedChart)
			}

			// "{" is an unclosed YAML flow mapping — guaranteed parse error.
			rc := bytes.NewReader([]byte("{"))
			buf := make([]byte, 64)
			_ = svc.sink(testCtx, tt.filename, "scan1", rc, buf, false, 1)

			require.Contains(t, logBuf.String(), tt.wantLevel)
		})
	}
}

func TestSink_IgnoreLinesWithResolvedFiles(t *testing.T) {
	tests := []struct {
		name              string
		filePath          string
		wantIgnoreLines   []int
		wantResolvedFiles bool
	}{
		{
			name:              "yaml with include keeps ignore lines on original coordinates",
			filePath:          filepath.Join("..", "..", "test", "fixtures", "resolve_ignore_lines", "docker-compose.yaml"),
			wantIgnoreLines:   []int{6, 7},
			wantResolvedFiles: true,
		},
		{
			name:              "yaml without include keeps parser ignore lines",
			filePath:          filepath.Join("..", "..", "test", "fixtures", "resolve_ignore_lines", "no-include.yaml"),
			wantIgnoreLines:   []int{4, 5},
			wantResolvedFiles: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := os.ReadFile(tt.filePath)
			require.NoError(t, err)

			file := sinkFile(t, tt.filePath, content)
			require.Equal(t, tt.wantResolvedFiles, len(file.ResolvedFiles) > 0)
			require.Equal(t, tt.wantIgnoreLines, file.LinesIgnore)
		})
	}
}

func sinkFile(t *testing.T, filename string, content []byte) *model.FileMetadata {
	t.Helper()
	ctx := context.Background()
	parsers, err := parser.NewBuilder(ctx).
		Add(&yamlParser.Parser{}).
		Build([]string{""}, []string{""})
	require.NoError(t, err)
	require.NotEmpty(t, parsers)

	s := &Service{
		Parser:      parsers[0],
		Storage:     storage.NewMemoryStorage(),
		Tracker:     noopTracker{},
		MaxFileSize: 5,
	}
	require.NoError(t, s.sink(ctx, filename, "scanID", bytes.NewReader(content), make([]byte, mbConst), false, 15))
	require.Len(t, s.files, 1)
	return s.files[0]
}

type noopTracker struct{}

func (noopTracker) TrackFileFound(_ string)            {}
func (noopTracker) TrackFileParse(_ string)            {}
func (noopTracker) TrackFileFoundCountLines(_ int)     {}
func (noopTracker) TrackFileParseCountLines(_ int)     {}
func (noopTracker) TrackFileIgnoreCountLines(_ int)    {}
func (noopTracker) TrackFileFoundCountResources(_ int) {}
