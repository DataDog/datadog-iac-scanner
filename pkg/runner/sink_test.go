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
	"errors"
	"fmt"
	"go/build"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	iniHostsParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/ansible/ini/hosts"
	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
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
	// Sunk, the plan's equal subtrees are a single tree.
	file := sinkFileWith(t, func(b *parser.Builder) *parser.Builder { return b.Add(p) }, "tfplan.json", planJSON)
	meta := file.Document["_dd_tfplan_meta"].(map[string]interface{})["aws_s3_bucket"].(map[string]interface{})["main"]
	change := file.Document["resource_changes"].([]interface{})[0].(map[string]interface{})["change"]
	require.Equal(t,
		reflect.ValueOf(meta.(map[string]interface{})["after_unknown"]).Pointer(),
		reflect.ValueOf(change.(map[string]interface{})["after_unknown"]).Pointer())
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
			_ = sinkReader(svc, testCtx, tt.filename, "scan1", rc, buf, false, 1)

			require.Contains(t, logBuf.String(), tt.wantLevel)
		})
	}
}

// TestSink_ParseFailureRedactsCredentials verifies that the credentials a
// third-party parser echoes back from the scanned file never reach the logs.
// The Ansible INI parser quotes the offending line verbatim
// ("bad key=value pair supplied: postgres://user:pass@host/db"), which is how
// customer database credentials used to leak into the scanner's error logs.
func TestSink_ParseFailureRedactsCredentials(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		wantKept string
	}{
		{
			name:     "plain scheme",
			url:      "postgres://user:sup3rs3cret@localhost:5432/dogdata",
			wantKept: "postgres://localhost:5432/dogdata",
		},
		{
			// Driver-qualified schemes are the common spelling in .ini/.env
			// config and put `+driver` before `://`.
			name:     "driver qualified scheme",
			url:      "postgresql+psycopg2://user:sup3rs3cret@localhost:5432/dogdata",
			wantKept: "postgresql+psycopg2://localhost:5432/dogdata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			parsers, err := parser.NewBuilder(ctx).
				Add(&iniHostsParser.Parser{}).
				Build([]string{"ansible"}, []string{""})
			require.NoError(t, err)
			require.NotEmpty(t, parsers)

			// A connection string is not valid Ansible inventory syntax, so
			// aini.Parse fails with "bad key=value pair supplied: <the URL>".
			content := "[main]\ndogdata_url = " + tt.url + "\n"

			var logBuf bytes.Buffer
			testCtx := zerolog.New(&logBuf).WithContext(ctx)

			svc := &Service{
				Parser:      parsers[0],
				Tracker:     noopTracker{},
				MaxFileSize: 1,
			}

			rc := bytes.NewReader([]byte(content))
			buf := make([]byte, 1024)
			require.NoError(t, sinkReader(svc, testCtx, "/repo/test/etc/test.ini", "scan1", rc, buf, false, 1))

			logged := logBuf.String()
			// The failure is still reported, with the offending scheme/host kept for triage.
			require.Contains(t, logged, "failed to parse file content")
			require.Contains(t, logged, tt.wantKept)
			// ... but without the credentials that were embedded in the scanned file.
			require.NotContains(t, logged, "sup3rs3cret")
			require.NotContains(t, logged, "user:sup3rs3cret")
		})
	}
}

func TestRedactErrorForLog(t *testing.T) {
	require.Equal(t, "", redactErrorForLog(nil))
	require.Equal(t,
		"bad key=value pair supplied: postgres://localhost:5432/dogdata",
		redactErrorForLog(errors.New("bad key=value pair supplied: postgres://u:p@localhost:5432/dogdata")))
	require.Equal(t, "yaml: line 1: did not find expected node content",
		redactErrorForLog(errors.New("yaml: line 1: did not find expected node content")))
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
	return sinkFileWith(t, func(b *parser.Builder) *parser.Builder { return b.Add(&yamlParser.Parser{}) }, filename, content)
}

func sinkFileWith(t *testing.T, add func(*parser.Builder) *parser.Builder, filename string, content []byte,
	configure ...func(*Service)) *model.FileMetadata {
	t.Helper()
	ctx := context.Background()
	parsers, err := add(parser.NewBuilder(ctx)).
		Build([]string{""}, []string{""})
	require.NoError(t, err)
	require.NotEmpty(t, parsers)

	s := &Service{
		Parser:      parsers[0],
		Storage:     storage.NewMemoryStorage(),
		Tracker:     noopTracker{},
		MaxFileSize: 5,
	}
	for _, configure := range configure {
		configure(s)
	}
	require.NoError(t, sinkReader(s, ctx, filename, "scanID", bytes.NewReader(content), make([]byte, mbConst), false, 15))
	require.Len(t, s.files, 1)
	return s.files[0]
}

func TestSinkTerraformContractOnlyTracksFoundLinesLikeLegacy(t *testing.T) {
	content := []byte(`resource "aws_s3_bucket" "example" {
  bucket = "example"
}
`)
	run := func(contractOnly bool) *foundLinesTracker {
		ctx := context.Background()
		parsers, err := parser.NewBuilder(ctx).Add(terraformParser.NewDefault()).Build([]string{"terraform"}, []string{""})
		require.NoError(t, err)
		require.Len(t, parsers, 1)
		tracker := &foundLinesTracker{}
		service := &Service{
			Parser: parsers[0], Storage: storage.NewMemoryStorage(), Tracker: tracker,
			MaxFileSize: mbConst, SkipLegacyTerraformDocumentParsing: contractOnly,
		}
		require.NoError(t, sinkReader(service, ctx, "main.tf", "scanID", bytes.NewReader(content), make([]byte, mbConst), false, 15))
		require.Len(t, service.files, 1)
		return tracker
	}

	legacy, contractOnly := run(false), run(true)
	require.Equal(t, legacy.calls, contractOnly.calls)
	require.Equal(t, 2, contractOnly.calls, "both paths report source and resolved-file line counts")
	require.Equal(t, legacy.lines, contractOnly.lines)
}

type foundLinesTracker struct {
	noopTracker
	calls int
	lines int
}

func (t *foundLinesTracker) TrackFileFoundCountLines(lines int) {
	t.calls++
	t.lines += lines
}

type noopTracker struct{}

func (noopTracker) TrackFileFound(_ string)            {}
func (noopTracker) TrackFileParse(_ string)            {}
func (noopTracker) TrackTerraformPlanParse(_ string)   {}
func (noopTracker) TrackFileFoundCountLines(_ int)     {}
func (noopTracker) TrackFileParseCountLines(_ int)     {}
func (noopTracker) TrackFileIgnoreCountLines(_ int)    {}
func (noopTracker) TrackFileFoundCountResources(_ int) {}
func (noopTracker) TrackFileFailed(_, _ string)        {}
func (noopTracker) TrackFileEmpty(_ string)            {}
func (noopTracker) TrackRenderFailed(_ string)         {}

// sinkReader reads a file and sinks it the way the shared walk does.
func sinkReader(s *Service, ctx context.Context, filename, scanID string,
	rc io.Reader, data []byte, openAPIResolveReferences bool, maxResolverDepth int) error {
	c, err := getContent(rc, data, s.MaxFileSize, filename)
	return s.sinkContent(ctx, filename, scanID, c, err, openAPIResolveReferences, maxResolverDepth)
}

// TestSink_planLineInfoRetention checks that a scan keeps a plan's line-info
// tree across decode passes, and that a scan exporting line info does not
// keep trees in a retention that could drop them under the export.
func TestSink_planLineInfoRetention(t *testing.T) {
	plan := []byte(`{"format_version": "1.0", "planned_values": {"root_module": {"resources": [
		{"address": "aws_s3_bucket.main", "type": "aws_s3_bucket", "name": "main", "values": {"acl": "private"}}]}}}`)
	p := &jsonParser.Parser{}
	add := func(b *parser.Builder) *parser.Builder { return b.Add(p) }
	ctx := context.Background()
	use := func(file *model.FileMetadata) {
		require.NoError(t, file.UseLineInfoDocument(ctx, func(doc map[string]interface{}) error {
			require.Contains(t, doc, "resource")
			return nil
		}))
		file.DiscardLineInfoDocument()
	}

	scan := sinkFileWith(t, add, "plan.json", plan)
	use(scan)
	require.NotNil(t, scan.LineInfoDocument, "kept for the next finding")
	// A service without an inspector has one decoder, even on a many-core host.
	s := &Service{}
	retention := s.planLineInfoRetention()
	scan.SetLineInfoRetention(retention)
	use(scan)
	other := sinkFileWith(t, add, "other.json", plan)
	other.SetLineInfoRetention(retention)
	use(other)
	require.Nil(t, scan.LineInfoDocument, "serial decoding retains only one plan")

	exported := sinkFileWith(t, add, "plan.json", plan, func(s *Service) { s.LineInfoPayload = true })
	use(exported)
	require.Nil(t, exported.LineInfoDocument)
}

// TestSink_planChangeSectionBuiltForAnchoredKeys checks that a scan's plan
// line-info holds the change list only for a finding whose search key reads
// it, and that the finding then gets its exact line.
func TestSink_planChangeSectionBuiltForAnchoredKeys(t *testing.T) {
	plan := []byte(`{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {}
  },
  "resource_changes": [
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
}`)
	p := &jsonParser.Parser{}
	file := sinkFileWith(t, func(b *parser.Builder) *parser.Builder { return b.Add(p) }, "plan.json", plan)
	ctx := context.Background()
	detect := func(searchKey string) (line int, hasChanges bool) {
		require.NoError(t, file.UseLineInfoDocumentSections(ctx, detector.LineInfoSections(file.Kind, searchKey),
			func(doc map[string]interface{}) error {
				line = detector.NewDetectLine(0).DetectLine(ctx, file, searchKey).Line
				_, hasChanges = doc["resource_changes"]
				return nil
			}))
		return line, hasChanges
	}

	_, hasChanges := detect("aws_s3_bucket[main].acl")
	require.False(t, hasChanges, "not built for a key that does not read it")

	_, hasChanges = detect("address={{aws_s3_bucket.main}}.change.actions")
	require.False(t, hasChanges, "a shallow anchor uses text matching, not change markers")

	line, hasChanges := detect("address={{aws_s3_bucket.main}}.change.actions[1]")
	require.True(t, hasChanges)
	require.Equal(t, 12, line)
}

// The runner records parse outcomes in the scan's own vocabulary: the
// optional inventory exporter reads them, the runner does not depend on it.
func TestRunnerDoesNotDependOnTheInventory(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	require.NoError(t, err)
	require.NotContains(t, pkg.Imports, "github.com/DataDog/datadog-iac-scanner/pkg/inventory")
}

// Exercise real plan loaders, lazy sections and eviction together, rather
// than only the in-memory loaders in model's retention tests.
func TestSinkConcurrentPlanLineInfoEviction(t *testing.T) {
	plan := []byte(`{
 "format_version": "1.0",
 "planned_values": {"root_module": {"resources": [
  {"address": "aws_s3_bucket.main", "type": "aws_s3_bucket", "name": "main", "values": {"acl": "private"}}
 ]}},
 "resource_changes": [{"address": "aws_s3_bucket.main", "change": {"actions": ["update"]}}]
}`)
	p := &jsonParser.Parser{}
	retention := model.NewLineInfoRetention(2)
	files := make([]*model.FileMetadata, 4)
	for i := range files {
		files[i] = sinkFileWith(t, func(b *parser.Builder) *parser.Builder { return b.Add(p) },
			fmt.Sprintf("plan-%d.json", i), plan)
		files[i].SetLineInfoRetention(retention)
	}
	var wg sync.WaitGroup
	for _, file := range files {
		wg.Go(func() {
			for range 10 {
				err := file.UseLineInfoDocumentSections(context.Background(), []string{"resource_changes"},
					func(doc map[string]interface{}) error {
						resource := doc["resource"].(map[string]interface{})["aws_s3_bucket"].(map[string]interface{})["main"]
						if resource.(map[string]interface{})["acl"] != "private" || doc["resource_changes"] == nil {
							return errors.New("incomplete plan line-info document")
						}
						return nil
					})
				require.NoError(t, err)
			}
		})
	}
	wg.Wait()
	retained := 0
	for _, file := range files {
		if file.LineInfoDocument != nil {
			retained++
		}
		file.ReleasePostEvalData()
		require.Nil(t, file.LineInfoDocument)
	}
	require.LessOrEqual(t, retained, 2)
}

// This is the scan path used by custom rules: a deep anchor selects a value
// held only by a prior-state data source. Verify exact lines through loading,
// eviction/reload, and full line-info payload export.
func TestSinkPriorDataAnchoredLinesMatchFullParse(t *testing.T) {
	plan := []byte(`{
 "format_version": "1.2",
 "planned_values": {"root_module": {}},
 "prior_state": {
  "format_version": "1.0",
  "values": {"root_module": {"resources": [{
   "address": "data.kubernetes_pod.web",
   "mode": "data",
   "type": "kubernetes_pod",
   "name": "web",
   "values": {"pods": [{
    "name": "web",
    "securityContext": {"capabilities": {"add": [
     "NET_ADMIN",
     "SYS_ADMIN"
    ]}}
   }]}
  }]}}
 }
}`)
	ctx := context.Background()
	p := &jsonParser.Parser{}
	add := func(b *parser.Builder) *parser.Builder { return b.Add(p) }
	file := sinkFileWith(t, add, "plan.json", plan)
	require.NoError(t, file.UseLineInfoDocument(ctx, func(doc map[string]interface{}) error {
		require.NotContains(t, doc, "data", "ordinary resource lookups stay light")
		return nil
	}))
	key := "name={{web}}.securityContext.capabilities.add[1]"
	expected := 0
	for i, line := range file.Lines() {
		if bytes.Contains([]byte(line), []byte(`"SYS_ADMIN"`)) {
			expected = i + 1
			break
		}
	}
	require.Positive(t, expected)
	for range 2 {
		require.NoError(t, file.UseLineInfoDocumentSections(ctx, detector.LineInfoSections(file.Kind, key),
			func(doc map[string]interface{}) error {
				require.Contains(t, doc, "data")
				require.Equal(t, expected, detector.NewDetectLine(0).DetectLine(ctx, file, key).Line)
				return nil
			}))
		file.SetLineInfoRetention(nil)
		file.DiscardLineInfoDocument()
	}
	exported := sinkFileWith(t, add, "plan.json", plan, func(s *Service) { s.LineInfoPayload = true })
	payload := model.FileMetadatas{exported}.Combine(ctx, true)
	require.Len(t, payload.Documents, 1)
	_, whole, _, _, err := p.Parse(ctx, []byte(exported.OriginalData), "plan.json", false, 15)
	require.NoError(t, err)
	want, err := json.Marshal(whole[0]["data"])
	require.NoError(t, err)
	got, err := json.Marshal(payload.Documents[0]["data"])
	require.NoError(t, err)
	require.JSONEq(t, string(want), string(got))
}

func TestSinkAnchorSectionNameCollisions(t *testing.T) {
	plan := []byte(`{
  "format_version":"1.2",
  "planned_values":{"root_module":{}},
  "prior_state":{"format_version":"1.0","values":{"root_module":{"resources":[{
   "address":"data.test.source","mode":"data","type":"test","name":"source",
   "values":{"items":[{
    "data":"in_prior","resource_changes":"in_prior","name":"in_prior",
    "permissions":{"actions":[
     "safe",
     "DANGEROUS_PRIOR"
    ]}
   }]}
  }]}}},
  "resource_changes":[{
   "data":"in_changes","resource_changes":"in_changes","name":"in_changes",
   "permissions":{"actions":[
    "safe",
    "DANGEROUS_CHANGES"
   ]}
  }]
 }`)
	for _, anchor := range []string{"data", "resource_changes", "name"} {
		for target, marker := range map[string]string{"in_prior": "DANGEROUS_PRIOR", "in_changes": "DANGEROUS_CHANGES"} {
			t.Run(anchor+"/"+target, func(t *testing.T) {
				p := &jsonParser.Parser{}
				// A fresh file is essential: a previous finding must not hide a
				// missing section by having already loaded it.
				file := sinkFileWith(t, func(b *parser.Builder) *parser.Builder { return b.Add(p) }, "plan.json", plan)
				key := anchor + "={{" + target + "}}.permissions.actions[1]"
				expected := 0
				for i, line := range file.Lines() {
					if bytes.Contains([]byte(line), []byte(marker)) {
						expected = i + 1
						break
					}
				}
				require.Positive(t, expected)
				require.NoError(t, file.UseLineInfoDocumentSections(context.Background(), detector.LineInfoSections(file.Kind, key),
					func(doc map[string]interface{}) error {
						require.Contains(t, doc, "data")
						require.Contains(t, doc, "resource_changes")
						require.Equal(t, expected, detector.NewDetectLine(0).DetectLine(context.Background(), file, key).Line)
						return nil
					}))
			})
		}
	}
}

func TestSinkTerraformContractOnlyConcurrentLinesAndParseFailure(t *testing.T) {
	ctx := context.Background()
	parsers, err := parser.NewBuilder(ctx).
		Add(terraformParser.NewDefault()).
		Build([]string{"terraform"}, []string{""})
	require.NoError(t, err)
	require.NotEmpty(t, parsers)

	store := storage.NewMemoryStorage()
	trk, err := tracker.NewTracker(3)
	require.NoError(t, err)
	svc := &Service{
		Parser:                             parsers[0],
		Storage:                            store,
		Tracker:                            trk,
		MaxFileSize:                        1,
		SkipLegacyTerraformDocumentParsing: true,
	}

	valid := []byte("resource \"aws_s3_bucket\" \"a\" {\n  bucket = \"ok\"\n}\n")
	require.NoError(t, svc.sinkContent(ctx, "main.tf", "scan1", &Content{Content: &valid, CountLines: 3}, nil, false, 15))
	require.Equal(t, 1, trk.ParsedFiles)
	require.Empty(t, trk.FailedFiles)

	// Concurrent file.Lines() calls must be race-free under -race.
	require.Len(t, svc.files, 1)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lines := svc.files[0].Lines()
			require.Len(t, lines, 4)
		}()
	}
	wg.Wait()

	// Invalid HCL must be tracked as failed rather than parsed.
	broken := []byte("resource \"aws_s3_bucket\" \"bad\" {\n  bucket = [\n")
	require.NoError(t, svc.sinkContent(ctx, "broken.tf", "scan1", &Content{Content: &broken, CountLines: 2}, nil, false, 15))
	require.Equal(t, 1, trk.ParsedFiles)
	require.Contains(t, trk.FailedFiles, "broken.tf")
}
