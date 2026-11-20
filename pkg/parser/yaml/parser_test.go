/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package yaml

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/DataDog/datadog-iac-scanner/test"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestParse_InvalidScalarLogging(t *testing.T) {
	tests := []struct {
		name      string
		filePath  string
		logLevel  zerolog.Level
		wantLevel string
	}{
		{"regular file", "services/app.yaml", zerolog.DebugLevel, "warn"},
		{"regular file at error level", "services/app.yaml", zerolog.ErrorLevel, ""},
		{"testdata", "testdata/golden/services/app.yaml", zerolog.DebugLevel, "debug"},
		{"testdata at warn level", "testdata/golden/services/app.yaml", zerolog.WarnLevel, ""},
		{"fixtures", "tests/fixtures/app.yaml", zerolog.DebugLevel, "debug"},
		{"__fixtures__", "tests/__fixtures__/app.yaml", zerolog.DebugLevel, "debug"},
		{"non-fixture filename", "config/fixtures.yaml", zerolog.DebugLevel, "warn"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			log := zerolog.New(&logs).Level(tt.logLevel)
			ctx := log.WithContext(t.Context())
			log.Debug().Msg("before YAML parsing")
			_, docs, _, _, err := Parse(ctx, nil, []byte("count: !!int invalid-number\n"), tt.filePath, false, 0)
			log.Debug().Msg("after YAML parsing")
			require.NoError(t, err)
			require.Len(t, docs, 1)
			require.Equal(t, "invalid-number", docs[0]["count"])
			require.Equal(t, tt.filePath, docs[0]["_path"])

			decoder := json.NewDecoder(&logs)
			matched := 0
			for {
				var event struct {
					Level   string `json:"level"`
					Message string `json:"message"`
				}
				err := decoder.Decode(&event)
				if errors.Is(err, io.EOF) {
					break
				}
				require.NoError(t, err)
				if !strings.HasPrefix(event.Message, "failed to decode scalar in yaml parser ") {
					continue
				}
				matched++
				require.Equal(t, tt.wantLevel, event.Level)
				require.Contains(t, event.Message, tt.filePath)
				require.Contains(t, event.Message, "invalid-number")
			}
			wantEvents := 1
			if tt.wantLevel == "" {
				wantEvents = 0
			}
			require.Equal(t, wantEvents, matched, "unexpected number of scalar parse failure events")
		})
	}
}

// TestParser_Parse tests the functions [Parse()] and all the methods called by them
func TestParser_Parse(t *testing.T) { //nolint
	have := []string{`
# dd-iac-scan ignore-block
martin:
  name: test
---
martin2:
  name: test2
`, `
---
# dd-iac-scan ignore-block
- name: Create an empty bucket2
  amazon.aws.aws_s3:
    bucket: mybucket
    mode: create
    permission: authenticated-read
`,
		`
test:
  - &test_anchor
    group:
      # dd-iac-scan ignore-line
      name: "cx"
test_2:
  perm:
    - <<: *test_anchor
`, `
kube_node_ready_controller_memory: "200Mi"
{{if eq .Cluster.Environment "test"}}
downscaler_default_uptime: "Mon-Fri 07:30-20:30 Europe/Berlin"
downscaler_default_downtime: "never"
downscaler_enabled: "true"
{{else if eq .Cluster.Environment "e2e"}}
downscaler_default_uptime: "always"
downscaler_default_downtime: "never"
downscaler_enabled: "true"
{{else}}
downscaler_default_uptime: "always"
downscaler_default_downtime: "never"
downscaler_enabled: "false"
{{end}}
`, `
resources:
- name: &SA_NAME my-vm-access
  type: *SA_NAME
- name: my-vm
  type: vm.jinja
  properties:
    serviceAccountId: *SA_NAME
`,
	}

	type wantExpect struct {
		want              string
		wantErr           bool
		wantLinesToIgnore []int
	}

	want := []wantExpect{
		{
			want: `[
			{
			  "_dd_lines": {
				"_dd__default": {
				  "_dd_line": 0
				},
				"_dd_martin": {
				  "_dd_line": 3
				}
			  },
			  "martin": {
				"_dd_lines": {
				  "_dd__default": {
					"_dd_line": 3
				  },
				  "_dd_name": {
					"_dd_line": 4
				  }
				},
				"name": "test"
			  }, 
			  "_path":"test.yaml"
			},
			{
			  "_dd_lines": {
				"_dd__default": {
				  "_dd_line": 0
				},
				"_dd_martin2": {
				  "_dd_line": 6
				}
			  },
			  "martin2": {
				"_dd_lines": {
				  "_dd__default": {
					"_dd_line": 6
				  },
				  "_dd_name": {
					"_dd_line": 7
				  }
				},
				"name": "test2"
			  }, 
			  "_path":"test.yaml"
			}
		  ]
		  `,
			wantErr:           false,
			wantLinesToIgnore: []int{3, 2, 4},
		},
		{
			want: `[
			{
			  "_dd_lines": {
				"_dd__default": {
				  "_dd_arr": [
					{
					  "_dd__default": {
						"_dd_line": 4
					  },
					  "_dd_amazon.aws.aws_s3": {
						"_dd_line": 5
					  },
					  "_dd_name": {
						"_dd_line": 4
					  }
					}
				  ],
				  "_dd_line": 0
				}
			  },
			  "playbooks": [
				{
				  "amazon.aws.aws_s3": {
					"_dd_lines": {
					  "_dd__default": {
						"_dd_line": 5
					  },
					  "_dd_bucket": {
						"_dd_line": 6
					  },
					  "_dd_mode": {
						"_dd_line": 7
					  },
					  "_dd_permission": {
						"_dd_line": 8
					  }
					},
					"bucket": "mybucket",
					"mode": "create",
					"permission": "authenticated-read"
				  },
				  "name": "Create an empty bucket2"
				}
			  ], 
			"_path":"test.yaml"
			}
		  ]
		  `,
			wantErr:           false,
			wantLinesToIgnore: []int{4, 3, 5, 6, 7, 8},
		},
		{
			want: `[
			{
			  "_dd_lines": {
				"_dd__default": {
				  "_dd_line": 0
				},
				"_dd_test": {
				  "_dd_arr": [
					{
					  "_dd__default": {
						"_dd_line": 4
					  },
					  "_dd_group": {
						"_dd_line": 4
					  }
					}
				  ],
				  "_dd_line": 2
				},
				"_dd_test_2": {
				  "_dd_line": 7
				}
			  },
			  "test": [
				{
				  "group": {
					"_dd_lines": {
					  "_dd__default": {
						"_dd_line": 4
					  },
					  "_dd_name": {
						"_dd_line": 6
					  }
					},
					"name": "cx"
				  }
				}
			  ],
			  "test_2": {
				"_dd_lines": {
				  "_dd__default": {
					"_dd_line": 7
				  },
				  "_dd_perm": {
					"_dd_arr": [
					  {
						"_dd_<<": {
						  "_dd_line": 9
						},
						"_dd__default": {
						  "_dd_line": 9
						}
					  }
					],
					"_dd_line": 8
				  }
				},
				"perm": [
					{
						"_dd_lines": {
							"_dd__default": {
								"_dd_line": 9
							}
						},
						"group": {
							"_dd_lines": {
								"_dd__default": {
									"_dd_line": 4
								},
								"_dd_name": {
									"_dd_line": 6
								}
							},
							"name": "cx"
						}
					}
				]
			  }, 
			  "_path":"test.yaml"
			}
		  ]
		  `,
			wantErr:           false,
			wantLinesToIgnore: []int{5, 6},
		},
		{
			want:              "{}",
			wantErr:           true,
			wantLinesToIgnore: []int{},
		},
		{
			want: `[
				{
					"_dd_lines": {
						"_dd__default": {
							"_dd_line": 0
						},
						"_dd_resources": {
							"_dd_arr": [
								{
									"_dd__default": {
										"_dd_line": 3
									},
									"_dd_name": {
										"_dd_line": 3
									},
									"_dd_type": {
										"_dd_line": 4
									}
								},
								{
									"_dd__default": {
										"_dd_line": 5
									},
									"_dd_name": {
										"_dd_line": 5
									},
									"_dd_properties": {
										"_dd_line": 7
									},
									"_dd_type": {
										"_dd_line": 6
									}
								}
							],
							"_dd_line": 2
						}
					},
					"resources": [
						{
							"name": "my-vm-access",
							"type": "my-vm-access"
						},
						{
							"name": "my-vm",
							"properties": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 7
									},
									"_dd_serviceAccountId": {
										"_dd_line": 8
									}
								},
								"serviceAccountId": "my-vm-access"
							},
							"type": "vm.jinja"
						}
					], 
					"_path":"test.yaml"
				}
			]`,
			wantErr:           false,
			wantLinesToIgnore: []int(nil),
		},
	}

	ctx := context.Background()
	for idx, tt := range have {
		t.Run(fmt.Sprintf("test_parse_case_%d", idx), func(t *testing.T) {
			_, doc, linesToIgnore, _, err := Parse(ctx, nil, []byte(tt), "test.yaml", true, 15)
			if want[idx].wantErr {
				require.Error(t, err)
			} else {
				require.Equal(t, want[idx].wantLinesToIgnore, linesToIgnore)
				require.NoError(t, err)
				compareJSONLine(t, doc, want[idx].want)
			}
		})
	}
}

func compareJSONLine(t *testing.T, test1 interface{}, test2 string) {
	stringefiedJSON, err := json.Marshal(&test1)
	require.NoError(t, err)
	require.JSONEq(t, test2, string(stringefiedJSON))
}

// Test_Resolve tests the functions [Resolve()] and all the methods called by them
func Test_Resolve(t *testing.T) {
	ctx := context.Background()
	have := `
	martin:
		name: test
	---
	martin2:
		name: test2
	`

	resolved, resolvedFiles := resolve(ctx, nil, []byte(have), "test.yaml", true, 15)
	require.Nil(t, resolved, "a file without references is decoded as is")
	require.Empty(t, resolvedFiles)
}

func TestYaml_processElements(t *testing.T) {
	type args struct {
		elements map[string]interface{}
		filePath string
	}
	tests := []struct {
		name     string
		args     args
		wantCert map[string]interface{}
		wantSwag string
	}{
		{
			name: "test_process_elements",
			args: args{
				elements: map[string]interface{}{
					"swagger_file": "test",
					"certificate":  filepath.Join("..", "..", "..", "test", "fixtures", "test_certificate", "certificate.pem"),
				},
				filePath: filepath.Join("..", "..", "..", "test", "fixtures", "test_certificate", "certificate.pem"),
			},
			wantCert: map[string]interface{}{
				"expiration_date": [3]int{2022, 3, 27},
				"file":            filepath.Join("..", "..", "..", "test", "fixtures", "test_certificate", "certificate.pem"),
				"rsa_key_bytes":   512,
			},
			wantSwag: "test",
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			(&certificateEnricher{ctx: ctx, fsys: vfs.DiskFS{}, filePath: tt.args.filePath}).processElements(tt.args.elements)
			require.Equal(t, tt.wantCert, tt.args.elements["certificate"])
			require.Equal(t, tt.wantSwag, tt.args.elements["swagger_file"])
		})
	}
}

func TestModel_TestYamlParser(t *testing.T) {
	tests := []struct {
		name    string
		sample  string
		want    string
		wantErr bool
	}{
		{
			name: "test_ansible_yaml",
			sample: `
- name: Setup AWS API Gateway setup on AWS and deploy API definition
  community.aws.aws_api_gateway:
	swagger_file: my_api.yml
	stage: production
	cache_enabled: true
	cache_size: '1.6'
	tracing_enabled: true
	endpoint_type: PRIVATE
	state: present
`,
			want:    `[]`,
			wantErr: true,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got, _, _, err := Parse(ctx, nil, []byte(tt.sample), "", true, 15)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				compareJSONLine(t, got, tt.want)
			}
		})
	}
}

func TestParseIgnoresTrailingDocumentSeparator(t *testing.T) {
	content := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: example\n---\n")
	_, docs, _, _, err := Parse(context.Background(), nil, content, "crds.yaml", false, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	require.Equal(t, "ConfigMap", docs[0]["kind"])
}

func TestParseSkipsUnparseableDocumentAndKeepsOthers(t *testing.T) {
	content := []byte("kind: ConfigMap\n---\njust a scalar\n---\nkind: Secret\n")
	_, docs, _, _, err := Parse(context.Background(), nil, content, "mixed.yaml", false, 15)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(docs), 1)
}

// countPaths returns the number of paths from v to a job named "leaf",
// counting each shared map once, and adds every map it meets to seen.
func countPaths(v interface{}, memo map[uintptr]int, seen map[uintptr]bool) int {
	switch typed := v.(type) {
	case map[string]interface{}:
		ptr := reflect.ValueOf(typed).Pointer()
		if n, ok := memo[ptr]; ok {
			return n
		}
		seen[ptr] = true
		n := 0
		if typed["job"] == "leaf" {
			n = 1
		}
		for _, child := range typed {
			n += countPaths(child, memo, seen)
		}
		memo[ptr] = n
		return n
	case []interface{}:
		n := 0
		for _, child := range typed {
			n += countPaths(child, memo, seen)
		}
		return n
	}
	return 0
}

// A template included from several places is inlined at each of them, with
// the content of each file shared by its references: the document stays as
// large as the files, where copying each reference made it grow with the
// number of paths (and the scan ran out of memory at a depth of about 5).
func TestParse_TemplateIncludedManyTimesIsSharedAndComplete(t *testing.T) {
	const fanout, depth = 10, 4
	root, err := test.WriteTemplateChain(t.TempDir(), fanout, depth, "")
	require.NoError(t, err)
	content, err := os.ReadFile(root)
	require.NoError(t, err)

	_, docs, _, resolvedFiles, err := Parse(context.Background(), nil, content, root, true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	require.Len(t, resolvedFiles, depth)

	seen := make(map[uintptr]bool)
	paths := countPaths(map[string]interface{}(docs[0]), make(map[uintptr]int), seen)
	require.Equal(t, 10_000, paths, "every reference is resolved, at every depth")
	// Each file has a job and fanout references, each holding a template map
	// and the shared content it references.
	require.LessOrEqual(t, len(seen), (2*fanout+2)*(depth+1))
}

// Resolution keeps every document of the file and the line of each key in
// it; the content inlined from another file has no line in this one.
func TestParse_ResolvedFileKeepsDocumentsAndLines(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "owner.yaml"), []byte("team: payments\n"), 0o600))
	path := filepath.Join(dir, "app.yaml")
	content := []byte("kind: Deployment\n\n# owner\nowner: owner.yaml\nreplicas: 2\n---\nkind: Service\n")
	require.NoError(t, os.WriteFile(path, content, 0o600))

	_, docs, _, resolvedFiles, err := Parse(context.Background(), nil, content, path, true, 15)
	require.NoError(t, err)
	require.Contains(t, resolvedFiles, "owner.yaml")
	require.Len(t, docs, 2)
	require.Equal(t, "Service", docs[1]["kind"])

	owner, ok := docs[0]["owner"].(map[string]interface{})
	require.True(t, ok, "owner.yaml is inlined")
	require.Equal(t, "payments", owner["team"])

	lines, ok := docs[0]["_dd_lines"].(map[string]*model.LineObject)
	require.True(t, ok)
	require.Equal(t, 4, lines["_dd_owner"].Line)
	require.Equal(t, 5, lines["_dd_replicas"].Line)
	ownerLines, ok := owner["_dd_lines"].(map[string]*model.LineObject)
	require.True(t, ok)
	require.Equal(t, 4, ownerLines["_dd__default"].Line)
	require.Zero(t, ownerLines["_dd_team"].Line)
}
