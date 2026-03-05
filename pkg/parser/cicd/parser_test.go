/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package cicd

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// TestParser_GetKind tests the functions [GetKind()] and all the methods called by them
func TestParser_GetKind(t *testing.T) {
	p := &Parser{}
	require.Equal(t, model.KindYAML, p.GetKind())
}

// TestParser_SupportedExtensions tests the functions [SupportedExtensions()] and all the methods called by them
func TestParser_SupportedExtensions(t *testing.T) {
	p := &Parser{}
	require.Equal(t, []string{".yaml", ".yml"}, p.SupportedExtensions())
}

// TestParser_SupportedExtensions tests the functions [SupportedTypes()] and all the methods called by them
func TestParser_SupportedTypes(t *testing.T) {
	p := &Parser{}
	require.Equal(t, map[string]bool{
		"cicd": true,
	}, p.SupportedTypes())
}

// TestParser_Parse tests the functions [Parse()] and all the methods called by them
func TestParser_Parse(t *testing.T) { //nolint
	p := &Parser{}
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
			  "_kics_lines": {
				"_kics__default": {
				  "_kics_line": 0
				},
				"_kics_martin": {
				  "_kics_line": 3
				}
			  },
			  "martin": {
				"_kics_lines": {
				  "_kics__default": {
					"_kics_line": 3
				  },
				  "_kics_name": {
					"_kics_line": 4
				  }
				},
				"name": "test"
			  }
			},
			{
			  "_kics_lines": {
				"_kics__default": {
				  "_kics_line": 0
				},
				"_kics_martin2": {
				  "_kics_line": 6
				}
			  },
			  "martin2": {
				"_kics_lines": {
				  "_kics__default": {
					"_kics_line": 6
				  },
				  "_kics_name": {
					"_kics_line": 7
				  }
				},
				"name": "test2"
			  }
			}
		  ]
		  `,
			wantErr:           false,
			wantLinesToIgnore: []int{3, 2, 4},
		},
		{
			want: `[
			{
			  "_kics_lines": {
				"_kics__default": {
				  "_kics_arr": [
					{
					  "_kics__default": {
						"_kics_line": 4
					  },
					  "_kics_amazon.aws.aws_s3": {
						"_kics_line": 5
					  },
					  "_kics_name": {
						"_kics_line": 4
					  }
					}
				  ],
				  "_kics_line": 0
				}
			  },
			  "playbooks": [
				{
				  "amazon.aws.aws_s3": {
					"_kics_lines": {
					  "_kics__default": {
						"_kics_line": 5
					  },
					  "_kics_bucket": {
						"_kics_line": 6
					  },
					  "_kics_mode": {
						"_kics_line": 7
					  },
					  "_kics_permission": {
						"_kics_line": 8
					  }
					},
					"bucket": "mybucket",
					"mode": "create",
					"permission": "authenticated-read"
				  },
				  "name": "Create an empty bucket2"
				}
			  ]
			}
		  ]
		  `,
			wantErr:           false,
			wantLinesToIgnore: []int{4, 3, 5, 6, 7, 8},
		},
		{
			want: `[
			{
			  "_kics_lines": {
				"_kics__default": {
				  "_kics_line": 0
				},
				"_kics_test": {
				  "_kics_arr": [
					{
					  "_kics__default": {
						"_kics_line": 4
					  },
					  "_kics_group": {
						"_kics_line": 4
					  }
					}
				  ],
				  "_kics_line": 2
				},
				"_kics_test_2": {
				  "_kics_line": 7
				}
			  },
			  "test": [
				{
				  "group": {
					"_kics_lines": {
					  "_kics__default": {
						"_kics_line": 4
					  },
					  "_kics_name": {
						"_kics_line": 6
					  }
					},
					"name": "cx"
				  }
				}
			  ],
			  "test_2": {
				"_kics_lines": {
				  "_kics__default": {
					"_kics_line": 7
				  },
				  "_kics_perm": {
					"_kics_arr": [
					  {
						"_kics_<<": {
						  "_kics_line": 9
						},
						"_kics__default": {
						  "_kics_line": 9
						}
					  }
					],
					"_kics_line": 8
				  }
				},
				"perm": [
					{
						"_kics_lines": {
							"_kics__default": {
								"_kics_line": 9
							}
						},
						"group": {
							"_kics_lines": {
								"_kics__default": {
									"_kics_line": 4
								},
								"_kics_name": {
									"_kics_line": 6
								}
							},
							"name": "cx"
						}
					}
				]
			  }
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
					"_kics_lines": {
						"_kics__default": {
							"_kics_line": 0
						},
						"_kics_resources": {
							"_kics_arr": [
								{
									"_kics__default": {
										"_kics_line": 3
									},
									"_kics_name": {
										"_kics_line": 3
									},
									"_kics_type": {
										"_kics_line": 4
									}
								},
								{
									"_kics__default": {
										"_kics_line": 5
									},
									"_kics_name": {
										"_kics_line": 5
									},
									"_kics_properties": {
										"_kics_line": 7
									},
									"_kics_type": {
										"_kics_line": 6
									}
								}
							],
							"_kics_line": 2
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
								"_kics_lines": {
									"_kics__default": {
										"_kics_line": 7
									},
									"_kics_serviceAccountId": {
										"_kics_line": 8
									}
								},
								"serviceAccountId": "my-vm-access"
							},
							"type": "vm.jinja"
						}
					]
				}
			]`,
			wantErr:           false,
			wantLinesToIgnore: []int(nil),
		},
	}

	ctx := context.Background()
	for idx, tt := range have {
		t.Run(fmt.Sprintf("test_parse_case_%d", idx), func(t *testing.T) {
			_, doc, linesToIgnore, _, err := p.Parse(ctx, []byte(tt), "test.yaml", true, 15)
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
	parser := &Parser{}

	resolved, _, err := parser.Resolve(ctx, []byte(have), "test.yaml", true, 15)
	require.NoError(t, err)
	require.Equal(t, []byte(have), resolved)
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
			parser := Parser{}
			_, got, _, _, err := parser.Parse(ctx, []byte(tt.sample), "", true, 15)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				compareJSONLine(t, got, tt.want)
			}
		})
	}
}

// Test_GetCommentToken must get the token that represents a comment
func Test_GetCommentToken(t *testing.T) {
	parser := &Parser{}
	require.Equal(t, "#", parser.GetCommentToken())
}

func TestYAML_StringifyContent(t *testing.T) {
	type fields struct {
		parser Parser
	}
	type args struct {
		content []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "test stringify content",
			fields: fields{
				parser: Parser{},
			},
			args: args{
				content: []byte(`
martin:
  name: test
---
martin2:
  name: test2
`),
			},
			want: `
martin:
  name: test
---
martin2:
  name: test2
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fields.parser.StringifyContent(tt.args.content)
			require.Equal(t, tt.wantErr, (err != nil))
			require.Equal(t, tt.want, got)
		})
	}
}

// TestParser_ParseWithShellEnhancement tests the full parsing flow including shell script enhancement
func TestParser_ParseWithShellEnhancement(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
		verify  func(t *testing.T, docs []model.Document)
	}{
		{
			name: "simple workflow with run block",
			yaml: `
jobs:
  test:
    steps:
      - run: echo hello world
`,
			wantErr: false,
			verify: func(t *testing.T, docs []model.Document) {
				require.Len(t, docs, 1)
				jobs := docs[0]["jobs"].(map[string]interface{})
				testJob := jobs["test"].(map[string]interface{})
				steps := testJob["steps"].([]interface{})
				require.Len(t, steps, 1)

				step := steps[0].(map[string]interface{})
				parsed := step["_parsed_run"].(*ParsedRun)

				require.NotNil(t, parsed)
				require.True(t, parsed.ParseOK)
				require.Equal(t, "bash", parsed.Shell)
				require.Len(t, parsed.Commands, 1)
				require.Equal(t, "echo", parsed.Commands[0].Command)
			},
		},
		{
			name: "workflow with variable expansion",
			yaml: `
jobs:
  test:
    steps:
      - run: cargo publish --token $TOKEN
`,
			wantErr: false,
			verify: func(t *testing.T, docs []model.Document) {
				require.Len(t, docs, 1)
				jobs := docs[0]["jobs"].(map[string]interface{})
				testJob := jobs["test"].(map[string]interface{})
				steps := testJob["steps"].([]interface{})
				step := steps[0].(map[string]interface{})
				parsed := step["_parsed_run"].(*ParsedRun)

				require.NotNil(t, parsed)
				require.True(t, parsed.ParseOK)
				require.Len(t, parsed.Commands, 1)
				require.Equal(t, "cargo", parsed.Commands[0].Command)
				require.Len(t, parsed.Commands[0].Args, 3)
				require.Equal(t, "simple_expansion", parsed.Commands[0].Args[2].Type)
				require.Equal(t, "TOKEN", parsed.Commands[0].Args[2].Var)
			},
		},
		{
			name: "workflow with redirect to GITHUB_ENV",
			yaml: `
jobs:
  test:
    steps:
      - run: echo "FOO=$BAR" >> $GITHUB_ENV
`,
			wantErr: false,
			verify: func(t *testing.T, docs []model.Document) {
				require.Len(t, docs, 1)
				jobs := docs[0]["jobs"].(map[string]interface{})
				testJob := jobs["test"].(map[string]interface{})
				steps := testJob["steps"].([]interface{})
				step := steps[0].(map[string]interface{})
				parsed := step["_parsed_run"].(*ParsedRun)

				require.NotNil(t, parsed)
				require.True(t, parsed.ParseOK)
				require.Len(t, parsed.Commands, 1)
				require.Equal(t, "redirected_statement", parsed.Commands[0].Type)
				require.Equal(t, "echo", parsed.Commands[0].Command)
				require.NotNil(t, parsed.Commands[0].Redirect)
				require.Equal(t, ">>", parsed.Commands[0].Redirect.Operator)
				require.Equal(t, "GITHUB_ENV", parsed.Commands[0].Redirect.Target.Var)
			},
		},
		{
			name: "workflow with custom shell",
			yaml: `
jobs:
  test:
    steps:
      - run: echo test
        shell: zsh
`,
			wantErr: false,
			verify: func(t *testing.T, docs []model.Document) {
				require.Len(t, docs, 1)
				jobs := docs[0]["jobs"].(map[string]interface{})
				testJob := jobs["test"].(map[string]interface{})
				steps := testJob["steps"].([]interface{})
				step := steps[0].(map[string]interface{})
				parsed := step["_parsed_run"].(*ParsedRun)

				require.NotNil(t, parsed)
				require.True(t, parsed.ParseOK)
				require.Equal(t, "zsh", parsed.Shell)
			},
		},
		{
			name: "workflow with pipeline",
			yaml: `
jobs:
  test:
    steps:
      - run: cat file.txt | grep pattern
`,
			wantErr: false,
			verify: func(t *testing.T, docs []model.Document) {
				require.Len(t, docs, 1)
				jobs := docs[0]["jobs"].(map[string]interface{})
				testJob := jobs["test"].(map[string]interface{})
				steps := testJob["steps"].([]interface{})
				step := steps[0].(map[string]interface{})
				parsed := step["_parsed_run"].(*ParsedRun)

				require.NotNil(t, parsed)
				require.True(t, parsed.ParseOK)
				require.Len(t, parsed.Commands, 1)
				require.Equal(t, "pipeline", parsed.Commands[0].Type)
				require.Len(t, parsed.Commands[0].Pipeline, 2)
				require.Equal(t, "cat", parsed.Commands[0].Pipeline[0].Command)
				require.Equal(t, "grep", parsed.Commands[0].Pipeline[1].Command)
			},
		},
		{
			name: "workflow with multiple steps",
			yaml: `
jobs:
  test:
    steps:
      - run: echo "Building..."
      - run: npm install
      - run: npm test
`,
			wantErr: false,
			verify: func(t *testing.T, docs []model.Document) {
				require.Len(t, docs, 1)
				jobs := docs[0]["jobs"].(map[string]interface{})
				testJob := jobs["test"].(map[string]interface{})
				steps := testJob["steps"].([]interface{})
				require.Len(t, steps, 3)

				// Verify each step has parsed run
				for i, s := range steps {
					step := s.(map[string]interface{})
					parsed := step["_parsed_run"].(*ParsedRun)
					require.NotNil(t, parsed, "step %d should have _parsed_run", i)
					require.True(t, parsed.ParseOK, "step %d parsing should succeed", i)
				}
			},
		},
		{
			name: "workflow without run blocks",
			yaml: `
jobs:
  test:
    steps:
      - uses: actions/checkout@v2
`,
			wantErr: false,
			verify: func(t *testing.T, docs []model.Document) {
				require.Len(t, docs, 1)
				jobs := docs[0]["jobs"].(map[string]interface{})
				testJob := jobs["test"].(map[string]interface{})
				steps := testJob["steps"].([]interface{})
				require.Len(t, steps, 1)

				step := steps[0].(map[string]interface{})
				// Should not have _parsed_run since there's no run block
				_, hasRun := step["_parsed_run"]
				require.False(t, hasRun)
			},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := &Parser{}
			_, docs, _, _, err := parser.Parse(ctx, []byte(tt.yaml), "test.yaml", true, 15)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				tt.verify(t, docs)
			}
		})
	}
}
