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
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
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

// TestParser_ParseLineInfoOnly verifies that a line-info reparse skips the
// run-block and expression enrichment while keeping the line markers.
func TestParser_ParseLineInfoOnly(t *testing.T) {
	p := &Parser{}
	content := []byte(`on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.issue.title }}
`)

	_, full, _, _, err := p.Parse(context.Background(), content, "workflow.yml", false, 15)
	require.NoError(t, err)
	fullStep := full[0]["jobs"].(map[string]interface{})["build"].(map[string]interface{})["steps"].([]interface{})[0].(map[string]interface{})
	require.Contains(t, fullStep, "_parsed_run")
	require.Contains(t, fullStep, "_parsed_expressions_run")

	_, lineOnly, _, _, err := p.Parse(parser.WithLineInfoOnly(context.Background()), content, "workflow.yml", false, 15)
	require.NoError(t, err)
	build := lineOnly[0]["jobs"].(map[string]interface{})["build"].(map[string]interface{})
	step := build["steps"].([]interface{})[0].(map[string]interface{})
	require.NotContains(t, step, "_parsed_run")
	require.NotContains(t, step, "_parsed_expressions_run")
	require.Contains(t, build, "_dd_lines")
}

// parsedExpressionRaws returns the raw text of the parsed expressions stored under exprKey in m.
func parsedExpressionRaws(t *testing.T, m map[string]interface{}, exprKey string) []string {
	t.Helper()
	require.Contains(t, m, exprKey)
	parsedExprs, ok := m[exprKey].([]ParsedExpression)
	require.True(t, ok, "%s holds %T", exprKey, m[exprKey])
	raws := make([]string, 0, len(parsedExprs))
	for _, parsed := range parsedExprs {
		require.True(t, parsed.ParseOK, "%s: %q", exprKey, parsed.Raw)
		raws = append(raws, strings.TrimSpace(parsed.Raw))
	}
	return raws
}

func parseWorkflowDocument(t *testing.T, content string) model.Document {
	t.Helper()
	p := &Parser{}
	_, documents, _, _, err := p.Parse(context.Background(), []byte(content), "workflow.yml", false, 15)
	require.NoError(t, err)
	require.Len(t, documents, 1)
	return documents[0]
}

// TestParser_ParsedExpressionsExactAndLegacyKeys verifies that the parsed expressions of
// a hyphenated key are stored under its exact key and under the legacy '-' to '_' alias,
// in workflow, job and step env maps, in `with` and on the job itself.
func TestParser_ParsedExpressionsExactAndLegacyKeys(t *testing.T) {
	doc := parseWorkflowDocument(t, `on: pull_request_target
env:
  WF-TITLE: ${{ github.event.pull_request.title }}
jobs:
  build:
    runs-on: ${{ matrix.os }}
    env:
      JOB-BODY: ${{ github.event.pull_request.body }}
    steps:
      - uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.TOKEN }}
          script: console.log("${{ github.head_ref }}")
      - env:
          PR-TITLE: ${{ github.event.pull_request.title }}
          PLAIN: ${{ github.sha }}
        run: echo "${{ env.PR-TITLE }}"
`)

	workflowEnv := doc["env"].(map[string]interface{})
	require.Equal(t, []string{"github.event.pull_request.title"}, parsedExpressionRaws(t, workflowEnv, "_parsed_expressions_WF-TITLE"))
	require.Equal(t, []string{"github.event.pull_request.title"}, parsedExpressionRaws(t, workflowEnv, "_parsed_expressions_WF_TITLE"))

	job := doc["jobs"].(map[string]interface{})["build"].(map[string]interface{})
	require.Equal(t, []string{"matrix.os"}, parsedExpressionRaws(t, job, "_parsed_expressions_runs-on"))
	require.Equal(t, []string{"matrix.os"}, parsedExpressionRaws(t, job, "_parsed_expressions_runs_on"))

	jobEnv := job["env"].(map[string]interface{})
	require.Equal(t, []string{"github.event.pull_request.body"}, parsedExpressionRaws(t, jobEnv, "_parsed_expressions_JOB-BODY"))
	require.Equal(t, []string{"github.event.pull_request.body"}, parsedExpressionRaws(t, jobEnv, "_parsed_expressions_JOB_BODY"))

	steps := job["steps"].([]interface{})
	with := steps[0].(map[string]interface{})["with"].(map[string]interface{})
	require.Equal(t, []string{"secrets.TOKEN"}, parsedExpressionRaws(t, with, "_parsed_expressions_github-token"))
	require.Equal(t, []string{"secrets.TOKEN"}, parsedExpressionRaws(t, with, "_parsed_expressions_github_token"))
	require.Equal(t, []string{"github.head_ref"}, parsedExpressionRaws(t, with, "_parsed_expressions_script"))

	step := steps[1].(map[string]interface{})
	require.Equal(t, []string{"env.PR-TITLE"}, parsedExpressionRaws(t, step, "_parsed_expressions_run"))
	stepEnv := step["env"].(map[string]interface{})
	require.Equal(t, []string{"github.event.pull_request.title"}, parsedExpressionRaws(t, stepEnv, "_parsed_expressions_PR-TITLE"))
	require.Equal(t, []string{"github.event.pull_request.title"}, parsedExpressionRaws(t, stepEnv, "_parsed_expressions_PR_TITLE"))
	require.Equal(t, []string{"github.sha"}, parsedExpressionRaws(t, stepEnv, "_parsed_expressions_PLAIN"))
	stepEnvKeys := make([]string, 0, len(stepEnv))
	for key := range stepEnv {
		stepEnvKeys = append(stepEnvKeys, key)
	}
	require.ElementsMatch(t, []string{
		"PLAIN", "PR-TITLE", "_dd_lines",
		"_parsed_expressions_PLAIN", "_parsed_expressions_PR-TITLE", "_parsed_expressions_PR_TITLE",
	}, stepEnvKeys)
}

// TestParser_ParsedExpressionsKeyCollisions verifies that colliding legacy aliases are
// resolved the same way on every parse: an exact key always wins, and an alias shared
// by several workflow keys is left out, whether or not those keys have expressions.
func TestParser_ParsedExpressionsKeyCollisions(t *testing.T) {
	content := `on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env:
          A-B: ${{ github.event.pull_request.title }}
          A_B: ${{ github.event.issue.title }}
          C-D: ${{ github.event.comment.body }}
          C_D: literal
          E-F_G: ${{ github.head_ref }}
          E_F-G: ${{ github.base_ref }}
          K-L_M: ${{ github.event.review.body }}
          K_L-M: literal
          _parsed-expressions_X: ${{ github.event.discussion.title }}
          _parsed_expressions_X: ${{ github.sha }}
          _parsed-expressions_Y: ${{ github.event.pages }}
          _parsed_expressions_Y: literal
        run: echo "${{ env.A-B }}"
`

	var first []byte
	for range 50 {
		doc := parseWorkflowDocument(t, content)
		step := doc["jobs"].(map[string]interface{})["build"].(map[string]interface{})["steps"].([]interface{})[0].(map[string]interface{})

		env := step["env"].(map[string]interface{})
		require.Equal(t, []string{"github.event.pull_request.title"}, parsedExpressionRaws(t, env, "_parsed_expressions_A-B"))
		require.Equal(t, []string{"github.event.issue.title"}, parsedExpressionRaws(t, env, "_parsed_expressions_A_B"))
		// C_D has no expression, but its name still owns the alias of C-D.
		require.Equal(t, []string{"github.event.comment.body"}, parsedExpressionRaws(t, env, "_parsed_expressions_C-D"))
		require.NotContains(t, env, "_parsed_expressions_C_D")
		require.Equal(t, []string{"github.head_ref"}, parsedExpressionRaws(t, env, "_parsed_expressions_E-F_G"))
		require.Equal(t, []string{"github.base_ref"}, parsedExpressionRaws(t, env, "_parsed_expressions_E_F-G"))
		require.NotContains(t, env, "_parsed_expressions_E_F_G")
		// K_L-M has no expression, but it shares the alias of K-L_M.
		require.Equal(t, []string{"github.event.review.body"}, parsedExpressionRaws(t, env, "_parsed_expressions_K-L_M"))
		require.NotContains(t, env, "_parsed_expressions_K_L_M")
		// The alias of _parsed-expressions_X is the exact key of _parsed_expressions_X,
		// which wins whatever the order in which the map is iterated.
		require.Equal(t, []string{"github.event.discussion.title"}, parsedExpressionRaws(t, env, "_parsed_expressions__parsed-expressions_X"))
		require.Equal(t, []string{"github.sha"}, parsedExpressionRaws(t, env, "_parsed_expressions__parsed_expressions_X"))
		// _parsed_expressions_Y is not a workflow key, so it does not take the alias of
		// _parsed-expressions_Y.
		require.Equal(t, []string{"github.event.pages"}, parsedExpressionRaws(t, env, "_parsed_expressions__parsed_expressions_Y"))

		encoded, err := json.Marshal(doc)
		require.NoError(t, err)
		if first == nil {
			first = encoded
		}
		require.Equal(t, string(first), string(encoded))
	}
}

// TestParser_ParsedExpressionsOverwriteReservedKeys verifies that a key the workflow
// writes in the "_parsed_expressions_" namespace cannot hide the parsed expressions of
// another value: the exact key and the legacy alias overwrite it.
func TestParser_ParsedExpressionsOverwriteReservedKeys(t *testing.T) {
	stepEnv := func(doc model.Document) map[string]interface{} {
		job := doc["jobs"].(map[string]interface{})["check"].(map[string]interface{})
		return job["steps"].([]interface{})[0].(map[string]interface{})["env"].(map[string]interface{})
	}
	workflow := func(trigger, env, run string) string {
		return "on:\n" + trigger + "jobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n" +
			env + "        run: " + run + "\n"
	}
	compositeAction := func(env, run string) string {
		return "name: action\ndescription: action\ninputs:\n  text:\n    description: text\n" +
			"runs:\n  using: composite\n  steps:\n    - shell: bash\n      env:\n" + env + "      run: " + run + "\n"
	}
	compositeEnv := func(doc model.Document) map[string]interface{} {
		runs := doc["runs"].(map[string]interface{})
		return runs["steps"].([]interface{})[0].(map[string]interface{})["env"].(map[string]interface{})
	}
	pullRequestTarget := "  pull_request_target:\n"
	workflowCall := "  workflow_call:\n    inputs:\n      text:\n        type: string\n        required: true\n"

	tests := []struct {
		name    string
		content string
		env     func(model.Document) map[string]interface{}
		want    map[string][]string
		strings map[string]string
	}{
		{
			name: "step env",
			content: workflow(pullRequestTarget,
				"          TITLE: ${{ github.event.pull_request.title }}\n          _parsed_expressions_TITLE: harmless\n",
				`echo "${{ env.TITLE }}"`),
			env:  stepEnv,
			want: map[string][]string{"_parsed_expressions_TITLE": {"github.event.pull_request.title"}},
		},
		{
			name: "composite action",
			content: compositeAction(
				"        TITLE: ${{ github.event.pull_request.title }}\n        _parsed_expressions_TITLE: harmless\n",
				`echo "${{ env.TITLE }}"`),
			env:  compositeEnv,
			want: map[string][]string{"_parsed_expressions_TITLE": {"github.event.pull_request.title"}},
		},
		{
			name: "composite action writing the environment file",
			content: compositeAction(
				"        TITLE: ${{ inputs.text }}\n        _parsed_expressions_TITLE: harmless\n",
				`echo "VALUE=$TITLE" >> "$GITHUB_ENV"`),
			env:  compositeEnv,
			want: map[string][]string{"_parsed_expressions_TITLE": {"inputs.text"}},
		},
		{
			name: "reusable workflow input",
			content: workflow(workflowCall,
				"          TITLE: ${{ inputs.text }}\n          _parsed_expressions_TITLE: harmless\n",
				`echo "${{ env.TITLE }}"`),
			env:  stepEnv,
			want: map[string][]string{"_parsed_expressions_TITLE": {"inputs.text"}},
		},
		{
			name: "secret",
			content: workflow(pullRequestTarget,
				"          DATA: ${{ secrets.TOKEN }}\n          _parsed_expressions_DATA: harmless\n", `echo "$DATA"`),
			env:  stepEnv,
			want: map[string][]string{"_parsed_expressions_DATA": {"secrets.TOKEN"}},
		},
		{
			name: "all secrets as JSON",
			content: workflow(pullRequestTarget,
				"          DATA: ${{ toJSON(secrets) }}\n          _parsed_expressions_DATA: harmless\n", `echo "$DATA"`),
			env:  stepEnv,
			want: map[string][]string{"_parsed_expressions_DATA": {"toJSON(secrets)"}},
		},
		{
			name: "secret decoded from JSON",
			content: workflow(pullRequestTarget,
				"          DATA: ${{ fromJSON(secrets.CONFIG).token }}\n          _parsed_expressions_DATA: harmless\n", `echo "$DATA"`),
			env:  stepEnv,
			want: map[string][]string{"_parsed_expressions_DATA": {"fromJSON(secrets.CONFIG).token"}},
		},
		{
			name: "chain of reserved keys",
			content: workflow(pullRequestTarget,
				"          TITLE: ${{ github.event.pull_request.title }}\n          _parsed_expressions_TITLE: literal\n"+
					"          _parsed_expressions__parsed_expressions_TITLE: ${{ github.sha }}\n",
				`echo "${{ env.TITLE }}"`),
			env: stepEnv,
			want: map[string][]string{
				"_parsed_expressions_TITLE":                                         {"github.event.pull_request.title"},
				"_parsed_expressions__parsed_expressions__parsed_expressions_TITLE": {"github.sha"},
			},
			// _parsed_expressions_TITLE has no expression, so nothing is stored under its exact key.
			strings: map[string]string{"_parsed_expressions__parsed_expressions_TITLE": "${{ github.sha }}"},
		},
		{
			name: "legacy alias",
			content: workflow(pullRequestTarget,
				"          A-B: ${{ github.event.pull_request.title }}\n          _parsed_expressions_A_B: literal\n",
				`echo "${{ env.A-B }}"`),
			env: stepEnv,
			want: map[string][]string{
				"_parsed_expressions_A-B": {"github.event.pull_request.title"},
				"_parsed_expressions_A_B": {"github.event.pull_request.title"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := tt.env(parseWorkflowDocument(t, tt.content))
			for exprKey, raws := range tt.want {
				require.Equal(t, raws, parsedExpressionRaws(t, env, exprKey), exprKey)
			}
			for key, value := range tt.strings {
				require.Equal(t, value, env[key], key)
			}
		})
	}
}
