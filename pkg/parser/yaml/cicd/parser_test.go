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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/cicd/gitlab"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
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

func TestParser_Parse_EmptyShellDoesNotPanic(t *testing.T) {
	content := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - shell: ""
        run: echo hello
`
	doc := parseWorkflowDocument(t, content)
	jobs := doc["jobs"].(map[string]interface{})
	build := jobs["build"].(map[string]interface{})
	steps := build["steps"].([]interface{})
	step := steps[0].(map[string]interface{})
	parsedRun, ok := step["_parsed_run"].(*ParsedRun)
	require.True(t, ok)
	require.False(t, parsedRun.ParseOK)
	require.Error(t, parsedRun.Error)
}

func TestParser_GitLabCI_AnchorsExtendsReferenceAndScripts(t *testing.T) {
	content := `stages:
  - build
  - deploy

default:
  image: alpine:3.19
  before_script:
    - echo "global setup"

.common_vars: &common_vars
  APP_ENV: staging
  SHARED: "yes"

.shared_cmds: &shared_cmds
  - apk add --no-cache curl

.base:
  image: golang:1.22
  variables:
    <<: *common_vars
    BASE_ONLY: "1"
  before_script:
    - *shared_cmds
    - go version
  script:
    - echo "overridden"

.helper:
  script:
    - curl -fsSL https://example.com/install.sh | sh

build:
  extends: .base
  stage: build
  variables:
    APP_ENV: production
  hooks:
    pre_get_sources_script:
      - git config --global advice.detachedHead false
  script:
    - !reference [.helper, script]
    - go build ./...
  after_script:
    - rm -rf tmp/

remote_ref_job:
  script:
    - !reference [.from_remote_template, script]
    - echo done
`
	p := &Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(content), ".gitlab-ci.yml", true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	doc := docs[0]
	// default.before_script is parsed with the bash parser.
	def := doc["default"].(map[string]interface{})
	defBefore, ok := def["_parsed_before_script"].(*ParsedRun)
	require.True(t, ok)
	require.True(t, defBefore.ParseOK)
	require.Len(t, defBefore.Commands, 1)
	require.Equal(t, "echo", defBefore.Commands[0].Command)

	// build inherits image/variables/before_script via extends, overrides APP_ENV,
	// splices !reference [.helper, script], and flattens *shared_cmds.
	build := doc["build"].(map[string]interface{})
	require.Equal(t, "golang:1.22", build["image"])
	require.Equal(t, ".base", build["extends"])

	vars := build["variables"].(map[string]interface{})
	require.Equal(t, "production", vars["APP_ENV"])
	require.Equal(t, "yes", vars["SHARED"])
	require.Equal(t, "1", vars["BASE_ONLY"])

	require.Equal(t, []interface{}{"apk add --no-cache curl", "go version"}, build["before_script"])
	require.Equal(t, []interface{}{"curl -fsSL https://example.com/install.sh | sh", "go build ./..."}, build["script"])

	parsedScript, ok := build["_parsed_script"].(*ParsedRun)
	require.True(t, ok)
	require.True(t, parsedScript.ParseOK)
	require.Len(t, parsedScript.Commands, 2)
	require.Equal(t, "pipeline", parsedScript.Commands[0].Type)
	require.Equal(t, "go", parsedScript.Commands[1].Command)

	parsedBefore, ok := build["_parsed_before_script"].(*ParsedRun)
	require.True(t, ok)
	require.True(t, parsedBefore.ParseOK)
	require.Len(t, parsedBefore.Commands, 2)
	require.Equal(t, "apk", parsedBefore.Commands[0].Command)
	require.Equal(t, "go", parsedBefore.Commands[1].Command)

	parsedAfter, ok := build["_parsed_after_script"].(*ParsedRun)
	require.True(t, ok)
	require.True(t, parsedAfter.ParseOK)
	require.Len(t, parsedAfter.Commands, 1)
	require.Equal(t, "rm", parsedAfter.Commands[0].Command)

	hooks := build["hooks"].(map[string]interface{})
	parsedHook, ok := hooks["_parsed_pre_get_sources_script"].(*ParsedRun)
	require.True(t, ok)
	require.True(t, parsedHook.ParseOK)
	require.Equal(t, "git", parsedHook.Commands[0].Command)

	// Unresolved !reference is preserved as a structured map and skipped by shell parsing.
	remoteJob := doc["remote_ref_job"].(map[string]interface{})
	remoteScript := remoteJob["script"].([]interface{})
	require.Len(t, remoteScript, 2)
	refMap, ok := remoteScript[0].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, []interface{}{".from_remote_template", "script"}, refMap["!reference"])
	parsedRemote, ok := remoteJob["_parsed_script"].(*ParsedRun)
	require.True(t, ok)
	require.Len(t, parsedRemote.Commands, 1)
	require.Equal(t, "echo", parsedRemote.Commands[0].Command)
}

func TestParser_GitLabCI_LocalIncludesConfinementAndNoGenericInlining(t *testing.T) {
	mem := vfs.NewMemFS(map[string][]byte{
		".gitlab-ci.yml": []byte(`include:
  - local: /ci/templates.yml
    inputs:
      tag: "1.31"
  - local: ../outside.yml
  - remote: https://example.invalid/remote.yml

.extra_vars:
  variables:
    FROM_REF: "yes"
    OVERRIDDEN: "base"

.with_ref_vars:
  variables: !reference [.extra_vars, variables]

deploy:
  extends:
    - .deploy_template
    - .with_ref_vars
  variables:
    OVERRIDDEN: "child"
  rules:
    - changes:
        - config.yml
  script:
    - !reference [.deploy_template, script]
    - ./deploy.sh
`),
		"ci/templates.yml": []byte(`spec:
  inputs:
    tag:
      default: "1.30"
---
.deploy_template:
  image: bitnami/kubectl:$[[ inputs.tag ]]
  variables:
    CLUSTER: prod
  script:
    - kubectl config use-context prod
`),
		"config.yml": []byte("unrelated: true\n"),
	})

	p := &Parser{FS: mem}
	_, docs, _, _, err := p.Parse(context.Background(), mustReadFS(t, mem, ".gitlab-ci.yml"), ".gitlab-ci.yml", true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	doc := docs[0]
	// Included template is NOT dumped as a top-level job in .gitlab-ci.yml.
	require.NotContains(t, doc, ".deploy_template")

	deploy := doc["deploy"].(map[string]interface{})
	require.Equal(t, "bitnami/kubectl:1.31", deploy["image"])
	require.Equal(t, []interface{}{"kubectl config use-context prod", "./deploy.sh"}, deploy["script"])

	deployVars := deploy["variables"].(map[string]interface{})
	require.Equal(t, "prod", deployVars["CLUSTER"])
	require.Equal(t, "yes", deployVars["FROM_REF"])
	require.Equal(t, "child", deployVars["OVERRIDDEN"])

	// Generic file.Resolver must NOT replace "config.yml" inside rules.changes.
	rules := deploy["rules"].([]interface{})
	changes := rules[0].(map[string]interface{})["changes"].([]interface{})
	require.Equal(t, []interface{}{"config.yml"}, changes)

	// Path traversal in local include was refused without touching MemFS.
	require.NotContains(t, mem.MissingFiles(), "../outside.yml")
	require.True(t, p.DirectoryDependent())
	require.True(t, p.SharedNodes())
}

func TestParser_GitLabCI_SpecHeaderCyclesIgnoreAndLineInfoOnly(t *testing.T) {
	content := `spec:
  inputs:
    env:
      default: staging
---
.cyc_a:
  extends: .cyc_b
  script:
    - !reference [.cyc_b, script]
.cyc_b:
  extends: .cyc_a
  script:
    - !reference [.cyc_a, script]

deploy:
  # dd-iac-scan ignore-line
  image: alpine:latest
  variables:
    LITERAL: "${{ not_a_github_expr }}"
  script:
    - echo "$[[ inputs.env ]]"
`
	p := &Parser{}
	_, docs, ignoreLines, _, err := p.Parse(context.Background(), []byte(content), ".gitlab-ci.yml", true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 2)
	require.Contains(t, docs[0], "spec")
	require.Contains(t, ignoreLines, 17)

	deploy := docs[1]["deploy"].(map[string]interface{})
	vars := deploy["variables"].(map[string]interface{})
	// GitLab CI documents must not run GitHub Actions expression parsing.
	require.NotContains(t, vars, "_parsed_expressions_LITERAL")
	// spec.inputs default value is interpolated into $[[ inputs.env ]].
	require.Equal(t, []interface{}{`echo "staging"`}, deploy["script"])
	require.Contains(t, deploy, "_parsed_script")

	// Line-info-only reparse preserves external positions without shell parsing.
	lineOnly, err := p.ParseOutput(parser.WithLineInfoOnly(context.Background()), []byte(content), ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	require.Len(t, lineOnly.Documents, 2)
	lineDeploy := lineOnly.Documents[1]["deploy"].(map[string]interface{})
	require.NotContains(t, lineDeploy, "_parsed_script")
	require.NotContains(t, lineDeploy, "_dd_lines")
	require.Positive(t, lineOnly.Sources[1].LineOverlay.Lookup([]string{"deploy", "script", "0"}))
}

func TestParser_GitHubWorkflowWithLiteralReferencePreservesGitHubParsing(t *testing.T) {
	content := `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # Mentioning !reference in a comment or shell string must not route to GitLab.
      - run: echo "!reference [.setup, script] ${{ github.sha }}"
`

	for _, path := range []string{".github/workflows/ci.yml", ".github/workflows/check.gitlab-ci.yml", ".github/workflows/check.gitlab-ci.yaml"} {
		t.Run(path, func(t *testing.T) {
			_, docs, _, _, err := (&Parser{}).Parse(t.Context(), []byte(content), path, false, 15)
			require.NoError(t, err)
			require.Len(t, docs, 1)
			step := docs[0]["jobs"].(map[string]interface{})["build"].(map[string]interface{})["steps"].([]interface{})[0].(map[string]interface{})
			require.Contains(t, step, "_parsed_run")
			require.Contains(t, step, "_parsed_expressions_run")
		})
	}
}

func TestParser_GitLabCI_LayeredIncludesTypedInputsNestedRefsAndHygiene(t *testing.T) {
	mem := vfs.NewMemFS(map[string][]byte{
		"ci/deploy.gitlab-ci.yml": []byte(`include:
  - local: /ci/shared.yml
  - local: /ci/component.yml
    inputs:
      name: one
      allow_failure: false
      retries: 2
  - local: /ci/component.yml
    inputs:
      name: two
      allow_failure: true
      retries: 4

.base:
  variables:
    ROOT_VAR: "from-root"

.setup:
  variables:
    TOOL_VERSION: "1.2.3"

release:
  extends:
    - .base
    - .from_inc_ref
  variables:
    CHILD_VAR: "from-child"
    PINNED: !reference [.setup, variables, TOOL_VERSION]
  script:
    - !reference [.base, script]
    - echo releasing

job_one:
  extends: .comp-one

job_two:
  extends: .comp-two

version:
  script:
    - echo version

updates:
  script:
    - echo updates
`),
		"ci/shared.yml": []byte(`.shared_vars:
  variables:
    SHARED: "from-shared"

.base:
  # dd-iac-scan ignore-line
  image: alpine:3.19
  variables:
    INC_VAR: "from-include"
  script:
    - echo from-include

.from_inc_ref:
  variables: !reference [.shared_vars, variables]
`),
		"ci/component.yml": []byte(`spec:
  inputs:
    name:
      default: default
    allow_failure:
      default: false
    retries:
      default: 1
---
.comp-$[[ inputs.name ]]:
  allow_failure: $[[ inputs.allow_failure ]]
  retry: $[[ inputs.retries ]]
  script:
    - echo "$[[ inputs.name ]]"
`),
	})

	p := &Parser{FS: mem}
	content := mustReadFS(t, mem, "ci/deploy.gitlab-ci.yml")
	_, docs, ignoreLines, _, err := p.Parse(context.Background(), content, "ci/deploy.gitlab-ci.yml", true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	// Comments inside ci/shared.yml must not leak into child ignore lines.
	require.Empty(t, ignoreLines)

	doc := docs[0]
	// Job named "release" is processed as a full job with layered .base merge,
	// included !reference resolution before extends, and 3-element nested !reference.
	rel := doc["release"].(map[string]interface{})
	require.Equal(t, "alpine:3.19", rel["image"])
	relVars := rel["variables"].(map[string]interface{})
	require.Equal(t, "from-include", relVars["INC_VAR"])
	require.Equal(t, "from-root", relVars["ROOT_VAR"])
	require.Equal(t, "from-shared", relVars["SHARED"])
	require.Equal(t, "from-child", relVars["CHILD_VAR"])
	require.Equal(t, "1.2.3", relVars["PINNED"])
	require.Equal(t, []interface{}{"echo from-include", "echo releasing"}, rel["script"])
	require.Contains(t, rel, "_parsed_script")

	// Repeated includes with distinct inputs both expand and preserve scalar types.
	j1 := doc["job_one"].(map[string]interface{})
	require.Equal(t, false, j1["allow_failure"])
	require.Equal(t, float64(2), j1["retry"])
	require.Equal(t, []interface{}{`echo "one"`}, j1["script"])

	j2 := doc["job_two"].(map[string]interface{})
	require.Equal(t, true, j2["allow_failure"])
	require.Equal(t, float64(4), j2["retry"])
	require.Equal(t, []interface{}{`echo "two"`}, j2["script"])

	// Canonical GitLab CI files with jobs named "version" and "updates" are not mistaken for Dependabot.
	require.Contains(t, doc["version"].(map[string]interface{}), "_parsed_script")
	require.Contains(t, doc["updates"].(map[string]interface{}), "_parsed_script")
	require.Empty(t, mem.MissingFiles())
}

func TestParser_GitLabCI_UncappedChainsAndCancellation(t *testing.T) {
	// Nested config on disk resolves /ci/base.yml against explicit RepoRoot.
	repo := t.TempDir()
	mem := vfs.NewMemFS(map[string][]byte{
		repo + "/ci/deploy.gitlab-ci.yml": []byte("include:\n  - local: /ci/base.yml\ndeploy:\n  extends: .base\n"),
		repo + "/ci/base.yml":             []byte(".base:\n  script:\n    - echo ok\n"),
	})
	p := &Parser{FS: mem, RepoRoot: repo}
	_, docs, _, _, err := p.Parse(context.Background(), mustReadFS(t, mem, repo+"/ci/deploy.gitlab-ci.yml"), repo+"/ci/deploy.gitlab-ci.yml", true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	require.Equal(t, []interface{}{"echo ok"}, docs[0]["deploy"].(map[string]interface{})["script"])

	// Deep include chains (12 levels), many distinct includes (40 files), deep
	// extends chains (15 levels), and deep !reference chains (14 levels) all
	// resolve completely without arbitrary truncation caps.
	chainFiles := map[string][]byte{}
	var rootInc strings.Builder
	rootInc.WriteString("include:\n  - local: inc_00.yml\n")
	for i := range 40 {
		name := fmt.Sprintf("extra_%02d.yml", i)
		fmt.Fprintf(&rootInc, "  - local: %s\n", name)
		chainFiles[name] = []byte(fmt.Sprintf(".extra_%02d:\n  variables:\n    EXTRA_%02d: \"yes\"\n", i, i))
	}
	for i := range 11 {
		chainFiles[fmt.Sprintf("inc_%02d.yml", i)] = []byte(fmt.Sprintf("include:\n  - local: inc_%02d.yml\n", i+1))
	}
	chainFiles["inc_11.yml"] = []byte(".deep_inc:\n  image: alpine:deep\n")
	rootInc.WriteString(".ext0:\n  variables:\n    FROM_EXT0: \"ok\"\n")
	for i := 1; i <= 15; i++ {
		fmt.Fprintf(&rootInc, ".ext%d:\n  extends: .ext%d\n", i, i-1)
	}
	rootInc.WriteString(".ref0:\n  script:\n    - echo deep-ref\n")
	for i := 1; i <= 14; i++ {
		fmt.Fprintf(&rootInc, ".ref%d:\n  script:\n    - !reference [.ref%d, script]\n", i, i-1)
	}
	rootInc.WriteString("final_job:\n  extends:\n    - .deep_inc\n    - .extra_39\n    - .ext15\n  script:\n    - !reference [.ref14, script]\n")
	chainFiles[".gitlab-ci.yml"] = []byte(rootInc.String())

	chainMem := vfs.NewMemFS(chainFiles)
	_, chainDocs, _, _, err := (&Parser{FS: chainMem}).Parse(
		context.Background(), mustReadFS(t, chainMem, ".gitlab-ci.yml"), ".gitlab-ci.yml", true, 15,
	)
	require.NoError(t, err)
	require.Len(t, chainDocs, 1)
	finalJob := chainDocs[0]["final_job"].(map[string]interface{})
	require.Equal(t, "alpine:deep", finalJob["image"])
	finalVars := finalJob["variables"].(map[string]interface{})
	require.Equal(t, "yes", finalVars["EXTRA_39"])
	require.Equal(t, "ok", finalVars["FROM_EXT0"])
	require.Equal(t, []interface{}{"echo deep-ref"}, finalJob["script"])

	// Cyclic alias in a spec.inputs default must not stack-overflow or hang.
	cyclicSpec := "spec:\n  inputs:\n    loop:\n      default: &cyc\n        self: *cyc\n---\njob:\n  variables:\n    V: $[[ inputs.loop ]]\n  script:\n    - echo ok\n"
	_, cycDocs, _, _, err := (&Parser{}).Parse(context.Background(), []byte(cyclicSpec), ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	require.Len(t, cycDocs, 2)

	// Canceled context stops parsing promptly.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, _, err = (&Parser{}).Parse(canceledCtx, []byte("job:\n  script:\n    - echo hi\n"), ".gitlab-ci.yml", false, 15)
	require.ErrorIs(t, err, context.Canceled)
}

func TestParser_GitLabCI_LargeFanoutAliasBombAndDiamondIncludes(t *testing.T) {
	// 300 jobs extending a shared 110-variable template must all inherit without truncation.
	var sb strings.Builder
	sb.WriteString(".tpl:\n  image: alpine:3.19\n  variables:\n")
	for i := range 110 {
		fmt.Fprintf(&sb, "    V%03d: val%03d\n", i, i)
	}
	for i := range 300 {
		fmt.Fprintf(&sb, "job%03d:\n  extends: .tpl\n  script:\n    - echo %d\n", i, i)
	}
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), []byte(sb.String()), ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	for i := range 300 {
		job := docs[0][fmt.Sprintf("job%03d", i)].(map[string]interface{})
		require.Equal(t, "alpine:3.19", job["image"], "job%03d lost inherited image", i)
		vars := job["variables"].(map[string]interface{})
		require.Equal(t, "val109", vars["V109"], "job%03d lost inherited variables", i)
	}

	// 300-document file with 6-level sequence alias bombs + local include stays
	// linear via DAG sharing and UnmarshalSharedYAML without caps.
	singleBomb := `include:
  - local: inc.yml
a0: &a0 ["x", "x", "x", "x", "x", "x"]
a1: &a1 [*a0, *a0, *a0, *a0, *a0, *a0]
a2: &a2 [*a1, *a1, *a1, *a1, *a1, *a1]
a3: &a3 [*a2, *a2, *a2, *a2, *a2, *a2]
a4: &a4 [*a3, *a3, *a3, *a3, *a3, *a3]
a5: &a5 [*a4, *a4, *a4, *a4, *a4, *a4]
job:
  extends: .inc
`
	var multi strings.Builder
	for i := range 300 {
		if i > 0 {
			multi.WriteString("---\n")
		}
		multi.WriteString(singleBomb)
	}
	mem := vfs.NewMemFS(map[string][]byte{
		".gitlab-ci.yml": []byte(multi.String()),
		"inc.yml":        []byte(".inc:\n  script:\n    - echo from-inc\n"),
	})
	_, multiDocs, _, _, err := (&Parser{FS: mem}).Parse(context.Background(), mustReadFS(t, mem, ".gitlab-ci.yml"), ".gitlab-ci.yml", true, 15)
	require.NoError(t, err)
	require.Len(t, multiDocs, 300)
	require.Equal(t, []interface{}{"echo from-inc"}, multiDocs[299]["job"].(map[string]interface{})["script"])

	// 1,000 documents each including a large local file reuse cached raw/parsed
	// layers and no-ref subtrees without re-reading or deep-cloning per doc.
	var bigInc strings.Builder
	bigInc.WriteString(".big_base:\n  image: alpine:3.20\n  variables:\n")
	for i := range 200 {
		fmt.Fprintf(&bigInc, "    K%03d: %s\n", i, strings.Repeat("v", 64))
	}
	var thousand strings.Builder
	for i := range 1000 {
		if i > 0 {
			thousand.WriteString("---\n")
		}
		thousand.WriteString("include:\n  - local: big.yml\njob:\n  script:\n    - echo ok\n")
	}
	repMem := vfs.NewMemFS(map[string][]byte{
		".gitlab-ci.yml": []byte(thousand.String()),
		"big.yml":        []byte(bigInc.String()),
	})
	_, repDocs, _, _, err := (&Parser{FS: repMem}).Parse(context.Background(), mustReadFS(t, repMem, ".gitlab-ci.yml"), ".gitlab-ci.yml", true, 15)
	require.NoError(t, err)
	require.Len(t, repDocs, 1000)

	// Unused included jobs do not get their inheritance expanded. Resolving all
	// 500 heavy jobs here would allocate hundreds of thousands of unused values.
	var unused strings.Builder
	unused.WriteString(".heavy:\n  variables:\n")
	for i := range 1000 {
		fmt.Fprintf(&unused, "    K%d: value\n", i)
	}
	for i := range 500 {
		fmt.Fprintf(&unused, ".unused%d:\n  extends: .heavy\n", i)
	}
	unused.WriteString(".used:\n  script: [echo used]\n")
	lazyMem := vfs.NewMemFS(map[string][]byte{
		".gitlab-ci.yml": []byte("include: [unused.yml]\njob:\n  extends: .used\n"),
		"unused.yml":     []byte(unused.String()),
	})
	_, lazyDocs, _, _, err := (&Parser{FS: lazyMem}).Parse(context.Background(), mustReadFS(t, lazyMem, ".gitlab-ci.yml"), ".gitlab-ci.yml", true, 15)
	require.NoError(t, err)
	require.Len(t, lazyDocs, 1)
	require.Equal(t, []interface{}{"echo used"}, lazyDocs[0]["job"].(map[string]interface{})["script"])
	require.NotContains(t, lazyDocs[0], ".unused0")

	// 20-level diamond include DAG (2^20 paths) collapses to linear unique layers
	// via memoization and right-deduplication while preserving precedence.
	diamondFiles := map[string][]byte{
		".gitlab-ci.yml": []byte("include:\n  - local: d0_a.yml\n  - local: d0_b.yml\njob:\n  extends: .leaf\n"),
	}
	for lvl := range 19 {
		nextA := fmt.Sprintf("d%d_a.yml", lvl+1)
		nextB := fmt.Sprintf("d%d_b.yml", lvl+1)
		body := fmt.Sprintf("include:\n  - local: %s\n  - local: %s\n", nextA, nextB)
		diamondFiles[fmt.Sprintf("d%d_a.yml", lvl)] = []byte(body)
		diamondFiles[fmt.Sprintf("d%d_b.yml", lvl)] = []byte(body)
	}
	diamondFiles["d19_a.yml"] = []byte(".leaf:\n  image: from-a\n  variables:\n    A: \"1\"\n")
	diamondFiles["d19_b.yml"] = []byte(".leaf:\n  image: from-b\n  variables:\n    B: \"2\"\n")
	diamondMem := vfs.NewMemFS(diamondFiles)
	_, diamondDocs, _, _, err := (&Parser{FS: diamondMem}).Parse(
		context.Background(), mustReadFS(t, diamondMem, ".gitlab-ci.yml"), ".gitlab-ci.yml", true, 15,
	)
	require.NoError(t, err)
	require.Len(t, diamondDocs, 1)
	diamondJob := diamondDocs[0]["job"].(map[string]interface{})
	require.Equal(t, "from-b", diamondJob["image"])
	diamondVars := diamondJob["variables"].(map[string]interface{})
	require.Equal(t, "1", diamondVars["A"])
	require.Equal(t, "2", diamondVars["B"])
}

func TestParser_GitLabCI_TransitiveCacheReplayWhitespaceNeedsIgnoreAndSubmodule(t *testing.T) {
	// Transitive include replay [a.yml, b.yml, a.yml] restores a.yml's transitive shared.yml precedence.
	mem := vfs.NewMemFS(map[string][]byte{
		".gitlab-ci.yml": []byte(`include:
  - local: a.yml
  - local: b.yml
  - local: a.yml
job:
  extends: .shared
`),
		"a.yml":      []byte("include:\n  - local: shared.yml\n"),
		"shared.yml": []byte(".shared:\n  image: alpine:from-shared\n  script:\n    - echo shared\n"),
		"b.yml":      []byte(".shared:\n  image: alpine:from-b\n"),
	})
	_, docs, _, _, err := (&Parser{FS: mem}).Parse(context.Background(), mustReadFS(t, mem, ".gitlab-ci.yml"), ".gitlab-ci.yml", true, 15)
	require.NoError(t, err)
	require.Equal(t, "alpine:from-shared", docs[0]["job"].(map[string]interface{})["image"])

	// Preserve literal surrounding whitespace, local ignore-line directives on whole-value inputs,
	// and splice interpolated array inputs into needs lists.
	specPipe := `spec:
  inputs:
    flag:
      default: true
    cmd:
      default: echo hi
    extra_needs:
      default:
        - test
        - lint
---
deploy:
  variables:
    PADDED_BOOL: " $[[ inputs.flag ]] "
  needs:
    - build
    - $[[ inputs.extra_needs ]]
  script:
    # dd-iac-scan ignore-line
    - $[[ inputs.cmd ]]
`
	_, specDocs, ignoreLines, _, err := (&Parser{}).Parse(context.Background(), []byte(specPipe), ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	require.Len(t, specDocs, 2)
	deploy := specDocs[1]["deploy"].(map[string]interface{})
	require.Equal(t, " true ", deploy["variables"].(map[string]interface{})["PADDED_BOOL"])
	require.Equal(t, []interface{}{"build", "test", "lint"}, deploy["needs"])
	require.Contains(t, ignoreLines, 20)

	// Submodule .gitlab-ci.yml on disk resolves includes from the submodule's own .git root.
	parent := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(parent, ".git"), 0o750))
	sub := filepath.Join(parent, "vendor", "sub")
	require.NoError(t, os.MkdirAll(filepath.Join(sub, "ci"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(sub, ".git"), []byte("gitdir: ../../.git/modules/vendor/sub\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "ci", "base.yml"), []byte(".sub:\n  script:\n    - echo from-submodule\n"), 0o600))
	subCI := filepath.Join(sub, ".gitlab-ci.yml")
	subContent := []byte("include:\n  - local: /ci/base.yml\njob:\n  extends: .sub\n")
	require.NoError(t, os.WriteFile(subCI, subContent, 0o600))

	_, subDocs, _, _, err := (&Parser{RepoRoot: parent}).Parse(context.Background(), subContent, subCI, true, 15)
	require.NoError(t, err)
	require.Len(t, subDocs, 1)
	require.Equal(t, []interface{}{"echo from-submodule"}, subDocs[0]["job"].(map[string]interface{})["script"])
}

func TestParser_GitLabCI_AdversarialDAGBombsAndUseSiteLines(t *testing.T) {
	// 1. Shared anchor/include DAGs and accepted repeated script/reference
	// expansion + 30-level doubling sequence in merge key + 30-level
	// doubling sequence in include + repeated flat and adjacent/interleaved
	// nested command groups all resolve safely and accurately.
	var sb strings.Builder
	sb.WriteString("inc_entry: &inc_entry\n  local: leaf.yml\n  inputs:\n    k: v\n")
	sb.WriteString("inc0: &inc0 [*inc_entry, *inc_entry]\n")
	for i := 1; i <= 30; i++ {
		fmt.Fprintf(&sb, "inc%d: &inc%d [*inc%d, *inc%d]\n", i, i, i-1, i-1)
	}
	sb.WriteString("include: *inc30\n")
	sb.WriteString("mbase: &mbase {MKEY: ok}\n")
	sb.WriteString("m0: &m0 [*mbase, *mbase]\n")
	for i := 1; i <= 30; i++ {
		fmt.Fprintf(&sb, "m%d: &m%d [*m%d, *m%d]\n", i, i, i-1, i-1)
	}
	sb.WriteString("s0: &s0 [\"echo a\", \"echo b\"]\n")
	for i := 1; i <= 4; i++ {
		fmt.Fprintf(&sb, "s%d: &s%d [*s%d, *s%d]\n", i, i, i-1, i-1)
	}
	sb.WriteString(".r0:\n  script:\n    - echo ref-leaf\n")
	for i := 1; i <= 4; i++ {
		fmt.Fprintf(&sb, ".r%d:\n  script:\n    - !reference [.r%d, script]\n    - !reference [.r%d, script]\n", i, i-1, i-1)
	}
	sb.WriteString(".check: &check\n  - echo check\n")
	sb.WriteString(".nested_grp: &nested_grp\n  - [\"echo grp1\"]\n  - \"echo grp2\"\n")
	sb.WriteString(".other_grp: &other_grp\n  - \"echo other\"\n")
	sb.WriteString(".stage_defs:\n  stages:\n    - build\n    - test\n")
	sb.WriteString("stages:\n  - !reference [.stage_defs, stages]\n  - deploy\n")
	sb.WriteString("anchor_script_job:\n  extends: .from_leaf\n  variables:\n    <<: *m30\n  script:\n    - *nested_grp\n    - *nested_grp\n    - *other_grp\n    - *nested_grp\n")
	sb.WriteString("expanded_script_job:\n  script: *s4\n")
	sb.WriteString("expanded_ref_job:\n  script:\n    - !reference [.r4, script]\n")
	sb.WriteString("repeat_flat_job:\n  script:\n    - *check\n    - echo mid\n    - *check\n")
	sb.WriteString("repeat_nested_grp_job:\n  script:\n    - *nested_grp\n    - echo middle\n    - *nested_grp\n")

	mem := vfs.NewMemFS(map[string][]byte{
		".gitlab-ci.yml": []byte(sb.String()),
		"leaf.yml":       []byte("spec:\n  inputs:\n    k:\n      default: d\n---\n.from_leaf:\n  image: alpine:$[[ inputs.k ]]\n"),
	})
	_, docs, _, _, err := (&Parser{FS: mem}).Parse(
		context.Background(), mustReadFS(t, mem, ".gitlab-ci.yml"), ".gitlab-ci.yml", true, 15,
	)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	require.Equal(t, []interface{}{"build", "test", "deploy"}, docs[0]["stages"])
	anchorJob := docs[0]["anchor_script_job"].(map[string]interface{})
	require.Equal(t, "alpine:v", anchorJob["image"])
	require.Equal(t, "ok", anchorJob["variables"].(map[string]interface{})["MKEY"])
	require.Equal(t, []interface{}{
		"echo grp1", "echo grp2",
		"echo grp1", "echo grp2",
		"echo other",
		"echo grp1", "echo grp2",
	}, anchorJob["script"])
	require.Contains(t, anchorJob, "_parsed_script")
	// Accepted repeated scripts preserve all occurrences.
	bombJob := docs[0]["expanded_script_job"].(map[string]interface{})
	require.Len(t, bombJob["script"], 32)
	refBombJob := docs[0]["expanded_ref_job"].(map[string]interface{})
	require.Len(t, refBombJob["script"], 16)
	// Flat reusable command anchor still expands at every occurrence.
	flatJob := docs[0]["repeat_flat_job"].(map[string]interface{})
	require.Equal(t, []interface{}{"echo check", "echo mid", "echo check"}, flatJob["script"])
	// Repeated nested command group separated by an intermediate step expands at both sites.
	nestedGrpJob := docs[0]["repeat_nested_grp_job"].(map[string]interface{})
	require.Equal(t, []interface{}{"echo grp1", "echo grp2", "echo middle", "echo grp1", "echo grp2"}, nestedGrpJob["script"])

	// 2. Merging two 10-level 6-way shared mapping DAGs across include and root
	// stays linear via DeepMergeMappings pair memoization.
	makeMapDAG := func(leafKey, leafVal string) string {
		var b strings.Builder
		fmt.Fprintf(&b, "n0: &n0 {%s: %s}\n", leafKey, leafVal)
		for l := 1; l <= 10; l++ {
			fmt.Fprintf(&b, "n%d: &n%d {k0: *n%d, k1: *n%d, k2: *n%d, k3: *n%d, k4: *n%d, k5: *n%d}\n",
				l, l, l-1, l-1, l-1, l-1, l-1, l-1)
		}
		b.WriteString("shared_job:\n  variables: *n10\n  script:\n    - echo ok\n")
		return b.String()
	}
	dagMem := vfs.NewMemFS(map[string][]byte{
		".gitlab-ci.yml": []byte("include:\n  - local: inc.yml\n" + makeMapDAG("ROOT", "yes")),
		"inc.yml":        []byte(makeMapDAG("INC", "yes")),
	})
	_, dagDocs, _, _, err := (&Parser{FS: dagMem}).Parse(
		context.Background(), mustReadFS(t, dagMem, ".gitlab-ci.yml"), ".gitlab-ci.yml", true, 15,
	)
	require.NoError(t, err)
	require.Len(t, dagDocs, 1)

	// 3. Scalar alias use-site line is preserved on the referencing job, not the definition.
	aliasLineYAML := `job_def:
  script:
    - &cmd "echo danger"
job_use:
  _parsed_script: "spoofed"
  script:
    - *cmd
`
	lineDocs, err := (&Parser{}).ParseOutput(context.Background(), []byte(aliasLineYAML), ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	require.Len(t, lineDocs.Documents, 1)
	useJob := lineDocs.Documents[0]["job_use"].(map[string]interface{})
	require.Equal(t, 7, lineDocs.Sources[0].LineOverlay.Lookup([]string{"job_use", "script", "0"}))
	// Source-supplied _parsed_script metadata must be overwritten by real shell parsing.
	parsedUse, ok := useJob["_parsed_script"].(*ParsedRun)
	require.True(t, ok)
	require.True(t, parsedUse.ParseOK)
	require.Len(t, parsedUse.Commands, 1)
	require.Equal(t, "echo", parsedUse.Commands[0].Command)
}

func mustReadFS(t *testing.T, fsys vfs.FS, path string) []byte {
	t.Helper()
	b, err := fsys.ReadFile(path)
	require.NoError(t, err)
	return b
}

// Rejection is atomic across documents and all resource-consuming stages.
func TestParser_GitLabCI_ResourceLimits(t *testing.T) {
	var bomb strings.Builder
	bomb.WriteString("s0: &s0 [echo a, echo b]\n")
	for i := 1; i <= 30; i++ {
		fmt.Fprintf(&bomb, "s%d: &s%d [*s%d, *s%d]\n", i, i, i-1, i-1)
	}
	bomb.WriteString("job:\n  script: *s30\n")
	var fanout strings.Builder
	fanout.WriteString("commands: &commands [")
	for range 5000 {
		fanout.WriteString("echo a,")
	}
	fanout.WriteString("]\n")
	for i := range 250 {
		fmt.Fprintf(&fanout, "job%d:\n  script: [*commands, echo unique%d]\n", i, i)
	}
	var interpolation strings.Builder
	interpolation.WriteString("spec:\n  inputs:\n    value:\n      default: " + strings.Repeat("x", 32*1024) + "\n---\njob:\n  variables:\n")
	for i := range 2200 {
		fmt.Fprintf(&interpolation, "    V%d: prefix-$[[ inputs.value ]]\n", i)
	}
	for name, content := range map[string]string{
		"exponential script":      bomb.String(),
		"later document":          "valid:\n  script: [echo ok]\n---\n" + bomb.String(),
		"aggregate lists":         fanout.String(),
		"aggregate interpolation": interpolation.String(),
		"scalar expansion":        "spec:\n  inputs:\n    v:\n      default: " + strings.Repeat("x", 1024) + "\n---\njob:\n  variables:\n    V: prefix-" + strings.Repeat("$[[ inputs.v ]]", 1100) + "\n",
		"script bytes":            "s: &s " + strings.Repeat("x", 1024) + "\njob:\n  script: [" + strings.Repeat("*s,", 9000) + "]\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, docs, _, _, err := (&Parser{}).Parse(context.Background(), []byte(content), ".gitlab-ci.yml", false, 15)
			require.ErrorIs(t, err, gitlab.ErrLimitExceeded)
			require.Nil(t, docs, "never expose a partial pipeline")
		})
	}
}

func TestParser_GitLabCI_ScriptMetadataHygiene(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		literal      map[string]interface{}
	}{
		{"job", "job: &payload {script: echo job, before_script: echo before, after_script: echo after}\n", map[string]interface{}{"script": "echo job", "before_script": "echo before", "after_script": "echo after"}},
		{"default", "default: &payload {before_script: echo before, after_script: echo after}\njob: {script: echo job}\n", map[string]interface{}{"before_script": "echo before", "after_script": "echo after"}},
		{"hooks", "job:\n  script: echo job\n  hooks: &payload {pre_get_sources_script: echo hook}\n", map[string]interface{}{"pre_get_sources_script": "echo hook"}},
		{"step", "job:\n  run: [&payload {name: inline, script: echo step}]\n", map[string]interface{}{"name": "inline", "script": "echo step"}},
		{"run list", "job:\n  run: &steps [&payload {name: inline, script: echo step}]\nother: {run: *steps}\n", map[string]interface{}{"name": "inline", "script": "echo step"}},
	} {
		t.Run("literal alias/"+tc.name, func(t *testing.T) {
			source := tc.source + "dispatch:\n  trigger:\n    project: downstream\n    inputs: {items: [*payload]}\n"
			out, err := (&Parser{}).ParseOutput(model.WithLazyLineInfo(t.Context()), []byte(source), ".gitlab-ci.yml", false, 15)
			require.NoError(t, err)
			trigger := out.Documents[0]["dispatch"].(map[string]interface{})["trigger"].(map[string]interface{})
			items := trigger["inputs"].(map[string]interface{})["items"]
			require.Equal(t, []interface{}{tc.literal}, items)
			job := out.Documents[0]["job"].(map[string]interface{})
			switch tc.name {
			case "step", "run list":
				require.IsType(t, &ParsedRun{}, job["run"].([]interface{})[0].(map[string]interface{})["_parsed_script"])
			case "hooks":
				require.IsType(t, &ParsedRun{}, job["hooks"].(map[string]interface{})["_parsed_pre_get_sources_script"])
			default:
				require.IsType(t, &ParsedRun{}, job["_parsed_script"])
			}
		})
	}
	for name, raw := range map[string]interface{}{
		"absent": nil, "empty": "", "whitespace": " ", "invalid": true,
		"oversized": strings.Repeat("x", maxJoinedScriptBytes+1),
		"valid":     "echo actual",
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := gitlab.WithLimits(context.Background())
			defer cancel()
			job := map[string]interface{}{"_parsed_script": "spoofed"}
			if raw != nil {
				job["script"] = raw
			}
			newScriptEnricher().parseField(ctx, job, "script")
			if name == "valid" {
				require.IsType(t, &ParsedRun{}, job["_parsed_script"])
			} else {
				require.NotContains(t, job, "_parsed_script")
			}
			if name == "oversized" {
				require.ErrorIs(t, context.Cause(ctx), gitlab.ErrLimitExceeded)
			}
		})
	}
	for _, globals := range []bool{false, true} {
		t.Run(fmt.Sprintf("pipeline/global=%t", globals), func(t *testing.T) {
			source := ".base: {script: [echo job]}\n"
			if globals {
				source += "before_script: [echo setup]\nafter_script: [echo cleanup]\n"
			}
			for _, name := range []string{"_parsed_before_script", "_parsed_after_script", "_dd_lines"} {
				source += name + ": {extends: .base}\n"
			}
			out, err := (&Parser{}).ParseOutput(t.Context(), []byte(source), ".gitlab-ci.yml", false, 15)
			require.NoError(t, err)
			for _, name := range []string{"_parsed_before_script", "_parsed_after_script", "_dd_lines"} {
				job := out.Documents[0][name].(map[string]interface{})
				require.True(t, gitlab.IsExecutableJob(name, job))
				require.IsType(t, &ParsedRun{}, job["_parsed_script"])
			}
			if globals {
				for _, field := range []string{"before_script", "after_script"} {
					parsed := out.Sources[0].GlobalScripts[field].(*ParsedRun)
					require.True(t, parsed.ParseOK)
					require.Len(t, parsed.Commands, 1)
				}
			} else {
				require.Empty(t, out.Sources[0].GlobalScripts)
			}
		})
	}
}

func TestParser_GitLabCI_SharedScriptsScale(t *testing.T) {
	// Reusing a large command group is accepted, with the converted list and
	// shell AST shared. Safety limits must not substitute for these optimizations.
	for _, mode := range []string{"anchor", "extends", "reference", "input", "nested-input", "default"} {
		t.Run(mode, func(t *testing.T) {
			jobs, commands := 100, 5000
			if mode == "extends" || mode == "default" {
				jobs, commands = 1000, 9000
			}
			var source strings.Builder
			if strings.Contains(mode, "input") {
				source.WriteString("spec:\n  inputs:\n    commands:\n      type: array\n      default: &commands [")
			} else if mode == "default" {
				source.WriteString("default:\n  before_script: &commands [")
			} else {
				source.WriteString(".base: &base\n  script: &commands [")
			}
			for range commands {
				source.WriteString("echo a,")
			}
			source.WriteString("]\n")
			if strings.Contains(mode, "input") {
				source.WriteString("---\n")
			}
			for i := range jobs {
				if mode == "input" {
					fmt.Fprintf(&source, "job%d:\n  script: '$[[ inputs.commands ]]'\n", i)
				} else if mode == "nested-input" {
					fmt.Fprintf(&source, "job%d:\n  script: ['$[[ inputs.commands ]]']\n", i)
				} else if mode == "default" {
					fmt.Fprintf(&source, "job%d: {script: echo job}\n", i)
				} else if mode == "extends" {
					fmt.Fprintf(&source, "job%d:\n  extends: .base\n", i)
				} else if mode == "reference" {
					fmt.Fprintf(&source, "job%d:\n  script: !reference [.base, script]\n", i)
				} else {
					fmt.Fprintf(&source, "job%d:\n  script: [*commands]\n", i)
				}
			}
			_, docs, _, _, err := (&Parser{}).Parse(context.Background(), []byte(source.String()), ".gitlab-ci.yml", false, 15)
			require.NoError(t, err)
			pipeline := docs[len(docs)-1]
			first := pipeline["job0"].(map[string]interface{})
			field := "script"
			if mode == "default" {
				field = "before_script"
			}
			for i := range jobs {
				job := pipeline[fmt.Sprintf("job%d", i)].(map[string]interface{})
				require.Len(t, job[field], commands)
				require.Equal(t, reflect.ValueOf(first[field]).Pointer(), reflect.ValueOf(job[field]).Pointer())
				require.Same(t, first["_parsed_"+field], job["_parsed_"+field])
			}
		})
	}
	// A large scalar is shared by template clones. Charging its bytes once per
	// job would reject valid reuse even though no string expansion occurs.
	var large strings.Builder
	value := strings.Repeat("v", 512*1024)
	large.WriteString(".base:\n  variables:\n    LARGE: " + value + "\n  script: [echo ok]\n")
	for i := range 300 {
		fmt.Fprintf(&large, "job%d:\n  extends: .base\n", i)
	}
	_, largeDocs, _, _, err := (&Parser{}).Parse(context.Background(), []byte(large.String()), ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	for i := range 300 {
		job := largeDocs[0][fmt.Sprintf("job%d", i)].(map[string]interface{})
		require.Equal(t, value, job["variables"].(map[string]interface{})["LARGE"])
	}
	// A merged mapping allocates pointer slots, not copies of every shared node.
	var wide strings.Builder
	wide.WriteString(".base:\n  script: [echo ok]\n  variables:\n")
	for i := range 1000 {
		fmt.Fprintf(&wide, "    V%d: value\n", i)
	}
	for i := range 150 {
		fmt.Fprintf(&wide, "job%d: {extends: .base, variables: {LOCAL: value}}\n", i)
	}
	_, wideDocs, _, _, err := (&Parser{}).Parse(t.Context(), []byte(wide.String()), ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	for i := range 150 {
		job := wideDocs[0][fmt.Sprintf("job%d", i)].(map[string]interface{})
		require.Len(t, job["variables"], 1001)
		require.Contains(t, job, "_parsed_script")
	}
}

func BenchmarkParser_GitLabCI_SharedScripts(b *testing.B) {
	for _, jobs := range []int{100, 400} {
		b.Run(fmt.Sprintf("jobs=%d", jobs), func(b *testing.B) {
			var source strings.Builder
			source.WriteString("commands: &commands [echo a, echo b]\n")
			for i := range jobs {
				fmt.Fprintf(&source, "job%d:\n  script: [*commands]\n", i)
			}
			content := []byte(source.String())
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_, docs, _, _, err := (&Parser{}).Parse(context.Background(), content, ".gitlab-ci.yml", false, 15)
				if err != nil || len(docs) != 1 {
					b.Fatalf("incomplete parse: %v", err)
				}
			}
		})
	}
}

func TestParser_GitLabCI_AllocationScaling(t *testing.T) {
	allocations := func(jobs int) float64 {
		var source strings.Builder
		source.WriteString("commands: &commands [echo a, echo b]\n")
		for i := range jobs {
			fmt.Fprintf(&source, "job%d:\n  script: [*commands]\n", i)
		}
		content := []byte(source.String())
		return testing.AllocsPerRun(2, func() {
			_, docs, _, _, err := (&Parser{}).Parse(context.Background(), content, ".gitlab-ci.yml", false, 15)
			require.NoError(t, err)
			require.Len(t, docs, 1)
			require.Len(t, docs[0]["job0"].(map[string]interface{})["script"], 2)
		})
	}
	small, large := allocations(100), allocations(400)
	t.Logf("100 jobs: %.0f allocations; 400 jobs: %.0f allocations; ratio: %.2f", small, large, large/small)
	// Four times the output should grow approximately linearly, with allowance
	// for hash-table growth. Quadratic copying would grow sixteenfold.
	require.Less(t, large, small*6)
}

func TestParser_GitLabCI_EffectiveIncludesAndSources(t *testing.T) {
	for _, pattern := range []string{"ci/*.yml", "./ci/*.yml", "ci/../ci/*.yml", "ci/**/*.yml", "ci/**/**/*.yml", "ci/{a,z}.yml", "ci/{a,z,nested/deploy}.yml", `ci/{a,\{literal\},z}.yml`} {
		t.Run(pattern, func(t *testing.T) {
			files := map[string][]byte{
				".gitlab-ci.yml":       []byte("include:\n  - local: " + pattern + "\n  - local: excluded.yml\n    rules: [{when: never}]\ndefault: {image: alpine}\nvariables: {ROOT: yes}\nbuild: {variables: {OWN: yes}}\n"),
				"ci/a.yml":             []byte("default: {before_script: [echo setup]}\nvariables: {SHARED: included}\n.base: {script: [echo inherited]}\nbuild: {extends: .base}\n"),
				"ci/nested/deploy.yml": []byte("deploy: {script: [echo nested]}\n"),
				"ci/z.yml":             []byte("# original source\n\n_parsed_build:\n  script: [echo included] # dd-iac-scan ignore-line\n"),
				"ci/{literal}.yml":     []byte("escaped: {script: echo escaped}\n"),
				"excluded.yml":         []byte(".base: {script: [echo wrong]}\n"),
			}
			mem := vfs.NewMemFS(files)
			out, err := (&Parser{FS: mem}).ParseOutput(context.Background(), files[".gitlab-ci.yml"], ".gitlab-ci.yml", false, 15)
			require.NoError(t, err)
			require.Len(t, out.Documents, 1, "rules must see the complete effective pipeline")
			root := out.Documents[0]
			require.Equal(t, "alpine", root["default"].(map[string]interface{})["image"])
			require.Equal(t, []interface{}{"echo setup"}, root["default"].(map[string]interface{})["before_script"])
			require.Contains(t, root["default"], "_parsed_before_script")
			require.Equal(t, "included", root["variables"].(map[string]interface{})["SHARED"])
			require.Equal(t, []interface{}{"echo inherited"}, root["build"].(map[string]interface{})["script"])
			require.Equal(t, 4, out.Sources[0].LineOverlay.Lookup([]string{"build", "script", "0"}))
			require.Equal(t, filepath.FromSlash("ci/a.yml"), out.Sources[0].LineOverlay.LookupSource([]string{"build", "script", "0"}).Snapshot.Path)
			require.Contains(t, root["_parsed_build"], "_parsed_script")
			position := out.Sources[0].LineOverlay.LookupSource([]string{"_parsed_build", "script"})
			require.Equal(t, "ci/z.yml", filepath.ToSlash(position.Snapshot.Path))
			require.Equal(t, string(files["ci/z.yml"]), position.Snapshot.Content)
			require.Equal(t, 0, position.DocumentIndex)
			require.Equal(t, strings.Contains(pattern, "**") || strings.Contains(pattern, "nested"), root["deploy"] != nil)
			require.Equal(t, strings.Contains(pattern, "*") || strings.Contains(pattern, "literal"), root["escaped"] != nil)
		})
	}
}

func TestParser_GitLabCI_JobDefaultInheritance(t *testing.T) {
	t.Run("supported default contract", func(t *testing.T) {
		body := "default:\n  after_script: [echo after]\n  artifacts: {paths: [out]}\n  before_script: [echo before]\n  cache: {paths: [cache]}\n  hooks: {pre_get_sources_script: [echo hook]}\n  id_tokens: {TOKEN: {aud: 'https://example.invalid'}}\n  image: alpine\n  interruptible: true\n  retry: 2\n  services: [postgres]\n  tags: [linux]\n  timeout: 5m\n  identity: google_cloud\njob: {script: echo job}\nexplicit: {script: echo explicit, identity: google_cloud}\n"
		out, err := (&Parser{}).ParseOutput(t.Context(), []byte(body), ".gitlab-ci.yml", false, 15)
		require.NoError(t, err)
		root := out.Documents[0]
		job := root["job"].(map[string]interface{})
		defaults := root["default"].(map[string]interface{})
		for _, field := range []string{"after_script", "artifacts", "before_script", "cache", "hooks", "id_tokens", "image", "interruptible", "retry", "services", "tags", "timeout"} {
			require.Equal(t, defaults[field], job[field], field)
		}
		// GitLab's Default::ALLOWED_KEYS excludes identity; it is job-only.
		require.NotContains(t, job, "identity")
		require.Equal(t, "google_cloud", root["explicit"].(map[string]interface{})["identity"])
	})
	for _, mode := range []string{"root", "included", "alias", "legacy", "False", "FALSE", "no", "NO", "off", "OFF"} {
		t.Run(mode, func(t *testing.T) {
			defaults := "default:\n  image: alpine\n  before_script: [echo setup]\n  cache: {paths: [shared]}\n  interruptible: true\n"
			line := 3
			if mode == "alias" {
				defaults = strings.Replace(defaults, "default:", ".defaults: &defaults", 1) + "default: *defaults\n"
				line = 6
			} else if mode == "legacy" {
				defaults = "image: alpine\nbefore_script: [echo setup]\ncache: {paths: [shared]}\n"
				line = 2
			}
			body := ".parent: {image: parent}\n.disabled: {inherit: {default: false}}\njob: {script: echo job}\nparented: {extends: .parent, script: echo parent}\nnone: {inherit: {default: false}, script: echo none}\nselected: {inherit: {default: [image]}, script: echo selected}\nfrom_parent: {extends: .disabled, script: echo disabled}\nown: {cache: {key: own}, before_script: [], image: null, script: echo own}\n"
			body += ".bridge: {trigger: downstream}\nbridge: {trigger: downstream}\ninherited_bridge: {extends: .bridge}\nupstream_status: {needs: {pipeline: group/project}}\n"
			switch mode {
			case "False", "FALSE", "no", "NO", "off", "OFF":
				body = strings.ReplaceAll(body, "default: false", "default: "+mode)
			}
			path := ".gitlab-ci.yml"
			files := map[string][]byte{}
			if mode == "included" {
				files["ci/defaults.yml"] = []byte(defaults)
				body = "include: [ci/defaults.yml]\n" + body
				path = "ci/defaults.yml"
			} else {
				body = defaults + body
			}
			out, err := (&Parser{FS: vfs.NewMemFS(files)}).ParseOutput(t.Context(), []byte(body), ".gitlab-ci.yml", false, 15)
			require.NoError(t, err)
			root := out.Documents[0]
			job := root["job"].(map[string]interface{})
			require.Equal(t, "alpine", job["image"])
			require.Equal(t, []interface{}{"echo setup"}, job["before_script"])
			require.Contains(t, job, "_parsed_before_script")
			position := out.Sources[0].LineOverlay.LookupSource([]string{"job", "before_script", "0"})
			require.Equal(t, path, filepath.ToSlash(position.Snapshot.Path))
			require.Equal(t, line, position.Line)
			require.Equal(t, "parent", root["parented"].(map[string]interface{})["image"])
			for _, name := range []string{"none", "from_parent"} {
				job := root[name].(map[string]interface{})
				require.NotContains(t, job, "image")
				require.NotContains(t, job, "before_script")
			}
			require.Equal(t, "alpine", root["selected"].(map[string]interface{})["image"])
			require.NotContains(t, root["selected"], "before_script")
			require.Equal(t, map[string]interface{}{"key": "own"}, root["own"].(map[string]interface{})["cache"])
			require.Empty(t, root["own"].(map[string]interface{})["before_script"])
			require.Nil(t, root["own"].(map[string]interface{})["image"])
			for _, name := range []string{"bridge", "inherited_bridge", "upstream_status"} {
				job := root[name].(map[string]interface{})
				require.NotContains(t, job, "image", "trigger jobs do not execute runner defaults")
				require.NotContains(t, job, "before_script")
				if mode != "legacy" {
					require.Equal(t, true, job["interruptible"])
				}
			}
		})
	}
}

func TestParser_GitLabCI_ExistenceComparisonSemantics(t *testing.T) {
	for _, tc := range []struct {
		name                                    string
		files                                   int
		rules                                   string
		topLevel, partial, included, incomplete bool
	}{
		{"below", 49999, "[{exists: ['ci/**/*.absent']}]", false, false, false, false},
		{"equal", 50000, "[{exists: ['ci/**/*.absent']}]", false, false, false, false},
		{"above with unrelated paths", 50001, "[{exists: ['ci/**/*.absent']}]", false, false, true, false},
		{"divided equal", 25000, "[{exists: ['ci/**/*.a', 'ci/**/*.b']}]", false, false, false, false},
		{"divided above", 25001, "[{exists: ['ci/**/*.a', 'ci/**/*.b']}]", false, false, true, false},
		{"independent rules", 25001, "[{exists: ['ci/**/*.a']}, {exists: ['ci/**/*.b']}]", false, false, false, false},
		{"suffix optimized", 50001, "[{exists: ['**/*.absent']}]", false, false, false, false},
		{"literal", 50001, "[{exists: ['absent.txt']}]", false, false, false, false},
		{"top level ignores nested count", 50001, "[{exists: ['*.absent']}]", false, false, false, false},
		{"top level equal", 50001, "[{exists: ['*.absent']}]", true, false, false, false},
		{"top level exceeds", 50002, "[{exists: ['*.absent']}]", true, false, true, false},
		{"per-rule cache identity", 25001, "[{exists: ['ci/**/*.a']}, {exists: ['ci/**/*.a', 'ci/**/*.b']}]", false, false, true, false},
		{"known lower bound", 50001, "[{exists: ['ci/**/*.absent']}]", false, true, true, false},
		{"unknown total", 2, "[{exists: ['ci/**/*.absent']}]", false, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "include: [{local: ci/jobs.yml, rules: " + tc.rules + "}]\nroot: {script: echo root}\n"
			files := map[string][]byte{".gitlab-ci.yml": []byte(body), "ci/jobs.yml": []byte("included: {script: echo included}\n")}
			for i := 0; i < tc.files-2; i++ {
				name := fmt.Sprintf("file-%06d.txt", i)
				if !tc.topLevel {
					name = "unrelated/" + name
				}
				files[name] = nil
			}
			fsys := vfs.NewMemFS(files)
			if !tc.partial {
				fsys.MarkDirectoryComplete(".")
			}
			out, err := (&Parser{FS: fsys}).ParseOutput(t.Context(), []byte(body), ".gitlab-ci.yml", false, 15)
			require.NoError(t, err)
			require.Len(t, out.Documents, 1)
			require.Contains(t, out.Documents[0], "root")
			require.Equal(t, tc.included, out.Documents[0]["included"] != nil)
			require.Equal(t, tc.incomplete, out.Sources[0].Incomplete)
			if tc.incomplete {
				require.Contains(t, fsys.MissingFiles(), ".")
			}
		})
	}
}

func TestParser_GitLabCI_ConditionalIncludeSymlinks(t *testing.T) {
	repo := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(repo, "bin"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(repo, "scripts"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "scripts/tool"), []byte("tool"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "jobs.yml"), []byte("included: {script: echo included}\n"), 0o600))
	for _, target := range []string{"../scripts/tool", "../absent", filepath.Join(t.TempDir(), "absent")} {
		link := filepath.Join(repo, "bin/tool")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		for _, pattern := range []string{"bin/tool", "bin/*", "bin/**"} {
			body := []byte("include: [{local: jobs.yml, rules: [{exists: ['" + pattern + "']}]}]\nroot: {script: echo root}\n")
			out, err := (&Parser{RepoRoot: repo}).ParseOutput(t.Context(), body, filepath.Join(repo, ".gitlab-ci.yml"), false, 15)
			require.NoError(t, err)
			require.Contains(t, out.Documents[0], "included")
			require.False(t, out.Sources[0].Incomplete)
		}
		require.NoError(t, os.Remove(link))
	}
	require.NoError(t, os.Symlink("../scripts", filepath.Join(repo, "bin/linked-directory")))
	for _, pattern := range []string{"bin/linked-directory/*", "bin/linked-directory/tool"} {
		body := []byte("include: [{local: jobs.yml, rules: [{exists: ['" + pattern + "']}]}]\nroot: {script: echo root}\n")
		out, err := (&Parser{RepoRoot: repo}).ParseOutput(t.Context(), body, filepath.Join(repo, ".gitlab-ci.yml"), false, 15)
		require.NoError(t, err)
		require.NotContains(t, out.Documents[0], "included", "existence checks do not traverse directory symlinks")
		require.False(t, out.Sources[0].Incomplete)
	}
}

func TestParser_GitLabCI_HeaderAliasesAndTypedDefaults(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  interface{}
	}{
		{"yes", true}, {"Yes", true}, {"YES", true}, {"on", true}, {"On", true}, {"ON", true},
		{"no", false}, {"No", false}, {"NO", false}, {"off", false}, {"Off", false}, {"OFF", false},
		{"'yes'", "yes"}, {"\"off\"", "off"}, {"!!str yes", "yes"}, {"y", "y"}, {"n", "n"},
		{"!!bool yes", true}, {"!!bool 'off'", false}, {"yEs", true}, {"oFf", false},
	} {
		for _, mode := range []string{"root", "included", "default input", "supplied input"} {
			t.Run(mode+"/"+tc.value, func(t *testing.T) {
				body := "job: {script: echo ok, allow_failure: " + tc.value + "}\n"
				files := map[string][]byte{}
				if strings.Contains(mode, "input") {
					kind := "string"
					if _, ok := tc.want.(bool); ok {
						kind = "boolean"
					}
					body = "spec: {inputs: {flag: {type: " + kind + ", default: " + tc.value + "}}}\n---\njob: {script: echo ok, allow_failure: '$[[ inputs.flag ]]'}\n"
				}
				if mode != "root" {
					files["ci/jobs.yml"] = []byte(body)
					body = "include: [ci/jobs.yml]\n"
					if mode == "supplied input" {
						body = "include: [{local: ci/jobs.yml, inputs: {flag: " + tc.value + "}}]\n"
					}
				}
				out, err := (&Parser{FS: vfs.NewMemFS(files)}).ParseOutput(t.Context(), []byte(body), ".gitlab-ci.yml", false, 15)
				require.NoError(t, err)
				require.Len(t, out.Documents, 1)
				require.Equal(t, tc.want, out.Documents[0]["job"].(map[string]interface{})["allow_failure"])
			})
		}
	}
	t.Run("boolean aliases preserve key spelling", func(t *testing.T) {
		body := "yes: &flag yes\njob: {script: echo ok, allow_failure: *flag}\n"
		out, err := (&Parser{}).ParseOutput(t.Context(), []byte(body), ".gitlab-ci.yml", false, 15)
		require.NoError(t, err)
		require.Equal(t, true, out.Documents[0]["yes"])
		require.Equal(t, true, out.Documents[0]["job"].(map[string]interface{})["allow_failure"])
	})
	for _, included := range []bool{false, true} {
		t.Run(fmt.Sprint(included), func(t *testing.T) {
			var header strings.Builder
			header.WriteString("spec:\n  inputs:\n    tag: {default: &tag alpine}\n    copy: {default: *tag}\n    graph:\n      type: array\n      default:\n")
			header.WriteString("        - &n0 [value]\n")
			for i := 1; i <= 6; i++ {
				fmt.Fprintf(&header, "        - &n%d [*n%d, *n%d, *n%d, *n%d, *n%d, *n%d]\n", i, i-1, i-1, i-1, i-1, i-1, i-1)
			}
			header.WriteString("---\njob:\n  image: registry/$[[ inputs.copy ]]\n  variables: {WHOLE: '$[[ inputs.copy ]]'}\n  script: [echo ok]\n")
			header.WriteString("dispatch:\n  trigger:\n    project: example/downstream\n    inputs:\n      args: '$[[ inputs.graph ]]'\n")
			source := []byte(header.String())
			files := map[string][]byte{".gitlab-ci.yml": source}
			if included {
				files["ci/jobs.yml"] = source
				files[".gitlab-ci.yml"] = []byte("include: [ci/jobs.yml]\n")
			}
			out, err := (&Parser{FS: vfs.NewMemFS(files)}).ParseOutput(context.Background(), files[".gitlab-ci.yml"], ".gitlab-ci.yml", false, 15)
			require.NoError(t, err)
			found := false
			for _, doc := range out.Documents {
				if dispatch, ok := doc["dispatch"].(map[string]interface{}); ok {
					trigger := dispatch["trigger"].(map[string]interface{})
					args := trigger["inputs"].(map[string]interface{})["args"].([]interface{})
					require.Len(t, args, 7)
					require.Equal(t, []interface{}{"value"}, args[0])
				}
				if job, ok := doc["job"].(map[string]interface{}); ok {
					found = true
					require.Equal(t, "registry/alpine", job["image"])
					require.Equal(t, "alpine", job["variables"].(map[string]interface{})["WHOLE"])
				}
			}
			require.True(t, found)
		})
	}
}

func TestParser_GitLabCI_ManyDisjointIncludes(t *testing.T) {
	files := make(map[string][]byte)
	var root strings.Builder
	root.WriteString("include:\n")
	for file := range 150 {
		name := fmt.Sprintf("ci/jobs_%03d.yml", file)
		fmt.Fprintf(&root, "  - %s\n", name)
		var jobs strings.Builder
		for job := range 10 {
			fmt.Fprintf(&jobs, "job_%d_%d: {script: [echo ok]}\n", file, job)
		}
		files[name] = []byte(jobs.String())
	}
	files[".gitlab-ci.yml"] = []byte(root.String())
	out, err := (&Parser{FS: vfs.NewMemFS(files)}).ParseOutput(context.Background(), files[".gitlab-ci.yml"], ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	jobs := 0
	for i, doc := range out.Documents {
		for key, value := range doc {
			if gitlab.IsExecutableJob(key, value) {
				jobs++
				require.Contains(t, value, "_parsed_script")
				require.True(t, strings.HasPrefix(filepath.ToSlash(out.Sources[i].LineOverlay.LookupSource([]string{key}).Snapshot.Path), "ci/jobs_"))
			}
		}
	}
	require.Equal(t, 1500, jobs)
}

func TestParser_GitLabCI_CachedInputPositions(t *testing.T) {
	for _, mode := range []string{"reference", "inheritance", "global reference"} {
		t.Run(mode, func(t *testing.T) {
			included := "job:\n  script: echo ok\n  # dd-iac-scan ignore-line\n  variables: !reference [.vars]\n"
			path := []string{"job", "variables"}
			line := 4
			if mode == "inheritance" {
				included = "job:\n  # dd-iac-scan ignore-line\n  extends: .base\n"
				line = 3
			}
			if mode == "global reference" {
				included = "job: {script: echo ok}\n# dd-iac-scan ignore-line\nvariables: !reference [.vars]\n"
				path = []string{"variables"}
				line = 3
			}
			var source strings.Builder
			for i, name := range []string{"FIRST", "SECOND", "FIRST"} {
				if i > 0 {
					source.WriteString("---\n")
				}
				fmt.Fprintf(&source, "include: [ci/jobs.YML]\n.vars: {%s: value}\n.base: {variables: {%s: value}}\n", name, name)
			}
			root := []byte(source.String())
			files := map[string][]byte{".gitlab-ci.yml": root, "ci/jobs.YML": []byte(included)}
			out, err := (&Parser{FS: vfs.NewMemFS(files)}).ParseOutput(model.WithLazyLineInfo(t.Context()), root, ".gitlab-ci.yml", false, 15)
			require.NoError(t, err)
			require.Len(t, out.Documents, 3)
			for i, name := range []string{"FIRST", "SECOND", "FIRST"} {
				position := out.Sources[i].LineOverlay.LookupSource(append(append([]string(nil), path...), name))
				require.Equal(t, "ci/jobs.YML", filepath.ToSlash(position.Snapshot.Path))
				require.Equal(t, line, position.Line)
				require.Contains(t, position.Snapshot.IgnoreLines, line)
			}
		})
	}
	source := []byte("spec:\n  inputs:\n    commands: {type: array, default: [echo a]}\n---\njob:\n  script: '$[[ inputs.commands ]]'\n")
	root := []byte("include: [ci/jobs.yml]\n---\ninclude: [ci/jobs.yml]\n")
	out, err := (&Parser{FS: vfs.NewMemFS(map[string][]byte{".gitlab-ci.yml": root, "ci/jobs.yml": source})}).ParseOutput(context.Background(), root, ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	seen := 0
	for i, doc := range out.Documents {
		if _, ok := doc["job"]; ok {
			seen++
			require.Equal(t, 6, out.Sources[i].LineOverlay.Lookup([]string{"job", "script", "0"}))
		}
	}
	require.Equal(t, 2, seen)
	// Cached included field keys must not retain another document's flattened ranges.
	root = []byte("include: [ci/jobs.yml]\n.commands: {script: [echo a, echo b]}\n---\ninclude: [ci/jobs.yml]\n.commands: {script: [echo a]}\n")
	source = []byte("job:\n  script:\n    - !reference [.commands, script]\n    # dd-iac-scan ignore-line\n    - echo literal\n")
	out, err = (&Parser{FS: vfs.NewMemFS(map[string][]byte{".gitlab-ci.yml": root, "ci/jobs.yml": source})}).ParseOutput(t.Context(), root, ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	require.Len(t, out.Documents, 2)
	for i, length := range []int{3, 2} {
		job := out.Documents[i]["job"].(map[string]interface{})
		require.Len(t, job["script"], length)
		position := out.Sources[i].LineOverlay.LookupSource([]string{"job", "script", fmt.Sprint(length - 1)})
		require.Equal(t, 5, position.Line)
		require.Equal(t, "ci/jobs.yml", filepath.ToSlash(position.Snapshot.Path))
		require.Contains(t, position.Snapshot.IgnoreLines, 5)
	}
}

func TestParser_GitLabCI_IncludeFailures(t *testing.T) {
	for _, scalar := range []string{"null", "~", "\"\"", "!!null ''", "value", "[]", "- invalid"} {
		for _, prefix := range []string{"", "job: {script: echo ok}\n---\n"} {
			t.Run("explicit root/"+prefix+scalar, func(t *testing.T) {
				out, err := (&Parser{}).ParseOutput(t.Context(), []byte(prefix+scalar+"\n"), ".gitlab-ci.yml", false, 15)
				require.ErrorIs(t, err, gitlab.ErrInvalidPipeline)
				require.Empty(t, out.Documents)
			})
		}
	}
	for index, body := range []string{"job: [unterminated", "job: {script: echo ok}\n---\njob: [unterminated", "- invalid\n", "job: {script: echo ok}\n---\n- invalid\n"} {
		t.Run(fmt.Sprintf("entrypoint/%d", index), func(t *testing.T) {
			out, err := (&Parser{}).ParseOutput(t.Context(), []byte(body), ".gitlab-ci.yml", false, 15)
			require.ErrorIs(t, err, gitlab.ErrInvalidPipeline)
			require.Empty(t, out.Documents, "invalid entrypoints cannot publish earlier documents")
		})
	}
	t.Run("special file", func(t *testing.T) {
		mkfifo, err := exec.LookPath("mkfifo")
		if err != nil {
			t.Skip("named pipes unavailable on this platform")
		}
		repo := t.TempDir()
		require.NoError(t, exec.Command(mkfifo, filepath.Join(repo, "jobs.yml")).Run())
		done := make(chan error, 1)
		go func() {
			_, err := (&Parser{FS: vfs.DiskFS{}, RepoRoot: repo}).ParseOutput(t.Context(), []byte("include: [jobs.yml]\nroot: {script: echo ok}\n"), filepath.Join(repo, ".gitlab-ci.yml"), false, 15)
			done <- err
		}()
		select {
		case err := <-done:
			require.ErrorIs(t, err, gitlab.ErrInvalidInclude)
		case <-time.After(2 * time.Second):
			t.Fatal("include compilation blocked opening a named pipe")
		}
	})
	root := []byte("include: [jobs.yml]\nroot: {script: [echo root]}\n")
	for _, mode := range []string{"disk", "memory"} {
		for _, tc := range []struct {
			name string
			body []byte
		}{
			{"missing", nil},
			{"malformed", []byte("job: [unterminated")},
			{"sequence", []byte("- script: echo invalid\n")},
			{"scalar", []byte("invalid configuration\n")},
			{"explicit null", []byte("null\n")},
			{"explicit tilde", []byte("~\n")},
			{"quoted empty string", []byte("\"\"\n")},
			{"later invalid document", []byte("included: {script: echo ok}\n---\n- invalid\n")},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				path, repo := ".gitlab-ci.yml", "."
				mem := vfs.NewMemFS(map[string][]byte{path: root})
				var fsys vfs.FS = mem
				if mode == "disk" {
					repo = t.TempDir()
					path = filepath.Join(repo, ".gitlab-ci.yml")
					require.NoError(t, os.WriteFile(path, root, 0o600))
					if tc.body != nil {
						require.NoError(t, os.WriteFile(filepath.Join(repo, "jobs.yml"), tc.body, 0o600))
					}
					fsys = vfs.DiskFS{}
				} else if tc.body != nil {
					mem = vfs.NewMemFS(map[string][]byte{path: root, "jobs.yml": tc.body})
					fsys = mem
				}
				out, err := (&Parser{FS: fsys, RepoRoot: repo}).ParseOutput(t.Context(), root, path, false, 15)
				if mode == "memory" && tc.body == nil {
					require.NoError(t, err)
					require.Contains(t, mem.MissingFiles(), "jobs.yml")
					require.NotEmpty(t, out.Documents)
				} else {
					require.ErrorIs(t, err, gitlab.ErrInvalidInclude)
					require.Empty(t, out.Documents, "a failed include cannot publish a partial pipeline")
				}
			})
		}
	}
}

func TestParser_GitLabCI_ReferenceSelectorDependencies(t *testing.T) {
	for _, cycle := range []bool{false, true} {
		t.Run(fmt.Sprint(cycle), func(t *testing.T) {
			var input strings.Builder
			input.WriteString(".r0: {cache: {key: {files: [echo resolved]}}}\n")
			if cycle {
				input.Reset()
				input.WriteString(".r0: {cache: !reference [.r12, cache]}\n")
			}
			for i := 1; i <= 12; i++ {
				fmt.Fprintf(&input, ".r%d: {cache: !reference [.r%d, cache]}\n", i, i-1)
			}
			input.WriteString("job: {script: !reference [.r12, cache, key, files]}\n")
			_, docs, _, _, err := (&Parser{}).Parse(context.Background(), []byte(input.String()), ".gitlab-ci.yml", false, 15)
			require.NoError(t, err)
			job := docs[0]["job"].(map[string]interface{})
			if cycle {
				require.NotContains(t, job, "_parsed_script")
			} else {
				require.Equal(t, []interface{}{"echo resolved"}, job["script"])
				require.Contains(t, job, "_parsed_script")
			}
		})
	}
	for _, unrelated := range []string{"", "# empty include\n", "unrelated: {script: echo unrelated}\n"} {
		body := ".base: {variables: {BASE: base}}\n.child: {extends: .base, variables: {CHILD: child}}\njob: {script: echo job, variables: !reference [.child, variables]}\nextended: {extends: .child, script: echo extended}\n"
		files := map[string][]byte{}
		if unrelated != "" {
			body = "include: [ci/unrelated.yml]\n" + body
			files["ci/unrelated.yml"] = []byte(unrelated)
		}
		files[".gitlab-ci.yml"] = []byte(body)
		out, err := (&Parser{FS: vfs.NewMemFS(files)}).ParseOutput(t.Context(), []byte(body), ".gitlab-ci.yml", false, 15)
		require.NoError(t, err)
		job := out.Documents[0]["job"].(map[string]interface{})
		extended := out.Documents[0]["extended"].(map[string]interface{})
		require.Equal(t, map[string]interface{}{"CHILD": "child"}, job["variables"], "unrelated includes cannot change reference evaluation")
		require.Equal(t, map[string]interface{}{"BASE": "base", "CHILD": "child"}, extended["variables"])
	}
}

func TestParser_GitLabCI_HeaderSelectsVariablesBody(t *testing.T) {
	source := []byte("spec:\n  inputs: {value: {default: resolved}}\n---\nvariables: {VALUE: '$[[ inputs.value ]]'}\n")
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), source, ".gitlab/ci/variables.yml", false, 15)
	require.NoError(t, err)
	require.Equal(t, "resolved", docs[1]["variables"].(map[string]interface{})["VALUE"])
	for _, fragment := range []string{
		".base: {image: alpine:latest}\n", "variables: {VALUE: raw}\n", "stages: [test]\n",
		"image: alpine:latest\n", "services: [postgres:16]\n", "default: {}\n", "cache: {paths: [cache]}\n",
		"spec: {inputs: {value: {default: raw}}}\n",
	} {
		t.Run(fragment, func(t *testing.T) {
			require.True(t, gitlab.ShouldParse([]byte(fragment), ".gitlab/ci/fragment.yml"))
			out, err := (&Parser{}).ParseOutput(t.Context(), []byte(fragment), ".gitlab/ci/fragment.yml", false, 15)
			require.NoError(t, err)
			require.Len(t, out.Documents, 1)
			require.Equal(t, model.GitLabDialect, out.Sources[0].Dialect)
		})
	}
}

func TestParser_GitLabCI_GlobIntermediateFiles(t *testing.T) {
	source := []byte("include: [ci/*/*.yml]\n")
	mem := vfs.NewMemFS(map[string][]byte{".gitlab-ci.yml": source, "ci/README.md": []byte("read me"), "ci/jobs/build.yml": []byte("build: {script: [echo ok]}\n")})
	mem.MarkDirectoryComplete("ci")
	out, err := (&Parser{FS: mem}).ParseOutput(context.Background(), source, ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	require.Empty(t, mem.MissingFiles())
	found := false
	for _, doc := range out.Documents {
		if _, ok := doc["build"]; ok {
			found = true
		}
	}
	require.True(t, found)
	for _, operation := range []string{"readdir", "stat", "read"} {
		t.Run(operation, func(t *testing.T) {
			fsys := includeFaultFS{FS: mem, operation: operation}
			out, err := (&Parser{FS: fsys}).ParseOutput(t.Context(), source, ".gitlab-ci.yml", false, 15)
			require.ErrorIs(t, err, gitlab.ErrInvalidInclude)
			require.Empty(t, out.Documents)
		})
	}
	missing := []byte("include: [absent/*.yml]\njob: {script: [echo ok]}\n")
	_, err = (&Parser{FS: mem}).ParseOutput(t.Context(), missing, ".gitlab-ci.yml", false, 15)
	require.NoError(t, err, "an unmatched wildcard remains an ordinary missing IDE request")
}

type includeFaultFS struct {
	vfs.FS
	operation string
}

func (f includeFaultFS) ReadDir(path string) ([]fs.DirEntry, error) {
	if f.operation == "readdir" && filepath.ToSlash(path) == "ci/jobs" {
		return nil, fs.ErrPermission
	}
	return f.FS.ReadDir(path)
}

func (f includeFaultFS) Stat(path string) (fs.FileInfo, error) {
	if f.operation == "stat" && filepath.ToSlash(path) == "ci/jobs/build.yml" {
		return nil, fs.ErrPermission
	}
	return f.FS.Stat(path)
}

func (f includeFaultFS) ReadFile(path string) ([]byte, error) {
	if f.operation == "read" && filepath.ToSlash(path) == "ci/jobs/build.yml" {
		return nil, fs.ErrPermission
	}
	return f.FS.ReadFile(path)
}

func TestParser_GitLabCI_IncludeCompilationBoundaries(t *testing.T) {
	for _, field := range []string{"script", "before_script", "after_script", "needs", "rules", "hooks"} {
		t.Run("cached literal/"+field, func(t *testing.T) {
			definition := "base: {script: echo job, " + field + ": [[one, two]]}\n"
			if field == "script" {
				definition = "base: {script: [[one, two]]}\n"
			}
			selector := field
			if field == "hooks" {
				definition = "base: {script: echo job, hooks: {pre_get_sources_script: [[one, two]]}}\n"
				selector = "hooks, pre_get_sources_script"
			}
			first := "include: [ci/base.yml]\n"
			second := "include: [ci/base.yml]\ndispatch: {trigger: {project: downstream, inputs: {items: !reference [base, " + selector + "]}}}\n"
			for _, source := range []string{second, first + "---\n" + second, second + "---\n" + first + "---\n" + second} {
				files := map[string][]byte{".gitlab-ci.yml": []byte(source), "ci/base.yml": []byte(definition)}
				out, err := (&Parser{FS: vfs.NewMemFS(files)}).ParseOutput(model.WithLazyLineInfo(t.Context()), files[".gitlab-ci.yml"], ".gitlab-ci.yml", false, 15)
				require.NoError(t, err)
				for _, doc := range out.Documents {
					if dispatch, ok := doc["dispatch"].(map[string]interface{}); ok {
						trigger := dispatch["trigger"].(map[string]interface{})
						require.Equal(t, []interface{}{[]interface{}{"one", "two"}}, trigger["inputs"].(map[string]interface{})["items"])
					}
				}
			}
		})
	}
	for _, tc := range []struct {
		name, root string
		files      map[string][]byte
		script     bool
		variables  map[string]interface{}
	}{
		{"whole-value reference", ".base: {script: [echo ok]}\n.parents: [.base]\njob: {extends: !reference [.parents]}\n", nil, true, nil},
		{"alias mapping key", "variables: {JOB_NAME: &name job}\n<<: {job: {script: [echo inherited]}}\n*name: {script: [echo ok]}\n", nil, true, nil},
		{"included reference-selected parents", "include: [ci/templates.yml]\n.parents: [.base]\njob: {extends: !reference [.parents]}\n", map[string][]byte{"ci/templates.yml": []byte(".base: {script: [echo ok]}\n")}, true, nil},
		{"reference-defined included job", "include: [ci/jobs.yml]\n", map[string][]byte{"ci/jobs.yml": []byte(".defs: {job: {script: [echo ok]}}\njob: !reference [.defs, job]\n")}, true, nil},
		{"raw override replaces reference", "include: [ci/jobs.yml]\njob: {variables: {ROOT: root}}\n", map[string][]byte{"ci/jobs.yml": []byte(".vars: {OLD: old}\njob: {script: [echo ok], variables: !reference [.vars]}\n")}, true, map[string]interface{}{"ROOT": "root"}},
		{"nested mapping reset", "include: [ci/first.yml, ci/parent.yml]\n", map[string][]byte{
			"ci/first.yml":  []byte("job: {script: [echo ok], variables: {FIRST: one}}\n"),
			"ci/parent.yml": []byte("include: [ci/null.yml]\njob: {variables: {PARENT: two}}\n"),
			"ci/null.yml":   []byte("job: {variables: null}\n"),
		}, true, map[string]interface{}{"FIRST": "one", "PARENT": "two"}},
		{"root steps", "job: {run: [{name: execute, script: echo ok}]}\n", nil, false, nil},
		{"unresolved extends selector", ".base: {script: [echo inherited]}\njob: {extends: !reference [.base, missing], run: [{name: execute, script: echo ok}]}\n", nil, false, nil},
		{"included steps", "include: [ci/steps.yml]\n", map[string][]byte{"ci/steps.yml": []byte("job: {run: [{name: execute, script: echo ok}]}\n")}, false, nil},
		{"literal expanded match", "include: [ci/*.yml]\n", map[string][]byte{"ci/job[1].yml": []byte("job: {script: [echo ok]}\n")}, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inputs := map[string][]byte{".gitlab-ci.yml": []byte(tc.root)}
			for path, data := range tc.files {
				inputs[path] = data
			}
			fsys := vfs.NewMemFS(inputs)
			fsys.MarkDirectoryComplete("ci")
			out, err := (&Parser{FS: fsys}).ParseOutput(model.WithLazyLineInfo(t.Context()), []byte(tc.root), ".gitlab-ci.yml", false, 15)
			require.NoError(t, err)
			require.Empty(t, fsys.MissingFiles())
			var jobs []map[string]interface{}
			for _, doc := range out.Documents {
				if job, ok := doc["job"].(map[string]interface{}); ok {
					jobs = append(jobs, job)
				}
			}
			require.Len(t, jobs, 1)
			if tc.script {
				require.Equal(t, []interface{}{"echo ok"}, jobs[0]["script"])
				require.Contains(t, jobs[0], "_parsed_script")
			} else {
				require.NotContains(t, jobs[0], "script")
				require.Contains(t, jobs[0], "run")
				step := jobs[0]["run"].([]interface{})[0].(map[string]interface{})
				require.Contains(t, step, "_parsed_script")
			}
			if tc.variables != nil {
				require.Equal(t, tc.variables, jobs[0]["variables"])
			}
		})
	}
}

func TestParser_GitLabCI_SharedRunStepsRetainAllJobs(t *testing.T) {
	var source strings.Builder
	source.WriteString(".steps: &steps\n")
	for index := range 5000 {
		fmt.Fprintf(&source, "  - {name: step%d, script: echo ok}\n", index)
	}
	for index := range 300 {
		fmt.Fprintf(&source, "job%d: {run: *steps}\n", index)
	}
	out, err := (&Parser{}).ParseOutput(model.WithLazyLineInfo(t.Context()), []byte(source.String()), ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	require.Len(t, out.Documents, 1)
	var firstStep map[string]interface{}
	for index := range 300 {
		job := out.Documents[0][fmt.Sprintf("job%d", index)].(map[string]interface{})
		steps := job["run"].([]interface{})
		require.Len(t, steps, 5000)
		step := steps[4999].(map[string]interface{})
		require.Contains(t, step, "_parsed_script")
		if firstStep == nil {
			firstStep = step
		} else {
			require.Same(t, firstStep["_parsed_script"], step["_parsed_script"])
		}
	}
}

// Mapping use sites relocate only the contributed fields. Deep merging must
// retain both the values and the source of earlier included mapping members.
func TestParser_GitLabCI_MappingContributionSources(t *testing.T) {
	for _, nested := range []bool{false, true} {
		for _, use := range []string{"job: *template", "job: {<<: *template}"} {
			t.Run(fmt.Sprintf("layered alias/nested=%t/%s", nested, use), func(t *testing.T) {
				first := ".base: &template\n  script: [echo ok]\n  variables: {KEPT: original}\n# dd-iac-scan ignore-line\n" + use + "\n"
				second := "job:\n  stage: test\n  variables: {ADDED: second}\n"
				third := "job:\n  image: alpine\n  variables: {LAST: third}\n"
				root := []byte("include: [ci/first.yml, ci/second.yml, ci/third.yml]\n")
				files := map[string][]byte{"ci/first.yml": []byte(first), "ci/second.yml": []byte(second), "ci/third.yml": []byte(third)}
				if nested {
					files["ci/parent.yml"] = root
					root = []byte("include: [ci/parent.yml]\n")
				}
				files[".gitlab-ci.yml"] = root
				out, err := (&Parser{FS: vfs.NewMemFS(files)}).ParseOutput(model.WithLazyLineInfo(t.Context()), root, ".gitlab-ci.yml", false, 15)
				require.NoError(t, err)
				for _, tc := range []struct {
					path []string
					file string
					line int
				}{
					{[]string{"job", "script", "0"}, "ci/first.yml", 5},
					{[]string{"job", "variables", "KEPT"}, "ci/first.yml", 5},
					{[]string{"job", "variables", "ADDED"}, "ci/second.yml", 3},
					{[]string{"job", "variables", "LAST"}, "ci/third.yml", 3},
				} {
					position := out.Sources[0].LineOverlay.LookupSource(tc.path)
					require.Equal(t, tc.file, filepath.ToSlash(position.Snapshot.Path))
					require.Equal(t, tc.line, position.Line)
				}
			})
		}
	}
	for _, use := range []string{"  script: *commands", "  script:\n    - *commands", "  <<: *job"} {
		t.Run("nested reference/"+use, func(t *testing.T) {
			source := ".base: {script: [echo ok]}\n.commands: &commands\n  - !reference [.base, script]\n.template: &job {script: *commands}\njob:\n" + use + "\n"
			out, err := (&Parser{}).ParseOutput(model.WithLazyLineInfo(t.Context()), []byte(source), ".gitlab-ci.yml", false, 15)
			require.NoError(t, err)
			position := out.Sources[0].LineOverlay.LookupSource([]string{"job", "script", "0"})
			require.Equal(t, strings.Count(source, "\n"), position.Line)
			require.Equal(t, ".gitlab-ci.yml", position.Snapshot.Path)
			require.Equal(t, []interface{}{"echo ok"}, out.Documents[0]["job"].(map[string]interface{})["script"])
		})
	}
	for _, tc := range []struct{ name, prefix, value string }{
		{"alias", ".local: &local {LOCAL: local}\n", "*local"},
		{"merge", ".local: &local {variables: {LOCAL: local}}\n", "*local"},
		{"reference", ".local: {LOCAL: local}\n", "!reference [.local]"},
		{"alias in stream", "spec:\n  inputs:\n    vars: {type: array, default: []}\n---\n.local: &local {LOCAL: local}\n", "*local"},
	} {
		for _, scope := range []string{"pipeline", "job", "extends"} {
			t.Run(scope+"/"+tc.name, func(t *testing.T) {
				body := "job:\n  variables: " + tc.value + "\n"
				base := "job:\n  script: echo ok\n  variables:\n    BASE: inherited\n"
				path := []string{"job", "variables"}
				baseLine, localOffset := 4, 3
				switch scope {
				case "pipeline":
					body = "variables: " + tc.value + "\n"
					base = "variables:\n  BASE: inherited\n"
					path = []string{"variables"}
					baseLine, localOffset = 2, 2
				case "extends":
					body = "job:\n  extends: .base\n  variables: " + tc.value + "\n"
					base = ".base:\n  script: echo ok\n  variables:\n    BASE: inherited\n"
					localOffset = 4
				}
				if tc.name == "merge" {
					switch scope {
					case "pipeline":
						body = "<<: *local\n"
					case "job":
						body = "job:\n  <<: *local\n"
					case "extends":
						body = "job:\n  extends: .base\n  <<: *local\n"
					}
				}
				root := tc.prefix + "include: [ci/base.yml]\n" + body
				files := map[string][]byte{".gitlab-ci.yml": []byte(root), "ci/base.yml": []byte(base)}
				out, err := (&Parser{FS: vfs.NewMemFS(files)}).ParseOutput(model.WithLazyLineInfo(t.Context()), files[".gitlab-ci.yml"], ".gitlab-ci.yml", false, 15)
				require.NoError(t, err)
				index := len(out.Documents) - 1
				var value interface{} = out.Documents[index]
				for _, part := range path {
					switch parent := value.(type) {
					case model.Document:
						value = parent[part]
					case map[string]interface{}:
						value = parent[part]
					}
				}
				expected := map[string]interface{}{"LOCAL": "local"}
				// Raw include overrides precede reference resolution; inheritance
				// deep-merges the resolved mapping afterwards.
				inherited := tc.name != "reference" || scope == "extends"
				if inherited {
					expected["BASE"] = "inherited"
				}
				require.Equal(t, expected, value)
				positions := out.Sources[index].LineOverlay
				if inherited {
					position := positions.LookupSource(append(append([]string(nil), path...), "BASE"))
					if scope == "extends" {
						// Inherited fields use the extends expression, while
						// the local mapping uses its own expression line.
						require.Equal(t, ".gitlab-ci.yml", position.Snapshot.Path)
						require.Equal(t, strings.Count(tc.prefix, "\n")+3, position.Line)
					} else {
						require.Equal(t, "ci/base.yml", filepath.ToSlash(position.Snapshot.Path))
						require.Equal(t, baseLine, position.Line)
					}
				}
				local := positions.LookupSource(append(append([]string(nil), path...), "LOCAL"))
				require.Equal(t, ".gitlab-ci.yml", local.Snapshot.Path)
				require.Equal(t, strings.Count(tc.prefix, "\n")+localOffset, local.Line)
			})
		}
	}
}
