/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package converter

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// TestLabelsWithNestedBlock tests the functions [DefaultConverted] and all the methods called by them (test with nested block)
func TestLabelsWithNestedBlock(t *testing.T) {
	input := `
block "label_one" "label_two" {
	nested_block { }
}`

	expected := `{
	"block": {
		"label_one": {
			"label_two": {
				"_dd_lines": {
					"_dd__default": {
						"_dd_line": 2
					},
					"_dd_nested_block": {
						"_dd_line": 3
					}
				},
				"nested_block": [{
					"_dd_lines": {
						"_dd__default": {
							"_dd_line": 3
						}
					}
				}]
			}
		}
	},
	"_dd_lines": {
		"_dd__default": {
			"_dd_line": 0
		},
		"_dd_block": {
			"_dd_line": 2
		}
	}
}`

	ctx := context.Background()
	file, _ := hclsyntax.ParseConfig([]byte(input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})

	body, err := DefaultConverted(ctx, file, VariableMap{})
	require.NoError(t, err)
	compareJSONLine(t, body, expected)
}

func TestArrayBlock(t *testing.T) {
	input := `
block "label_one" "label_two" {
	default = [
      {
        id = "name1"
        attribute = "a"
      },
      {
        id = "name2"
        attribute = "a,b"
      },
      {
        id = "name3"
        attribute = "d"
      }
  ]
}`

	expected := `{
		"_dd_lines": {
			"_dd__default": {
				"_dd_line": 0
			},
			"_dd_block": {
				"_dd_line": 2
			}
		},
		"block": {
			"label_one": {
				"label_two": {
					"_dd_lines": {
						"_dd__default": {
							"_dd_line": 2
						},
						"_dd_default": {
							"_dd_arr": [
								{
									"_dd__default": {
										"_dd_line": 5
									},
									"_dd_attribute": {
										"_dd_line": 6
									},
									"_dd_id": {
										"_dd_line": 5
									}
								},
								{
									"_dd__default": {
										"_dd_line": 9
									},
									"_dd_attribute": {
										"_dd_line": 10
									},
									"_dd_id": {
										"_dd_line": 9
									}
								},
								{
									"_dd__default": {
										"_dd_line": 13
									},
									"_dd_attribute": {
										"_dd_line": 14
									},
									"_dd_id": {
										"_dd_line": 13
									}
								}
							],
							"_dd_line": 3
						}
					},
					"default": [
						{
							"attribute": "a",
							"id": "name1"
						},
						{
							"attribute": "a,b",
							"id": "name2"
						},
						{
							"attribute": "d",
							"id": "name3"
						}
					]
				}
			}
		}
	}`

	ctx := context.Background()
	file, _ := hclsyntax.ParseConfig([]byte(input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})

	body, err := DefaultConverted(ctx, file, VariableMap{})
	require.NoError(t, err)
	compareJSONLine(t, body, expected)
}

func compareJSONLine(t *testing.T, test1 interface{}, test2 string) {
	stringefiedJSON, err := json.Marshal(&test1)
	require.NoError(t, err)
	require.JSONEq(t, test2, string(stringefiedJSON))
}

// TestLabelsWithNestedBlock tests the functions [DefaultConverted] and all the methods called by them (test with single block)
func TestSingleBlock(t *testing.T) {
	input := `
block "label_one" {
	attribute = "value"
}
`

	expected := `{
		"block": {
			"label_one": {
				"attribute": "value",
				"_dd_lines": {
					"_dd__default": {
						"_dd_line": 2
					},
					"_dd_attribute": {
						"_dd_line": 3
					}
				}
			}
		},
		"_dd_lines": {
			"_dd__default": {
				"_dd_line": 0
			},
			"_dd_block": {
				"_dd_line": 2
			}
		}
	}`

	ctx := context.Background()
	file, _ := hclsyntax.ParseConfig([]byte(input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})

	body, err := DefaultConverted(ctx, file, VariableMap{})
	require.NoError(t, err)
	compareJSONLine(t, body, expected)
}

// TestMultipleBlocks tests the functions [DefaultConverted] and all the methods called by them (test with multiple blocks)
func TestMultipleBlocks(t *testing.T) {
	input := `
block "label_one" {
	attribute = "value"
}
block "label_one" {
	attribute = "value_two"
}
`

	expected := `{
		"block": {
			"label_one": [
				{
					"_dd_lines": {
						"_dd__default": {
							"_dd_line": 2
						},
						"_dd_attribute": {
							"_dd_line": 3
						}
					},
					"attribute": "value"
				},
				{
					"attribute": "value_two",
					"_dd_lines": {
						"_dd__default": {
							"_dd_line": 5
						},
						"_dd_attribute": {
							"_dd_line": 6
						}
					}
				}
			]
		},
		"_dd_lines": {
			"_dd__default": {
				"_dd_line": 0
			},
			"_dd_block": {
				"_dd_line": 5
			}
		}
	}`

	ctx := context.Background()
	file, _ := hclsyntax.ParseConfig([]byte(input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})

	body, err := DefaultConverted(ctx, file, VariableMap{})
	require.NoError(t, err)
	compareJSONLine(t, body, expected)
}

// TestInputVariables tests if it is replacing variables
func TestInputVariables(t *testing.T) {
	input := `
block "label_one" {
	attribute = "${var.test}"
	attribute1 = var.test
	attribute2 = "${var.test}-concat"
}
`

	expected := map[string]string{
		"attribute":  "my-test",
		"attribute1": "my-test",
		"attribute2": "my-test-concat",
	}

	ctx := context.Background()
	file, _ := hclsyntax.ParseConfig([]byte(input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})

	body, err := DefaultConverted(ctx, file, VariableMap{
		"var": cty.ObjectVal(map[string]cty.Value{
			"test": cty.StringVal("my-test"),
		}),
	})
	if err != nil {
		t.Fatal("parse bytes:", err)
	}
	for key, value := range expected {
		t.Run(fmt.Sprintf("body['block']['label_one'][%s] should be equal to %s", key, value), func(t *testing.T) {
			gotValue := ""
			if token, ok := body["block"].(model.Document)["label_one"].(model.Document)[key].(ctyjson.SimpleJSONValue); ok {
				gotValue = token.Value.AsString()
			} else {
				gotValue = body["block"].(model.Document)["label_one"].(model.Document)[key].(string)
			}

			require.Equal(t, value, gotValue)
		})
	}
}

func TestUnknownValuesRemainSerializable(t *testing.T) {
	input := `
block "test" {
	conditional = var.enabled ? "enabled" : "disabled"
	function    = upper(var.name)
	template    = "prefix-${var.name}"
}
`
	file, diags := hclsyntax.ParseConfig([]byte(input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), "parse error: %v", diags)

	body, err := DefaultConverted(context.Background(), file, VariableMap{
		"var": cty.ObjectVal(map[string]cty.Value{
			"enabled": cty.UnknownVal(cty.Bool),
			"name":    cty.UnknownVal(cty.String),
		}),
	})
	require.NoError(t, err)
	require.NotPanics(t, func() {
		_, err = json.Marshal(body)
	})
	require.NoError(t, err)

	block := body["block"].(model.Document)["test"].(model.Document)
	require.Equal(t, `${var.enabled ? "enabled" : "disabled"}`, block["conditional"])
	require.Equal(t, "${upper(var.name)}", block["function"])
	require.Equal(t, "prefix-${var.name}", block["template"])
}

func TestRelativeTraversalExpr(t *testing.T) {
	t.Run("jsondecode_with_traversal_resolves", func(t *testing.T) {
		input := `
block "test" {
  host = jsondecode(var.json_data).host
}
`
		ctx := context.Background()
		file, diags := hclsyntax.ParseConfig([]byte(input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})
		require.False(t, diags.HasErrors(), "parse error: %v", diags)

		body, err := DefaultConverted(ctx, file, VariableMap{
			"var": cty.ObjectVal(map[string]cty.Value{
				"json_data": cty.StringVal(`{"host":"db.example.com"}`),
			}),
		})
		require.NoError(t, err)

		blockDoc := body["block"].(model.Document)["test"].(model.Document)
		gotValue := ""
		if token, ok := blockDoc["host"].(ctyjson.SimpleJSONValue); ok {
			gotValue = token.Value.AsString()
		} else if s, ok := blockDoc["host"].(string); ok {
			gotValue = s
		}
		require.Equal(t, "db.example.com", gotValue)
	})

	t.Run("relative_traversal_without_vars_wraps_expression", func(t *testing.T) {
		input := `
block "test" {
  host = jsondecode(var.json_data).host
}
`
		ctx := context.Background()
		file, diags := hclsyntax.ParseConfig([]byte(input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})
		require.False(t, diags.HasErrors(), "parse error: %v", diags)

		body, err := DefaultConverted(ctx, file, VariableMap{})
		require.NoError(t, err)

		blockDoc := body["block"].(model.Document)["test"].(model.Document)
		gotValue := fmt.Sprintf("%v", blockDoc["host"])
		// Without variables, the expression can't be fully evaluated and gets wrapped
		require.Contains(t, gotValue, "jsondecode")
	})

	t.Run("relative_traversal_in_template", func(t *testing.T) {
		input := `
block "test" {
  host = "prefix-${jsondecode(var.json_data).host}"
}
`
		ctx := context.Background()
		file, diags := hclsyntax.ParseConfig([]byte(input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})
		require.False(t, diags.HasErrors(), "parse error: %v", diags)

		body, err := DefaultConverted(ctx, file, VariableMap{
			"var": cty.ObjectVal(map[string]cty.Value{
				"json_data": cty.StringVal(`{"host":"db.example.com"}`),
			}),
		})
		require.NoError(t, err)

		blockDoc := body["block"].(model.Document)["test"].(model.Document)
		gotValue := ""
		if token, ok := blockDoc["host"].(ctyjson.SimpleJSONValue); ok {
			gotValue = token.Value.AsString()
		} else if s, ok := blockDoc["host"].(string); ok {
			gotValue = s
		}
		require.Equal(t, "prefix-db.example.com", gotValue)
	})
}

func TestFunctionCallExprInStringPart(t *testing.T) {
	t.Run("function_call_in_template_resolves", func(t *testing.T) {
		input := `
block "test" {
  name = "prefix-${upper("hello")}"
}
`
		ctx := context.Background()
		file, diags := hclsyntax.ParseConfig([]byte(input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})
		require.False(t, diags.HasErrors(), "parse error: %v", diags)

		body, err := DefaultConverted(ctx, file, VariableMap{})
		require.NoError(t, err)

		blockDoc := body["block"].(model.Document)["test"].(model.Document)
		gotValue := ""
		if token, ok := blockDoc["name"].(ctyjson.SimpleJSONValue); ok {
			gotValue = token.Value.AsString()
		} else if s, ok := blockDoc["name"].(string); ok {
			gotValue = s
		}
		require.Equal(t, "prefix-HELLO", gotValue)
	})

	t.Run("function_call_in_template_with_vars", func(t *testing.T) {
		input := `
block "test" {
  name = "prefix-${upper(var.env)}"
}
`
		ctx := context.Background()
		file, diags := hclsyntax.ParseConfig([]byte(input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})
		require.False(t, diags.HasErrors(), "parse error: %v", diags)

		body, err := DefaultConverted(ctx, file, VariableMap{
			"var": cty.ObjectVal(map[string]cty.Value{
				"env": cty.StringVal("production"),
			}),
		})
		require.NoError(t, err)

		blockDoc := body["block"].(model.Document)["test"].(model.Document)
		gotValue := ""
		if token, ok := blockDoc["name"].(ctyjson.SimpleJSONValue); ok {
			gotValue = token.Value.AsString()
		} else if s, ok := blockDoc["name"].(string); ok {
			gotValue = s
		}
		require.Equal(t, "prefix-PRODUCTION", gotValue)
	})

	t.Run("function_call_in_template_without_vars_wraps", func(t *testing.T) {
		input := `
block "test" {
  name = "prefix-${upper(var.env)}"
}
`
		ctx := context.Background()
		file, diags := hclsyntax.ParseConfig([]byte(input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})
		require.False(t, diags.HasErrors(), "parse error: %v", diags)

		body, err := DefaultConverted(ctx, file, VariableMap{})
		require.NoError(t, err)

		blockDoc := body["block"].(model.Document)["test"].(model.Document)
		gotValue := fmt.Sprintf("%v", blockDoc["name"])
		require.Contains(t, gotValue, "upper")
	})

	t.Run("function_call_returning_non_string_interpolates", func(t *testing.T) {
		input := `
block "test" {
  name = "prefix-${length("hello")}"
}
`
		ctx := context.Background()
		file, diags := hclsyntax.ParseConfig([]byte(input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})
		require.False(t, diags.HasErrors(), "parse error: %v", diags)

		body, err := DefaultConverted(ctx, file, VariableMap{})
		require.NoError(t, err)

		blockDoc := body["block"].(model.Document)["test"].(model.Document)
		require.Equal(t, "prefix-5", blockDoc["name"])
	})
}

func TestConvertRendersUnresolved(t *testing.T) { //nolint
	type funcTest struct {
		name    string
		input   string
		want    string
		wantErr bool
	}
	tests := []funcTest{
		{
			name: "should evaluate without problems (1)",
			input: `
block "label_one" {
	policy = jsonencode({
    	Id      = "id"
	})
	some_number = max(max(1,3),2)
}
`,
			want: `{
				"_dd_lines": {
				  "_dd__default": {
					"_dd_line": 0
				  },
				  "_dd_block": {
					"_dd_line": 2
				  }
				},
				"block": {
				  "label_one": {
					"_dd_lines": {
					  "_dd__default": {
						"_dd_line": 2
					  },
					  "_dd_policy": {
						"_dd_line": 3
					  },
					  "_dd_some_number": {
						"_dd_line": 6
					  }
					},
					"policy": "{\"Id\":\"id\"}",
					"some_number": 3
				  }
				}
			  }
			  `,
			wantErr: false,
		},
		{
			name: "should render unresolved references inside jsonencode",
			input: `
block "label_one" {
	policy = jsonencode({
    	Id      = aws.meuId
	})
	some_number = max(max(1,3),2)
}
`,
			want: `{
				"_dd_lines": {
				  "_dd__default": {
					"_dd_line": 0
				  },
				  "_dd_block": {
					"_dd_line": 2
				  }
				},
				"block": {
				  "label_one": {
					"_dd_lines": {
					  "_dd__default": {
						"_dd_line": 2
					  },
					  "_dd_policy": {
						"_dd_line": 3
					  },
					  "_dd_some_number": {
						"_dd_line": 6
					  }
					},
					"policy": "{\"Id\":\"${aws.meuId}\"}",
					"some_number": 3
				  }
				}
			  }
			  `,
			wantErr: false,
		},
		{
			name: "should evaluate without problems (2)",
			input: `data "aws_iam_policy_document" "blabla" {
	statement {
	  actions = [
		"secretsmanager:GetSecretValue",
	  ]
	  resources = [
		for s in [
		  "DATABASE_READONLY_PASSWORD",
		  "DATABASE_DATA_PASSWORD",
		] : "arn:aws:secretsmanager:eu-west-1:${data.aws_caller_identity.this.account_id}:secret:/${var.env}/*/${s}-*"
	  ]
	}
  }
`,
			want: `
			{
				"data": {
				  "aws_iam_policy_document": {
					"blabla": {
					  "_dd_meta": {
						"provider": "aws",
						"configured": {
						  "statement": [
							{"actions": true, "resources": true}
						  ]
						},
						"unknown": {
						  "statement": [
							{"resources": true}
						  ]
						}
					  },
					  "statement": [{
						"resources": [
						  "arn:aws:secretsmanager:eu-west-1:${data.aws_caller_identity.this.account_id}:secret:/${var.env}/*/DATABASE_READONLY_PASSWORD-*",
						  "arn:aws:secretsmanager:eu-west-1:${data.aws_caller_identity.this.account_id}:secret:/${var.env}/*/DATABASE_DATA_PASSWORD-*"
						],
						"actions": [
						  "secretsmanager:GetSecretValue"
						],
						"_dd_lines": {
						  "_dd__default": {
							"_dd_line": 2
						  },
						  "_dd_actions": {
							"_dd_line": 3,
							"_dd_arr": [
							  {
								"_dd__default": {
								  "_dd_line": 4
								}
							  }
							]
						  },
						  "_dd_resources": {
							"_dd_line": 6
						  }
						}
					  }],
					  "_dd_lines": {
						"_dd__default": {
						  "_dd_line": 1
						},
						"_dd_statement": {
						  "_dd_line": 2
						}
					  }
					}
				  }
				},
				"_dd_lines": {
				  "_dd__default": {
					"_dd_line": 0
				  },
				  "_dd_data": {
					"_dd_line": 1
				  }
				}
			  }
`,
			wantErr: false,
		},
		{
			name: "should evaluate without problems (3)",
			input: `locals {
  namespace_secrets = { for n in ["string1", "string2", "string3"] : "${n}_default" => {
    "roles/secretmanager.secretAccessor" = [
      "serviceAccount:${module.test[local.name].email}",
    ]
    }
  }
}
`,
			want: `
			{
  "locals": {
    "namespace_secrets": "${{ for n in [\"string1\", \"string2\", \"string3\"] : \"${n}_default\" => {\n    \"roles/secretmanager.secretAccessor\" = [\n      \"serviceAccount:${module.test[local.name].email}\",\n    ]\n    }\n  }}",
    "_dd_lines": {
      "_dd__default": {
        "_dd_line": 1
      },
      "_dd_namespace_secrets": {
        "_dd_line": 2
      }
    }
  },
  "_dd_lines": {
    "_dd__default": {
      "_dd_line": 0
    },
    "_dd_locals": {
      "_dd_line": 1
    }
  }
}
`,
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, _ := hclsyntax.ParseConfig([]byte(tt.input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})
			c := newConverter(file.Bytes, nil, functions.TerraformFuncs)
			body := file.Body.(*hclsyntax.Body)
			c.file = body
			got, _, err := c.convertBody(ctx, body, 0, bodyRules{})
			require.True(t, (err != nil) == tt.wantErr)
			gotJSON, _ := json.Marshal(got)
			var wantJSON model.Document
			_ = json.Unmarshal([]byte(tt.want), &wantJSON)
			_ = json.Unmarshal(gotJSON, &got)
			require.Equal(t, wantJSON, got)
		})
	}
}

// TestLabelsWithNestedBlock tests the functions [DefaultConverted] and all the methods called by them
func TestConversion(t *testing.T) { //nolint
	const input = `
locals {
	test3 = 1 + 2
	test1 = "hello"
	test2 = 5
	arr = [1, 2, 3, 4]
	hyphen-test = 3
	temp = "${1 + 2} %{if local.test2 < 3}\"4\n\"%{endif}"
	temp2 = "${"hi"} there"
		quoted = "\"quoted\""
		squoted = "'quoted'"
	x = -10
	y = -x
	z = -(1 + 4)
}
locals {
	other = {
		num = local.test2 + 5
		thing = [for x in local.arr: x * 2]
		"${local.test3}" = 4
		3 = 1
		"local.test1" = 89
		"a.b.c[\"hi\"][3].*" = 3
		loop = "This has a for loop: %{for x in local.arr}x,%{endfor}"
		a.b.c = "True"
	}
}
locals {
	heredoc = <<-EOF
		This is a heredoc template.
		It references ${local.other.3}
	EOF
	simple = "${4 - 2}"
	cond = test3 > 2 ? 1: 0
	heredoc2 = <<EOF
		Another heredoc, that
		doesn't remove indentation
		${local.other.3}
		%{if true ? false : true}"gotcha"\n%{else}4%{endif}
	EOF
}
data "terraform_remote_state" "remote" {
	backend = "s3"
	config = {
		profile = var.profile
		region  = var.region
		bucket  = "${var.bucket}-mybucket"
		key     = "mykey"
	}
	policy = jsonencode({
    	Id      = "MYBUCKETPOLICY"
	})
	some_number = max(max(1,3),2)
}
variable "profile" {}
variable "region" {
	default = "us-east-1"
}
`

	const expected = `{
		"locals": [
			{
				"arr": [
					1,
					2,
					3,
					4
				],
				"temp2": "hi there",
				"x": -10,
				"squoted": "'quoted'",
				"hyphen-test": 3,
				"_dd_lines": {
					"_dd__default": {
						"_dd_line": 2
					},
					"_dd_arr": {
						"_dd_line": 6,
						"_dd_arr": [
							{
								"_dd__default": {
									"_dd_line": 6
								}
							},
							{
								"_dd__default": {
									"_dd_line": 6
								}
							},
							{
								"_dd__default": {
									"_dd_line": 6
								}
							},
							{
								"_dd__default": {
									"_dd_line": 6
								}
							}
						]
					},
					"_dd_hyphen-test": {
						"_dd_line": 7
					},
					"_dd_quoted": {
						"_dd_line": 10
					},
					"_dd_squoted": {
						"_dd_line": 11
					},
					"_dd_temp": {
						"_dd_line": 8
					},
					"_dd_temp2": {
						"_dd_line": 9
					},
					"_dd_test1": {
						"_dd_line": 4
					},
					"_dd_test2": {
						"_dd_line": 5
					},
					"_dd_test3": {
						"_dd_line": 3
					},
					"_dd_x": {
						"_dd_line": 12
					},
					"_dd_y": {
						"_dd_line": 13
					},
					"_dd_z": {
						"_dd_line": 14
					}
				},
				"quoted": "\"quoted\"",
				"y": "${-x}",
				"z": -5,
				"test3": 3,
				"test1": "hello",
				"test2": 5,
				"temp": "3 %{if local.test2 \u003c 3}\"4\n\"%{endif}"
			},
			{
				"other": {
					"a.b.c": "True",
					"num": "${local.test2 + 5}",
					"thing": "${[for x in local.arr: x * 2]}",
					"${local.test3}": 4,
					"3": 1,
					"local.test1": 89,
					"a.b.c[\"hi\"][3].*": 3,
					"loop": "This has a for loop: %{for x in local.arr}x,%{endfor}"
				},
				"_dd_lines": {
					"_dd__default": {
						"_dd_line": 16
					},
					"_dd_other": {
						"_dd_line": 17
					}
				}
			},
			{
				"heredoc2": "\t\tAnother heredoc, that\n\t\tdoesn't remove indentation\n\t\t${local.other.3}\n\t\t%{if true ? false : true}\"gotcha\"\\n%{else}4%{endif}\n",` + //nolint
		`"_dd_lines": {
					"_dd__default": {
						"_dd_line": 28
					},
					"_dd_cond": {
						"_dd_line": 34
					},
					"_dd_heredoc": {
						"_dd_line": 29
					},
					"_dd_heredoc2": {
						"_dd_line": 35
					},
					"_dd_simple": {
						"_dd_line": 33
					}
				},
				"heredoc": "This is a heredoc template.\nIt references ${local.other.3}\n",
				"simple": 2,
				"cond": "${test3 \u003e 2 ? 1: 0}"
			}
		],
		"data": {
			"terraform_remote_state": {
				"remote": {
					"some_number": 3,
					"_dd_lines": {
						"_dd__default": {
							"_dd_line": 42
						},
						"_dd_backend": {
							"_dd_line": 43
						},
						"_dd_config": {
							"_dd_line": 44
						},
						"_dd_policy": {
							"_dd_line": 50
						},
						"_dd_some_number": {
							"_dd_line": 53
						}
					},
					"_dd_meta": {
						"provider": "terraform",
						"configured": {
							"backend": true,
							"config": true,
							"policy": true,
							"some_number": true
						},
						"unknown": {
							"config": {
								"bucket": true,
								"profile": true,
								"region": true
							}
						}
					},
					"backend": "s3",
					"config": {
						"profile": "${var.profile}",
						"region": "${var.region}",
						"bucket": "${var.bucket}-mybucket",
						"key": "mykey"
					},
					"policy": "{\"Id\":\"MYBUCKETPOLICY\"}"
				}
			}
		},
		"variable": {
			"profile": {
				"_dd_lines": {
					"_dd__default": {
						"_dd_line": 55
					}
				}
			},
			"region": {
				"default": "us-east-1",
				"_dd_lines": {
					"_dd__default": {
						"_dd_line": 56
					},
					"_dd_default": {
						"_dd_line": 57
					}
				}
			}
		},
		"_dd_lines": {
			"_dd__default": {
				"_dd_line": 0
			},
			"_dd_data": {
				"_dd_line": 42
			},
			"_dd_locals": {
				"_dd_line": 28
			},
			"_dd_variable": {
				"_dd_line": 56
			}
		}
	}`

	ctx := context.Background()
	file, _ := hclsyntax.ParseConfig([]byte(input), "testFileName", hcl.Pos{Byte: 0, Line: 1, Column: 1})

	body, err := DefaultConverted(ctx, file, VariableMap{})
	require.NoError(t, err)
	compareJSONLine(t, body, expected)
}

func convertToJSONMap(t *testing.T, input string, vars VariableMap) map[string]interface{} {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(input), "main.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors())
	body, err := DefaultConverted(context.Background(), file, vars)
	require.NoError(t, err)
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func TestDynamicBlocksExpand(t *testing.T) {
	input := `
resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = var.rules
    iterator = rule
    content {
      description = rule.key
      from_port   = rule.value.port
    }
  }
  dynamic "egress" {
    for_each = var.unknown
    content {
      to_port = egress.value.port
    }
  }
  dynamic "logging" {
    for_each = []
    content {
      enabled = true
    }
  }
  tags = { name = "${rule}" }
}
`
	out := convertToJSONMap(t, input, VariableMap{
		"var": cty.ObjectVal(map[string]cty.Value{
			"rules": cty.ObjectVal(map[string]cty.Value{
				"https": cty.ObjectVal(map[string]cty.Value{"port": cty.NumberIntVal(443)}),
				"ssh":   cty.ObjectVal(map[string]cty.Value{"port": cty.NumberIntVal(22)}),
			}),
			"unknown": cty.DynamicVal,
		}),
	})
	sg := out["resource"].(map[string]interface{})["aws_security_group"].(map[string]interface{})["sg"].(map[string]interface{})

	require.NotContains(t, sg["dynamic"], "ingress")
	require.NotContains(t, sg, "logging")
	ingress := sg["ingress"].([]interface{})
	require.Len(t, ingress, 2)
	require.Equal(t, "https", ingress[0].(map[string]interface{})["description"])
	require.Equal(t, float64(22), ingress[1].(map[string]interface{})["from_port"])

	require.NotContains(t, sg, "egress", "a dynamic block over an unknown collection is kept as written")
	content := sg["dynamic"].(map[string]interface{})["egress"].([]interface{})[0].(map[string]interface{})["content"].([]interface{})[0].(map[string]interface{})
	require.Equal(t, "${egress.value.port}", content["to_port"])

	require.Equal(t, "${rule}", sg["tags"].(map[string]interface{})["name"],
		"the iterator must not stay bound after its dynamic block")
}

func TestCountResolvedFromVariables(t *testing.T) {
	input := `
resource "aws_s3_bucket" "disabled" {
  count  = var.enabled ? 1 : 0
  bucket = "a"
}
resource "aws_s3_bucket" "unknown" {
  count  = var.unset ? 1 : 0
  bucket = "b"
}
`
	out := convertToJSONMap(t, input, VariableMap{
		"var": cty.ObjectVal(map[string]cty.Value{
			"enabled": cty.False,
			"unset":   cty.DynamicVal,
		}),
	})
	buckets := out["resource"].(map[string]interface{})["aws_s3_bucket"].(map[string]interface{})
	require.NotContains(t, buckets, "disabled", "a block whose count is known to be 0 creates nothing")
	unknown := buckets["unknown"].(map[string]interface{})
	require.NotContains(t, unknown, "count")
	require.Equal(t, true, unknown["_dd_meta"].(map[string]interface{})["unknown"].(map[string]interface{})["count"])
}

func TestNestedCountAttributeKept(t *testing.T) {
	input := `
resource "aws_y" "b" {
  setting {
    count = 0
    name  = "a"
  }
}
`
	out := convertToJSONMap(t, input, VariableMap{})
	setting := out["resource"].(map[string]interface{})["aws_y"].(map[string]interface{})["b"].(map[string]interface{})["setting"].([]interface{})[0].(map[string]interface{})
	require.EqualValues(t, 0, setting["count"])
	require.Equal(t, "a", setting["name"])
}

func TestNullStringDoesNotPanic(t *testing.T) {
	input := `
resource "aws_ssm_parameter" "db" {
  name  = "prefix-${var.password}"
  value = "${null}"
  count = null
}
`
	file, diags := hclsyntax.ParseConfig([]byte(input), "ssm.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors())

	require.NotPanics(t, func() {
		_, err := DefaultConverted(context.Background(), file, VariableMap{
			"var": cty.ObjectVal(map[string]cty.Value{
				"password": cty.NullVal(cty.String),
			}),
		})
		require.NoError(t, err)
	})
}

// A dynamic block whose labels do not resolve for one element is kept as
// written, not expanded with that element's blocks dropped.
func TestDynamicBlocksWithUnresolvedLabelStayAsWritten(t *testing.T) {
	input := `
resource "aws_y" "b" {
  dynamic "setting" {
    for_each = var.settings
    labels   = [setting.value.name]
    content {
      value = setting.value.name
    }
  }
}
`
	out := convertToJSONMap(t, input, VariableMap{
		"var": cty.ObjectVal(map[string]cty.Value{
			"settings": cty.ListVal([]cty.Value{
				cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal("a")}),
				cty.ObjectVal(map[string]cty.Value{"name": cty.NullVal(cty.String)}),
			}),
		}),
	})
	b := out["resource"].(map[string]interface{})["aws_y"].(map[string]interface{})["b"].(map[string]interface{})
	require.NotContains(t, b, "setting", "a partially resolved dynamic block must not be expanded")
	require.Contains(t, b["dynamic"], "setting")
}

// Nested dynamic blocks expand fully: every outer block carries every inner
// block, however many the nesting multiplies to.
func TestDynamicBlocksExpandFully(t *testing.T) {
	input := `
resource "aws_security_group" "sg" {
  dynamic "outer" {
    for_each = var.outer
    content {
      dynamic "inner" {
        for_each = var.inner
        content {
          port = inner.value
        }
      }
    }
  }
}
`
	numbers := func(n int) cty.Value {
		vals := make([]cty.Value, n)
		for i := range vals {
			vals[i] = cty.NumberIntVal(int64(i))
		}
		return cty.ListVal(vals)
	}
	out := convertToJSONMap(t, input, VariableMap{
		"var": cty.ObjectVal(map[string]cty.Value{
			"outer": numbers(40),
			"inner": numbers(30),
		}),
	})
	sg := out["resource"].(map[string]interface{})["aws_security_group"].(map[string]interface{})["sg"].(map[string]interface{})
	outer := sg["outer"].([]interface{})
	require.Len(t, outer, 40)
	for _, o := range outer {
		entry := o.(map[string]interface{})
		inner, ok := entry["inner"].([]interface{})
		require.True(t, ok, "every outer block must carry its expanded inner blocks")
		require.Len(t, inner, 30)
	}
}

// Values the converter cannot evaluate are listed in _dd_meta.unknown in the
// shape of Terraform's after_unknown, while the document keeps their text.
func TestUnevaluatedValuesAreUnknown(t *testing.T) {
	input := `
resource "aws_x" "a" {
  name   = var.name
  known  = "k"
  joined = "${var.p}-x"
  list   = ["a", var.b, { c = var.c }, { d = "d" }]
  tags   = { a = "a", b = local.b }
  ebs {
    size = 1
  }
  ebs {
    size = var.size
  }
  dynamic "setting" {
    for_each = var.settings
    content {
      value = setting.value
    }
  }
  dynamic "rule" {
    for_each = ["x", "y"]
    content {
      value = rule.value == "y" ? var.y : rule.value
    }
  }
}

data "aws_y" "d" {
  name = "n"
}

ephemeral "aws_z" "e" {
  name = var.n
}

resource "aws_x" "single" {
  ebs {
    size = var.size
    type = "gp3"
  }
  dynamic "rule" {
    for_each = ["x"]
    content {
      value = var.y
    }
  }
}

module "m" {
  source = var.s
}
`
	out := convertToJSONMap(t, input, nil)
	block := func(section, typ, name string) map[string]interface{} {
		byType := out[section].(map[string]interface{})[typ].(map[string]interface{})
		if name == "" {
			return byType
		}
		return byType[name].(map[string]interface{})
	}
	unknownOf := func(block map[string]interface{}) interface{} {
		meta, _ := block["_dd_meta"].(map[string]interface{})
		return meta["unknown"]
	}
	a := block("resource", "aws_x", "a")
	require.Equal(t, "${var.name}", a["name"])
	require.Equal(t, map[string]interface{}{
		"name":    true,
		"joined":  true,
		"list":    []interface{}{false, true, map[string]interface{}{"c": true}, map[string]interface{}{}},
		"tags":    map[string]interface{}{"b": true},
		"ebs":     []interface{}{map[string]interface{}{}, map[string]interface{}{"size": true}},
		"setting": true,
		"rule":    []interface{}{map[string]interface{}{}, map[string]interface{}{"value": true}},
	}, unknownOf(a))
	single := block("resource", "aws_x", "single")
	require.IsType(t, []interface{}{}, single["ebs"])
	require.IsType(t, []interface{}{}, single["rule"])
	require.Equal(t, map[string]interface{}{
		"ebs":  []interface{}{map[string]interface{}{"size": true}},
		"rule": []interface{}{map[string]interface{}{"value": true}},
	}, unknownOf(single))
	require.Nil(t, unknownOf(block("data", "aws_y", "d")))
	require.Equal(t, map[string]interface{}{"name": true}, unknownOf(block("ephemeral", "aws_z", "e")))
	require.Equal(t, map[string]interface{}{"source": true}, unknownOf(block("module", "m", "")))
}

// Meta-arguments are not in the body; an unknown count or for_each is
// unknown.count, as in an evaluated block.
func TestMetaArgumentsLeaveTheBody(t *testing.T) {
	input := `
resource "aws_x" "a" {
  count      = var.n
  depends_on = [var.d]
  provider   = aws.west
  name       = var.name
  lifecycle {
    ignore_changes = [var.i]
  }
  connection {
    host = "h"
  }
  provisioner "local-exec" {
    command = "echo"
  }
}

resource "aws_x" "b" {
  for_each = var.m
}

module "m" {
  source     = "./m"
  count      = 2
  depends_on = [aws_x.a]
  providers  = { aws = aws.west }
}
`
	out := convertToJSONMap(t, input, nil)
	a := out["resource"].(map[string]interface{})["aws_x"].(map[string]interface{})["a"].(map[string]interface{})
	for _, key := range []string{"count", "depends_on", "provider", "lifecycle", "connection"} {
		require.NotContains(t, a, key)
	}
	require.Contains(t, a, "provisioner")
	meta := a["_dd_meta"].(map[string]interface{})
	require.Equal(t, map[string]interface{}{"name": true, "count": true}, meta["unknown"])
	require.Equal(t, map[string]interface{}{"name": true}, meta["configured"])
	require.Equal(t, "aws.west", meta["provider"])

	b := out["resource"].(map[string]interface{})["aws_x"].(map[string]interface{})["b"].(map[string]interface{})
	require.NotContains(t, b, "for_each")
	require.Equal(t, map[string]interface{}{"count": true}, b["_dd_meta"].(map[string]interface{})["unknown"])
	require.Equal(t, "aws", b["_dd_meta"].(map[string]interface{})["provider"])

	m := out["module"].(map[string]interface{})["m"].(map[string]interface{})
	for _, key := range []string{"count", "depends_on", "providers"} {
		require.NotContains(t, m, key)
	}
	require.Equal(t, "./m", m["source"])
}

// An output's depends_on is a meta-argument: not in the body and not unknown.
func TestOutputDependsOnIsHidden(t *testing.T) {
	out := convertToJSONMap(t, `
output "o" {
  value      = aws_x.a.id
  depends_on = [aws_x.a]
}
resource "aws_x" "a" {}
`, nil)
	o := out["output"].(map[string]interface{})["o"].(map[string]interface{})
	require.NotContains(t, o, "depends_on")
	meta, _ := o["_dd_meta"].(map[string]interface{})
	if meta != nil {
		unknown, _ := meta["unknown"].(map[string]interface{})
		require.NotContains(t, unknown, "depends_on")
	}
}

// Blocks whose count or for_each is known to create nothing are left out.
func TestEmptyExpansionsAreLeftOut(t *testing.T) {
	input := `
resource "aws_x" "zero" {
  count = 0
}
resource "aws_x" "empty" {
  for_each = toset([])
}
data "aws_y" "empty" {
  for_each = {}
}
module "none" {
  source = "./m"
  count  = 0
}
resource "aws_x" "kept" {
  count = 1
}
`
	out := convertToJSONMap(t, input, nil)
	require.Equal(t, []string{"kept"}, sortedKeys(out["resource"].(map[string]interface{})["aws_x"]))
	require.NotContains(t, out, "data")
	require.NotContains(t, out, "module")
}

func sortedKeys(v interface{}) []string {
	var keys []string
	for k := range v.(map[string]interface{}) {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// A constant null attribute of a resource or provider is unset, as in
// Terraform; elsewhere, as a variable default, null is a value.
func TestNullAttributesAreUnset(t *testing.T) {
	input := `
resource "aws_x" "a" {
  key_name = null
  name     = var.none
  ebs {
    size = null
    type = "gp3"
  }
}
provider "aws" {
  region = null
}
variable "v" {
  default = null
}
`
	out := convertToJSONMap(t, input, VariableMap{
		"var": cty.ObjectVal(map[string]cty.Value{"none": cty.NullVal(cty.String)}),
	})
	a := out["resource"].(map[string]interface{})["aws_x"].(map[string]interface{})["a"].(map[string]interface{})
	require.NotContains(t, a, "key_name")
	require.NotContains(t, a, "name")
	require.Contains(t, a["_dd_lines"], "_dd_key_name", "the written line is still known")
	ebs := a["ebs"].([]interface{})[0].(map[string]interface{})
	require.NotContains(t, ebs, "size")
	require.Equal(t, map[string]interface{}{"ebs": []interface{}{map[string]interface{}{"type": true}}},
		a["_dd_meta"].(map[string]interface{})["configured"])
	aws := out["provider"].(map[string]interface{})["aws"].([]interface{})[0].(map[string]interface{})
	require.NotContains(t, aws, "region")
	v := out["variable"].(map[string]interface{})["v"].(map[string]interface{})
	require.Contains(t, v, "default")
}

// Labels that may repeat hold a list of bodies, even when written once.
func TestRepeatableLabelsAreLists(t *testing.T) {
	input := `
provider "aws" {
  region = "us-east-1"
}
provider "google" {
  project = "a"
}
provider "google" {
  alias   = "b"
  project = "b"
}
resource "aws_x" "a" {
  provisioner "local-exec" {
    command = "echo"
  }
  dynamic "setting" {
    for_each = var.unknown
    content {
      name = setting.value
    }
  }
}
`
	out := convertToJSONMap(t, input, nil)
	providers := out["provider"].(map[string]interface{})
	require.Len(t, providers["aws"], 1)
	require.Len(t, providers["google"], 2)
	a := out["resource"].(map[string]interface{})["aws_x"].(map[string]interface{})["a"].(map[string]interface{})
	require.Len(t, a["provisioner"].(map[string]interface{})["local-exec"], 1)
	require.Len(t, a["dynamic"].(map[string]interface{})["setting"], 1)
}

// An unknown dynamic block is unknown.<type> = true and generates no
// configured shape; static and generated blocks of a type have one
// configured shape per block, in document order.
func TestDynamicBlocksMeta(t *testing.T) {
	input := `
resource "aws_x" "a" {
  ingress {
    from_port = 1
  }
  dynamic "ingress" {
    for_each = ["a", "b"]
    content {
      to_port     = 2
      description = ingress.value
    }
  }
  dynamic "egress" {
    for_each = var.unknown
    content {
      to_port = 2
    }
  }
}
`
	out := convertToJSONMap(t, input, nil)
	a := out["resource"].(map[string]interface{})["aws_x"].(map[string]interface{})["a"].(map[string]interface{})
	require.Len(t, a["ingress"], 3)
	require.NotContains(t, a["dynamic"], "ingress")
	meta := a["_dd_meta"].(map[string]interface{})
	require.Equal(t, map[string]interface{}{"egress": true}, meta["unknown"])
	require.Equal(t, map[string]interface{}{
		"ingress": []interface{}{
			map[string]interface{}{"from_port": true},
			map[string]interface{}{"to_port": true, "description": true},
			map[string]interface{}{"to_port": true, "description": true},
		},
	}, meta["configured"])
}

// Module calls and outputs record their unknown values like a plan does.
func TestModuleOutputAndProviderMeta(t *testing.T) {
	input := `
provider "aws" {
  default_tags {
    tags = var.tags
  }
}
provider "aws" {
  alias = "west"
}
module "m" {
  source = "./m"
  name   = var.name
}
output "o" {
  value = aws_x.a.id
}
output "k" {
  value = "k"
}
`
	out := convertToJSONMap(t, input, nil)
	m := out["module"].(map[string]interface{})["m"].(map[string]interface{})
	require.Equal(t, map[string]interface{}{"unknown": map[string]interface{}{"name": true}}, m["_dd_meta"])
	outputs := out["output"].(map[string]interface{})
	require.Equal(t, map[string]interface{}{"unknown": map[string]interface{}{"value": true}},
		outputs["o"].(map[string]interface{})["_dd_meta"])
	require.NotContains(t, outputs["k"], "_dd_meta")
	providers := out["provider"].(map[string]interface{})["aws"].([]interface{})
	require.Len(t, providers, 2)
	require.Equal(t, map[string]interface{}{"unknown": map[string]interface{}{
		"default_tags": []interface{}{map[string]interface{}{"tags": true}},
	}}, providers[0].(map[string]interface{})["_dd_meta"])
	require.NotContains(t, providers[1], "_dd_meta")
}
