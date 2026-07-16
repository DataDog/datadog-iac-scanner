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
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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
				"nested_block": {
					"_dd_lines": {
						"_dd__default": {
							"_dd_line": 3
						}
					}
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
							"_dd_lines": {
								"_dd__default": {
									"_dd_line": 4
								},
								"_dd_attribute": {
									"_dd_line": 6
								},
								"_dd_id": {
									"_dd_line": 5
								}
							},
							"attribute": "a",
							"id": "name1"
						},
						{
							"_dd_lines": {
								"_dd__default": {
									"_dd_line": 8
								},
								"_dd_attribute": {
									"_dd_line": 10
								},
								"_dd_id": {
									"_dd_line": 9
								}
							},
							"attribute": "a,b",
							"id": "name2"
						},
						{
							"_dd_lines": {
								"_dd__default": {
									"_dd_line": 12
								},
								"_dd_attribute": {
									"_dd_line": 14
								},
								"_dd_id": {
									"_dd_line": 13
								}
							},
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

	t.Run("function_call_returning_non_string_wraps", func(t *testing.T) {
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
		gotValue := fmt.Sprintf("%v", blockDoc["name"])
		require.Contains(t, gotValue, "length")
	})
}

func TestEvalFunction(t *testing.T) { //nolint
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
						"_dd_line": 3,
						"_dd_lines": {
						  "_dd__default": {
							"_dd_line": 3
						  },
						  "_dd_Id": {
							"_dd_line": 4
						  }
						}
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
			name: "should evaluate after mocking variable",
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
						"_dd_line": 3,
						"_dd_lines": {
						  "_dd__default": {
							"_dd_line": 3
						  },
						  "_dd_Id": {
							"_dd_line": 4
						  }
						}
					  },
					  "_dd_some_number": {
						"_dd_line": 6
					  }
					},
					"policy": "{\"Id\":\"aws.meuId\"}",
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
					  "statement": {
						"resources": "${[\n\t\tfor s in [\n\t\t  \"DATABASE_READONLY_PASSWORD\",\n\t\t  \"DATABASE_DATA_PASSWORD\",\n\t\t] : \"arn:aws:secretsmanager:eu-west-1:${data.aws_caller_identity.this.account_id}:secret:/${var.env}/*/${s}-*\"\n\t  ]}",
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
					  },
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
			c := converter{bytes: file.Bytes}
			got, err := c.convertBody(ctx, file.Body.(*hclsyntax.Body), 0)
			fmt.Println(err)
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
				"temp": "${1 + 2} %{if local.test2 \u003c 3}\"4\n\"%{endif}"
			},
			{
				"other": {
					"_dd_lines": {
						"_dd__default": {
							"_dd_line": 17
						},
						"_dd_num": {
							"_dd_line": 18
						},
						"_dd_thing": {
							"_dd_line": 19
						},
						"_dd_${local.test3}": {
							"_dd_line": 20
						},
						"_dd_3": {
							"_dd_line": 21
						},
						"_dd_local.test1": {
							"_dd_line": 22
						},
						"_dd_a.b.c[\"hi\"][3].*": {
							"_dd_line": 23
						},
						"_dd_loop": {
							"_dd_line": 24
						},
						"_dd_a.b.c": {
							"_dd_line": 25
						}
					},
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
							"_dd_line": 50,
							"_dd_lines": {
								"_dd__default": {
									"_dd_line": 50
								},
								"_dd_Id": {
									"_dd_line": 51
								}
							}
						},
						"_dd_some_number": {
							"_dd_line": 53
						}
					},
					"backend": "s3",
					"config": {
						"_dd_lines": {
							"_dd__default": {
								"_dd_line": 44
							},
							"_dd_profile": {
								"_dd_line": 45
							},
							"_dd_region": {
								"_dd_line": 46
							},
							"_dd_bucket": {
								"_dd_line": 47
							},
							"_dd_key": {
								"_dd_line": 48
							}
						},
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
