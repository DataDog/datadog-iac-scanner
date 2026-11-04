/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"encoding/json"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

type args struct {
	doc []byte
}

var testsinitiateJSONLine = []struct {
	name     string
	args     args
	wantLine string
}{
	{
		name: "test array of ints",
		args: args{
			doc: []byte(`{
					"father": {
						"son" : [
							1,
							2,
							3,
							0
						]
					}
				}
				`),
		},
		wantLine: `{
				"_dd_lines": {
				  "_dd__default": {
					"_dd_line": 0
				  },
				  "_dd_father": {
					"_dd_line": 2
				  }
				},
				"father": {
				  "_dd_lines": {
					"_dd__default": {
					  "_dd_line": 2
					},
					"_dd_son": {
					  "_dd_arr": [
						{
						  "_dd__default": {
							"_dd_line": 4
						  }
						},
						{
						  "_dd__default": {
							"_dd_line": 5
						  }
						},
						{
						  "_dd__default": {
							"_dd_line": 6
						  }
						},
						{
						  "_dd__default": {
							"_dd_line": 7
						  }
						}
					  ],
					  "_dd_line": 3
					}
				  },
				  "son": [
					1,
					2,
					3,
					0
				  ]
				}
			  }`,
	},
	{
		name: "test array objects line",
		args: args{
			doc: []byte(`{
					"father": [
						{
							"key": "value"
						}
					]
				}
				`),
		},
		wantLine: `
			{
				"_dd_lines": {
				  "_dd__default": {
					"_dd_line": 0
				  },
				  "_dd_father": {
					"_dd_arr": [
					  {
						"_dd__default": {
						  "_dd_line": 4
						},
						"_dd_key": {
						  "_dd_line": 4
						}
					  }
					],
					"_dd_line": 2
				  }
				},
				"father": [
				  {
					"key": "value"
				  }
				]
			  }
			  `,
	},
	{
		name: "test initiate json line",
		args: args{
			doc: []byte(`{
					"parameters": "simple test"
				}
				`),
		},
		wantLine: `
			{
				"_dd_lines": {
					"_dd__default": {
						"_dd_line": 0
					},
					"_dd_parameters": {
						"_dd_line": 2
					}
				},
				"parameters":"simple test"
			}`,
	},
	{
		name: "test initiate special close json line",
		args: args{
			doc: []byte(`{
					"father": {
						"close": [
							"value"
						]
					}
				}
				`),
		},
		wantLine: `
			{
				"_dd_lines": {
				  "_dd__default": {
					"_dd_line": 0
				  },
				  "_dd_father": {
					"_dd_line": 2
				  }
				},
				"father": {
				  "_dd_lines": {
					"_dd__default": {
					  "_dd_line": 2
					},
					"_dd_close": {
					  "_dd_arr": [
						{
						  "_dd__default": {
							"_dd_line": 4
						  }
						}
					  ],
					  "_dd_line": 3
					}
				  },
				  "close": [
					"value"
				  ]
				}
			  }
			  `,
	},
	{
		name: "test same key different path json line",
		args: args{
			doc: []byte(`{
					"father1": {
						"key": "value"
					},
					"father2": {
						"key": "value"
					}
				}
				`),
		},
		wantLine: `{
				"_dd_lines": {
				  "_dd__default": {
					"_dd_line": 0
				  },
				  "_dd_father1": {
					"_dd_line": 2
				  },
				  "_dd_father2": {
					"_dd_line": 5
				  }
				},
				"father1": {
				  "_dd_lines": {
					"_dd__default": {
					  "_dd_line": 2
					},
					"_dd_key": {
					  "_dd_line": 3
					}
				  },
				  "key": "value"
				},
				"father2": {
				  "_dd_lines": {
					"_dd__default": {
					  "_dd_line": 5
					},
					"_dd_key": {
					  "_dd_line": 6
					}
				  },
				  "key": "value"
				}
			  }`,
	},
	{
		name: "test with parent json line",
		args: args{
			doc: []byte(`{
				"father": {
					"son": "this is a son"
				}
			}
			`),
		},
		wantLine: `
			{
				"_dd_lines": {
					"_dd__default": {
						"_dd_line": 0
					},
					"_dd_father":{
						"_dd_line": 2
					}
				},
				"father": {
					"_dd_lines": {
						"_dd__default": {
							"_dd_line": 2
						},
						"_dd_son": {
							"_dd_line": 3
						}
					},
					"son": "this is a son"
					}
			}`,
	},
	{
		name: "test with array string json line",
		args: args{
			doc: []byte(`{
					"father": [
						"testing1",
						"testing2"
					]
				}
				`),
		},
		wantLine: `
			{
				"_dd_lines": {
					"_dd__default": {
						"_dd_line": 0
					},
					"_dd_father": {
						"_dd_arr": [
							{
								"_dd__default": {
									"_dd_line": 3
								}
							},
							{
								"_dd__default": {
									"_dd_line": 4
								}
							}
						],
						"_dd_line":2
					}
				},
				"father": [
					"testing1",
					"testing2"
				]
			}`,
	},
	{
		name: "test with equal string json line",
		args: args{
			doc: []byte(`{
					"father": [
						"testing",
						"testing"
					]
				}
				`),
		},
		wantLine: `
			{
				"_dd_lines": {
					"_dd__default": {
						"_dd_line": 0
					},
					"_dd_father": {
						"_dd_arr":[
							{
								"_dd__default": {
									"_dd_line": 3
								}
							},
							{
								"_dd__default": {
									"_dd_line": 4
								}
							}
						],
						"_dd_line": 2
					}
				},
				"father":[
					"testing",
					"testing"
				]
			}`,
	},
	{
		name: "test arrays with objects",
		args: args{
			doc: []byte(`{
				"resources": [
					{
						"properties": {
							"httpsOnly": false
						}
					},
					{
						"properties": {
							"httpsOnly": false
						}
					}
				]
			}
			`),
		},
		wantLine: `
			{
				"_dd_lines":{
					"_dd__default":{
						"_dd_line":0
					},
					"_dd_resources":{
						"_dd_line":2,
					"_dd_arr":[
						{
							"_dd__default":{
								"_dd_line":4
							},
							"_dd_properties":{
								"_dd_line":4
							}
						},
						{
							"_dd__default":{
								"_dd_line":9
							},
							"_dd_properties":{
								"_dd_line":9
							}
						}
					]
				}
			},
			"resources":[
				{
					"properties":{
						"_dd_lines":{
							"_dd__default":{
								"_dd_line":4
							},
							"_dd_httpsOnly":{
								"_dd_line":5
							}
						},
						"httpsOnly":false
					}
				},
				{
					"properties":{
						"_dd_lines":{
							"_dd__default":{
								"_dd_line":9
							},
							"_dd_httpsOnly":{
								"_dd_line":10
							}
						},
						"httpsOnly":false
					}
				}
			]
		}`,
	},
}

func compareJSONLine(t *testing.T, test1 interface{}, test2 string) {
	stringefiedJSON, err := json.Marshal(&test1)
	require.NoError(t, err)
	aux := string(stringefiedJSON)
	require.JSONEq(t, test2, aux)
}

func Test_jsonLine_setLineInfo(t *testing.T) {
	for _, tt := range testsinitiateJSONLine {
		//t.Run(tt.name, func(t *testing.T) {
		unmarshaledJSON := make(map[string]interface{})
		err := json.Unmarshal(tt.args.doc, &unmarshaledJSON)
		require.NoError(t, err)
		j := initializeJSONLine(tt.args.doc)
		got := j.setLineInfo(unmarshaledJSON)
		compareJSONLine(t, got, tt.wantLine)
		//})
	}
}

func TestExtractResourceHeaderLinesReadsChildModules(t *testing.T) {
	src := []byte(`{
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_vpc.main",
          "values": {
            "id": "vpc"
          }
        }
      ],
      "child_modules": [
        {
          "address": "module.child",
          "resources": [
            {
              "address": "module.child.aws_vpc_endpoint.gw",
              "values": {
                "service_name": "dynamodb"
              }
            }
          ]
        }
      ]
    }
  }
}`)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(src, &doc))
	raw, err := json.Marshal(initializeJSONLine(src).setLineInfo(doc))
	require.NoError(t, err)
	lines := extractResourceHeaderLines(raw)
	require.Equal(t, 7, lines["aws_vpc.main"])
	require.Equal(t, 18, lines["module.child.aws_vpc_endpoint.gw"])
}

func TestSetLineInfoListElementsKeepTheirOwnLine(t *testing.T) {
	src := []byte(`{
  "items": [
    {
      "a": 1
    },
    {
      "b": 2
    }
  ]
}`)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(src, &doc))
	out := initializeJSONLine(src).setLineInfo(doc)
	arr := out["_dd_lines"].(map[string]*model.LineObject)["_dd_items"].Arr
	require.Len(t, arr, 2)
	require.Equal(t, 4, arr[0]["_dd__default"].Line)
	require.Equal(t, 7, arr[1]["_dd__default"].Line)
}

func TestSetLineInfoValuesNeverTakeKeyLines(t *testing.T) {
	src := []byte(`{
  "description": "egress",
  "egress": [
    {
      "cidr_blocks": ["0.0.0.0/0"]
    }
  ],
  "ingress": [
    {
      "cidr_blocks": ["10.0.0.0/8"],
      "description": "self",
      "self": false
    },
    {
      "cidr_blocks": ["0.0.0.0/0"],
      "description": "ssh",
      "self": true
    }
  ]
}`)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(src, &doc))
	table := initializeJSONLine(src).setLineInfo(doc)["_dd_lines"].(map[string]*model.LineObject)
	require.Equal(t, 3, table["_dd_egress"].Line)
	ingress := table["_dd_ingress"].Arr
	require.Len(t, ingress, 2)
	require.Equal(t, 12, ingress[0]["_dd_self"].Line)
	require.Equal(t, 15, ingress[1]["_dd__default"].Line)
	require.Equal(t, 17, ingress[1]["_dd_self"].Line)
	require.Equal(t, 15, ingress[1]["_dd_cidr_blocks"].Line)
}

func TestSetLineInfoListElementsAfterEqualValue(t *testing.T) {
	src := []byte(`{
  "default_action": [
    {
      "type": "redirect"
    },
    {
      "redirect": [
        {
          "port": "443"
        }
      ],
      "type": "forward"
    }
  ]
}`)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(src, &doc))
	actions := initializeJSONLine(src).setLineInfo(doc)["_dd_lines"].(map[string]*model.LineObject)["_dd_default_action"].Arr
	require.Len(t, actions, 2)
	require.Equal(t, 4, actions[0]["_dd_type"].Line)
	require.Nil(t, actions[0]["_dd_redirect"])
	require.Equal(t, 7, actions[1]["_dd_redirect"].Line)
	require.Equal(t, 9, actions[1]["_dd_redirect"].Arr[0]["_dd_port"].Line)
}

func TestSetLineInfoNestedListsKeepElementIndexes(t *testing.T) {
	src := []byte(`{
  "matrix": [
    [
      "a"
    ],
    "b"
  ]
}`)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(src, &doc))
	arr := initializeJSONLine(src).setLineInfo(doc)["_dd_lines"].(map[string]*model.LineObject)["_dd_matrix"].Arr
	require.Len(t, arr, 2)
	require.Equal(t, 3, arr[0]["_dd__default"].Line)
	require.Equal(t, 4, arr[0]["_dd__default"].Arr[0]["_dd__default"].Line)
	require.Equal(t, 6, arr[1]["_dd__default"].Line)
}
