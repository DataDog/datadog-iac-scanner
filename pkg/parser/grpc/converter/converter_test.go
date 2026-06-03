/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package converter

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/emicklei/proto"
	"github.com/stretchr/testify/require"
)

func Test_newJSONProto(t *testing.T) {
	tests := []struct {
		name string
		want *JSONProto
	}{
		{
			name: "newJSONProto",
			want: &JSONProto{
				Messages:      make(map[string]interface{}),
				Services:      make(map[string]interface{}),
				Imports:       make(map[string]interface{}),
				Options:       make([]Option, 0),
				Enum:          make(map[string]interface{}),
				Syntax:        "",
				PackageName:   "",
				linesToIgnore: make([]int, 0),
				Lines:         make(map[string]model.LineObject),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newJSONProto(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newJSONProto() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConvert(t *testing.T) {
	tests := []struct {
		name            string
		content         []byte
		want            string
		wantIgnoreLines []int
	}{
		{
			name: "convert simple",
			content: []byte(`
			syntax = "proto3";
			`),
			wantIgnoreLines: []int(nil),
			want: `{
				"syntax": "proto3",
				"package": "",
				"messages": {
					"_dd_lines": {}
				},
				"enum": {
					"_dd_lines": {}
				},
				"services": {
					"_dd_lines": {}
				},
				"imports": {
					"_dd_lines": {}
				},
				"options": [],
				"_dd_lines": {
					"_dd__default": {
						"_dd_line":0
					},
					"_dd_syntax": {
						"_dd_line":2
					}
				}
			}`,
		},
		{
			name: "convert message oneOf and enum",
			content: []byte(`
			syntax = "proto3";
			// dd-iac-scan ignore-line
			message test{
				enum Testing {
					// dd-iac-scan ignore-line
					reserved "foo", "bar";
				}
				// dd-iac-scan ignore-block
				oneof payload {
					bytes protobuf_payload = 1;
					string json_payload = 2;
				  }
			}
			`),
			wantIgnoreLines: []int{3, 4, 6, 7, 9, 10, 11, 12},
			want: `{
				"_dd_lines": {
					"_dd_syntax": {
						"_dd_line": 2
					},
					"_dd__default": {
						"_dd_line": 0
					}
				},
				"enum": {
					"_dd_lines": {}
				},
				"imports": {
					"_dd_lines": {}
				},
				"messages": {
					"_dd_lines": {
						"_dd_test": {
							"_dd_line": 4
						}
					},
					"test": {
						"_dd_lines": {
							"_dd_Testing": {
								"_dd_line": 5
							},
							"_dd__default": {
								"_dd_line": 4
							},
							"_dd_payload": {
								"_dd_line": 10
							}
						},
						"enum": {
							"Testing": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_arr": [
											{
												"Reserved": {
													"_dd_line": 7
												}
											}
										],
										"_dd_line": 5
									}
								},
								"reserved": [
									{
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 7
											}
										},
										"fieldNames": [
											"foo",
											"bar"
										]
									}
								]
							}
						},
						"oneof": {
							"payload": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 10
									},
									"_dd_json_payload": {
										"_dd_line": 12
									},
									"_dd_protobuf_payload": {
										"_dd_line": 11
									}
								},
								"fields": {
									"json_payload": {
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 12
											}
										},
										"sequence": 2,
										"type": "string"
									},
									"protobuf_payload": {
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 11
											}
										},
										"sequence": 1,
										"type": "bytes"
									}
								}
							}
						}
					}
				},
				"options": [],
				"package": "",
				"services": {
					"_dd_lines": {}
				},
				"syntax": "proto3"
			}`,
		},
		{
			name: "convert simple message",
			content: []byte(`
			syntax = "proto3";
			message reserved {
				reserved "foo", "bar";
			}
			`),
			wantIgnoreLines: []int(nil),
			want: `{
				"_dd_lines": {
					"_dd_syntax": {
						"_dd_line": 2
					},
					"_dd__default": {
						"_dd_line": 0
					}
				},
				"enum": {
					"_dd_lines": {}
				},
				"imports": {
					"_dd_lines": {}
				},
				"messages": {
					"_dd_lines": {
						"_dd_reserved": {
							"_dd_line": 3
						}
					},
					"reserved": {
						"_dd_lines": {
							"_dd__default": {
								"_dd_arr": [
									{
										"Reserved": {
											"_dd_line": 4
										}
									}
								],
								"_dd_line": 3
							}
						},
						"reserved": [
							{
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 4
									}
								},
								"fieldNames": [
									"foo",
									"bar"
								]
							}
						]
					}
				},
				"options": [],
				"package": "",
				"services": {
					"_dd_lines": {}
				},
				"syntax": "proto3"
			}`,
		},
		{
			name: "convert complex service",
			content: []byte(`syntax = "proto3";
			package statustest;

			import "envoyproxy/protoc-gen-validate/validate/validate.proto";
			import "google/rpc/status.proto";

			package helloworld;

			service Greeter {
			  rpc SayHello (HelloRequest) returns (HelloReply) {
				option (google.api.http) = {
					post: "/service/hello"
					body: "*"
				};
			  }
			}

			message HelloRequest {
			  string name = 1  [(validate.rules).string.pattern = "^\\w+( +\\w+)*$"]; // Required. Allows multiple words with spaces in between, as it can contain both first and last name;
			}

			message HelloReply {
			  string message = 1;
			  google.rpc.Status status = 2;
			}`),
			wantIgnoreLines: []int(nil),
			want: `{
				"_dd_lines": {
					"_dd_package": {
						"_dd_line": 7
					},
					"_dd_syntax": {
						"_dd_line": 1
					},
					"_dd__default": {
						"_dd_line": 0
					}
				},
				"enum": {
					"_dd_lines": {}
				},
				"imports": {
					"_dd_lines": {
						"_dd_envoyproxy/protoc-gen-validate/validate/validate.proto": {
							"_dd_line": 4
						},
						"_dd_google/rpc/status.proto": {
							"_dd_line": 5
						}
					},
					"envoyproxy/protoc-gen-validate/validate/validate.proto": {},
					"google/rpc/status.proto": {}
				},
				"messages": {
					"HelloReply": {
						"_dd_lines": {
							"_dd__default": {
								"_dd_line": 22
							},
							"_dd_message": {
								"_dd_line": 23
							},
							"_dd_status": {
								"_dd_line": 24
							}
						},
						"field": {
							"message": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 23
									}
								},
								"sequence": 1,
								"type": "string"
							},
							"status": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 24
									}
								},
								"sequence": 2,
								"type": "google.rpc.Status"
							}
						}
					},
					"HelloRequest": {
						"_dd_lines": {
							"_dd__default": {
								"_dd_line": 18
							},
							"_dd_name": {
								"_dd_line": 19
							}
						},
						"field": {
							"name": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 19
									}
								},
								"options": [
									{
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 19
											}
										},
										"constant": {
											"_dd_lines": {
												"_dd__default": {
													"_dd_line": 19
												}
											},
											"isString": true,
											"quoteRune": 34,
											"source": "^\\\\w+( +\\\\w+)*$"
										},
										"isEmbedded": true,
										"name": "(validate.rules).string.pattern"
									}
								],
								"sequence": 1,
								"type": "string"
							}
						}
					},
					"_dd_lines": {
						"_dd_HelloReply": {
							"_dd_line": 22
						},
						"_dd_HelloRequest": {
							"_dd_line": 18
						}
					}
				},
				"options": [],
				"package": "helloworld",
				"services": {
					"Greeter": {
						"_dd_lines": {
							"_dd_SayHello": {
								"_dd_line": 10
							},
							"_dd__default": {
								"_dd_line": 9
							}
						},
						"rpc": {
							"SayHello": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 10
									}
								},
								"options": [
									{
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 11
											}
										},
										"constant": {
											"_dd_lines": {
												"_dd__default": {
													"_dd_line": 11
												}
											},
											"map": {
												"body": {
													"_dd_lines": {
														"_dd__default": {
															"_dd_line": 13
														}
													},
													"isString": true,
													"quoteRune": 34,
													"source": "*"
												},
												"post": {
													"_dd_lines": {
														"_dd__default": {
															"_dd_line": 12
														}
													},
													"isString": true,
													"quoteRune": 34,
													"source": "/service/hello"
												}
											},
											"orderedMap": [
												{
													"_dd_lines": {
														"_dd__default": {
															"_dd_line": 12
														}
													},
													"isString": true,
													"name": "post",
													"quoteRune": 34,
													"source": "/service/hello"
												},
												{
													"_dd_lines": {
														"_dd__default": {
															"_dd_line": 13
														}
													},
													"isString": true,
													"name": "body",
													"quoteRune": 34,
													"source": "*"
												}
											]
										},
										"name": "(google.api.http)"
									}
								],
								"requestType": "HelloRequest",
								"returnsType": "HelloReply"
							}
						}
					},
					"_dd_lines": {
						"_dd_Greeter": {
							"_dd_line": 9
						}
					}
				},
				"syntax": "proto3"
			}`,
		},
		{
			name: "convert complex",
			content: []byte(`syntax = "proto3";
			package Cx;
			import public "other.proto";
			option java_package = "com.example.foo";
			enum EnumAllowingAlias {
			  option allow_alias = true;
			  UNKNOWN = 0;
			  STARTED = 1;
			  RUNNING = 2 [(custom_option) = "hello world"];
			}
			message Outer {
			  option (my_option).a = true;
			  message Inner {   // Level 2
				int64 ival = 1;
			  }
			  repeated Inner inner_message = 2;
			  EnumAllowingAlias enum_field =3;
			  map<int32, string> my_map = 4;
			}`),
			wantIgnoreLines: []int(nil),
			want: `{
				"_dd_lines": {
					"_dd_package": {
						"_dd_line": 2
					},
					"_dd_syntax": {
						"_dd_line": 1
					},
					"_dd__default": {
						"_dd_arr": [
							{
								"java_package": {
									"_dd_line": 4
								}
							}
						],
						"_dd_line": 0
					}
				},
				"enum": {
					"EnumAllowingAlias": {
						"_dd_lines": {
							"_dd_RUNNING": {
								"_dd_line": 9
							},
							"_dd_STARTED": {
								"_dd_line": 8
							},
							"_dd_UNKNOWN": {
								"_dd_line": 7
							},
							"_dd__default": {
								"_dd_line": 5
							},
							"_dd_allow_alias": {
								"_dd_line": 6
							}
						},
						"field": {
							"RUNNING": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 9
									}
								},
								"options": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 9
										}
									},
									"constant": {
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 9
											}
										},
										"isString": true,
										"quoteRune": 34,
										"source": "hello world"
									},
									"isEmbedded": true,
									"name": "(custom_option)"
								},
								"value": 2
							},
							"STARTED": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 8
									}
								},
								"options": {
									"constant": {}
								},
								"value": 1
							},
							"UNKNOWN": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 7
									}
								},
								"options": {
									"constant": {}
								}
							}
						},
						"options": {
							"allow_alias": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 6
									}
								},
								"constant": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 6
										}
									},
									"source": "true"
								},
								"name": "allow_alias"
							}
						}
					},
					"_dd_lines": {
						"_dd_EnumAllowingAlias": {
							"_dd_line": 5
						}
					}
				},
				"imports": {
					"_dd_lines": {
						"_dd_other.proto": {
							"_dd_line": 3
						}
					},
					"other.proto": {
						"kind": "public"
					}
				},
				"messages": {
					"Outer": {
						"_dd_lines": {
							"_dd_(my_option).a": {
								"_dd_line": 12
							},
							"_dd_Inner": {
								"_dd_line": 13
							},
							"_dd__default": {
								"_dd_line": 11
							},
							"_dd_enum_field": {
								"_dd_line": 17
							},
							"_dd_inner_message": {
								"_dd_line": 16
							},
							"_dd_my_map": {
								"_dd_line": 18
							}
						},
						"field": {
							"enum_field": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 17
									}
								},
								"sequence": 3,
								"type": "EnumAllowingAlias"
							},
							"inner_message": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 16
									}
								},
								"repeated": true,
								"sequence": 2,
								"type": "Inner"
							}
						},
						"inner_message": {
							"Inner": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 13
									},
									"_dd_ival": {
										"_dd_line": 14
									}
								},
								"field": {
									"ival": {
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 14
											}
										},
										"sequence": 1,
										"type": "int64"
									}
								}
							}
						},
						"map": {
							"my_map": {
								"field": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 18
										}
									},
									"sequence": 4,
									"type": "string"
								},
								"key_type": "int32"
							}
						},
						"options": {
							"(my_option).a": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 12
									}
								},
								"constant": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 12
										}
									},
									"source": "true"
								},
								"name": "(my_option).a"
							}
						}
					},
					"_dd_lines": {
						"_dd_Outer": {
							"_dd_line": 11
						}
					}
				},
				"options": [
					{
						"_dd_lines": {
							"_dd__default": {
								"_dd_line": 4
							}
						},
						"constant": {
							"_dd_lines": {
								"_dd__default": {
									"_dd_line": 4
								}
							},
							"isString": true,
							"quoteRune": 34,
							"source": "com.example.foo"
						},
						"name": "java_package"
					}
				],
				"package": "Cx",
				"services": {
					"_dd_lines": {}
				},
				"syntax": "proto3"
			}`,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.content)
			parserProto := proto.NewParser(reader)
			nodes, err := parserProto.Parse()
			require.NoError(t, err)
			got, ignore := Convert(ctx, nodes)
			require.Equal(t, tt.wantIgnoreLines, ignore)
			gotString, err := json.Marshal(got)
			require.NoError(t, err)
			require.JSONEq(t, tt.want, string(gotString))

		})
	}
}
