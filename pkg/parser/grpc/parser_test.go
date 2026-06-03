/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package grpc

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// TestParser_Parse tests the parsing of a grpc file.
func TestParser_Parse(t *testing.T) {
	type args struct {
		in0         string
		fileContent []byte
	}
	tests := []struct {
		name    string
		p       *Parser
		args    args
		want    string
		want1   []int
		wantErr bool
	}{
		{
			name: "grpc simple parse",
			p:    &Parser{},
			args: args{
				in0: "test.proto",
				fileContent: []byte(`
				syntax = "proto3";
				`),
			},
			want: `[
				{
					"options": [],
					"_dd_lines": {
						"_dd_syntax": {
							"_dd_line": 2
						},
						"_dd__default": {
							"_dd_line": 0
						}
					},
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
					}
				}
			]`,
			want1:   []int(nil),
			wantErr: false,
		},
		{
			name: "grpc complex file",
			p:    &Parser{},
			args: args{
				in0: "test.proto",
				fileContent: []byte(`syntax = "proto3";
				package Cx;
				import public "other.proto";
				option java_package = "com.example.foo";
				// dd-iac-scan ignore-block
				enum EnumAllowingAlias {
				  option allow_alias = true;
				  UNKNOWN = 0;
				  STARTED = 1;
				  RUNNING = 2 [(custom_option) = "hello world"];
				}
				message Outer {
				  // dd-iac-scan ignore-line
				  option (my_option).a = true;
				  message Inner {   // Level 2
					int64 ival = 1;
				  }
				  repeated Inner inner_message = 2;
				  EnumAllowingAlias enum_field =3;
				  // dd-iac-scan ignore-line
				  map<int32, string> my_map = 4;
				}`),
			},
			want: `[
				{
					"enum": {
						"EnumAllowingAlias": {
							"_dd_lines": {
								"_dd_RUNNING": {
									"_dd_line": 10
								},
								"_dd_STARTED": {
									"_dd_line": 9
								},
								"_dd_UNKNOWN": {
									"_dd_line": 8
								},
								"_dd__default": {
									"_dd_line": 6
								},
								"_dd_allow_alias": {
									"_dd_line": 7
								}
							},
							"field": {
								"RUNNING": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 10
										}
									},
									"options": {
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 10
											}
										},
										"constant": {
											"_dd_lines": {
												"_dd__default": {
													"_dd_line": 10
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
											"_dd_line": 9
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
											"_dd_line": 8
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
											"_dd_line": 7
										}
									},
									"constant": {
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 7
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
								"_dd_line": 6
							}
						}
					},
					"services": {
						"_dd_lines": {}
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
					"syntax": "proto3",
					"package": "Cx",
					"messages": {
						"Outer": {
							"_dd_lines": {
								"_dd_(my_option).a": {
									"_dd_line": 14
								},
								"_dd_Inner": {
									"_dd_line": 15
								},
								"_dd__default": {
									"_dd_line": 12
								},
								"_dd_enum_field": {
									"_dd_line": 19
								},
								"_dd_inner_message": {
									"_dd_line": 18
								},
								"_dd_my_map": {
									"_dd_line": 21
								}
							},
							"field": {
								"enum_field": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 19
										}
									},
									"sequence": 3,
									"type": "EnumAllowingAlias"
								},
								"inner_message": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 18
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
											"_dd_line": 15
										},
										"_dd_ival": {
											"_dd_line": 16
										}
									},
									"field": {
										"ival": {
											"_dd_lines": {
												"_dd__default": {
													"_dd_line": 16
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
												"_dd_line": 21
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
											"_dd_line": 14
										}
									},
									"constant": {
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 14
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
								"_dd_line": 12
							}
						}
					}
				}
			]`,
			want1:   []int{5, 6, 7, 8, 9, 10, 13, 14, 20, 21},
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{}
			_, got, got1, _, err := p.Parse(ctx, tt.args.fileContent, tt.args.in0, true, 15)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parser.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotString, err := json.Marshal(got)
			require.NoError(t, err)
			require.JSONEq(t, tt.want, string(gotString))
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("Parser.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

// TestParser_GetKind tests the GetKind function
func TestParser_GetKind(t *testing.T) {
	tests := []struct {
		name string
		p    *Parser
		want model.FileKind
	}{
		{
			name: "grpc kind",
			p:    &Parser{},
			want: model.KindPROTO,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{}
			if got := p.GetKind(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parser.GetKind() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParser_SupportedExtensions tests the SupportedExtensions function
func TestParser_SupportedExtensions(t *testing.T) {
	tests := []struct {
		name string
		p    *Parser
		want []string
	}{
		{
			name: "grpc extensions",
			p:    &Parser{},
			want: []string{".proto"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{}
			if got := p.SupportedExtensions(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parser.SupportedExtensions() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParser_SupportedTypes tests the SupportedTypes function
func TestParser_SupportedTypes(t *testing.T) {
	tests := []struct {
		name string
		p    *Parser
		want map[string]bool
	}{
		{
			name: "grpc types",
			p:    &Parser{},
			want: map[string]bool{"grpc": true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{}
			if got := p.SupportedTypes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parser.SupportedTypes() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParser_GetCommentToken tests the GetCommentToken function
func TestParser_GetCommentToken(t *testing.T) {
	tests := []struct {
		name string
		p    *Parser
		want string
	}{
		{
			name: "grpc comment token",
			p:    &Parser{},
			want: "//",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{}
			if got := p.GetCommentToken(); got != tt.want {
				t.Errorf("Parser.GetCommentToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParser_StringifyContent tests the StringifyContent function
func TestParser_StringifyContent(t *testing.T) {
	type args struct {
		content []byte
	}
	tests := []struct {
		name    string
		p       *Parser
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "grpc stringify content",
			p:    &Parser{},
			args: args{
				content: []byte(`
syntax = "proto3";
import "google/protobuf/descriptor.proto";`),
			},
			want: `
syntax = "proto3";
import "google/protobuf/descriptor.proto";`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{}
			got, err := p.StringifyContent(tt.args.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parser.StringifyContent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Parser.StringifyContent() = %v, want %v", got, tt.want)
			}
		})
	}
}
