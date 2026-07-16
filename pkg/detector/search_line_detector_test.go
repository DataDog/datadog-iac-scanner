/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

func TestGetLineBySearchLine(t *testing.T) { //nolint
	type args struct {
		pathComponents []string
		file           *model.FileMetadata
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{ //nolint
			name: "test simple search line",
			args: args{
				pathComponents: []string{"father", "son", "grandson"},
				file: &model.FileMetadata{
					LineInfoDocument: map[string]interface{}{
						"_dd_lines": map[string]interface{}{
							"_dd__default": map[string]interface{}{
								"_dd_line": 0,
							},
							"_dd_father": map[string]interface{}{
								"_dd_line": 3,
							},
						},
						"father": map[string]interface{}{
							"_dd_lines": map[string]interface{}{
								"_dd__default": map[string]interface{}{
									"_dd_line": 3,
								},
								"_dd_son": map[string]interface{}{
									"_dd_line": 4,
								},
							},
							"son": map[string]interface{}{
								"_dd_lines": map[string]interface{}{
									"_dd__default": map[string]interface{}{
										"_dd_line": 4,
									},
									"_dd_grandson": map[string]interface{}{
										"_dd_line": 5,
									},
								},
								"grandson": "value",
							},
						},
					},
				},
			},
			want:    5,
			wantErr: false,
		},
		{
			name: "test with similar array elements",
			args: args{
				pathComponents: []string{"father", "1", "son"},
				file: &model.FileMetadata{
					LineInfoDocument: map[string]interface{}{
						"_dd_lines": map[string]interface{}{
							"_dd__default": map[string]interface{}{
								"_dd_line": 0,
							},
							"_dd_father": map[string]interface{}{
								"_dd_arr": []interface{}{
									map[string]interface{}{
										"_dd__default": map[string]interface{}{
											"_dd_line": 2,
										}, "_dd_son": map[string]interface{}{
											"_dd_line": 4,
										},
									},
									map[string]interface{}{
										"_dd__default": map[string]interface{}{
											"_dd_line": 2,
										},
										"_dd_son": map[string]interface{}{
											"_dd_line": 7,
										},
									},
									map[string]interface{}{
										"_dd__default": map[string]interface{}{
											"_dd_line": 2,
										},
										"_dd_son": map[string]interface{}{
											"_dd_line": 10,
										},
									},
								},
								"_dd_line": 2,
							},
						},
						"father": []interface{}{
							map[string]interface{}{
								"son": "son_1",
							},
							map[string]interface{}{
								"son": "son_2",
							},
							map[string]interface{}{
								"son": "son_3",
							},
						},
					},
				},
			},
			want:    7,
			wantErr: false,
		},
		{ //nolint
			name: "test with dots on keys",
			args: args{
				pathComponents: []string{"father", "son.name", "grandson"},
				file: &model.FileMetadata{
					LineInfoDocument: map[string]interface{}{
						"_dd_lines": map[string]interface{}{
							"_dd__default": map[string]interface{}{
								"_dd_line": 0,
							},
							"_dd_father": map[string]interface{}{
								"_dd_line": 2,
							},
						},
						"father": map[string]interface{}{
							"_dd_lines": map[string]interface{}{
								"_dd__default": map[string]interface{}{
									"_dd_line": 2,
								},
								"_dd_son.name": map[string]interface{}{
									"_dd_line": 3,
								},
							},
							"son.name": map[string]interface{}{
								"_dd_lines": map[string]interface{}{
									"_dd__default": map[string]interface{}{
										"_dd_line": 3,
									},
									"_dd_grandson": map[string]interface{}{
										"_dd_line": 4,
									},
								},
								"grandson": "value",
							},
						},
					},
				},
			},
			want:    4,
			wantErr: false,
		},
		{ //nolint
			name: "test number issue with key",
			args: args{
				pathComponents: []string{"father", "1", "grandson"},
				file: &model.FileMetadata{
					LineInfoDocument: map[string]interface{}{
						"_dd_lines": map[string]interface{}{
							"_dd__default": map[string]interface{}{
								"_dd_line": 0,
							},
							"_dd_father": map[string]interface{}{
								"_dd_line": 2,
							},
						},
						"father": map[string]interface{}{
							"_dd_lines": map[string]interface{}{
								"_dd__default": map[string]interface{}{
									"_dd_line": 2,
								},
								"_dd_son.name": map[string]interface{}{
									"_dd_line": 3,
								},
							},
							"1": map[string]interface{}{
								"_dd_lines": map[string]interface{}{
									"_dd__default": map[string]interface{}{
										"_dd_line": 3,
									},
									"_dd_grandson": map[string]interface{}{
										"_dd_line": 4,
									},
								},
								"grandson": "value",
							},
						},
					},
				},
			},
			want:    4,
			wantErr: false,
		},
		{ //nolint
			// The final path component (targetObj) must be dot-escaped too, or
			// gjson misreads a dotted key as nested paths.
			name: "test with dots on final path component",
			args: args{
				pathComponents: []string{"father", "module.staging.web"},
				file: &model.FileMetadata{
					LineInfoDocument: map[string]any{
						"_dd_lines": map[string]any{
							"_dd__default": map[string]any{
								"_dd_line": 0,
							},
							"_dd_father": map[string]any{
								"_dd_line": 2,
							},
						},
						"father": map[string]any{
							"_dd_lines": map[string]any{
								"_dd__default": map[string]any{
									"_dd_line": 2,
								},
								"_dd_module.staging.web": map[string]any{
									"_dd_line": 3,
								},
							},
							"module.staging.web": map[string]any{
								"instance_type": "t2.micro",
							},
						},
					},
				},
			},
			want:    3,
			wantErr: false,
		},
		{
			name: "test number issue with array",
			args: args{
				pathComponents: []string{"father", "son", "3"},
				file: &model.FileMetadata{
					LineInfoDocument: map[string]interface{}{
						"_dd_lines": map[string]interface{}{
							"_dd__default": map[string]interface{}{
								"_dd_line": 0,
							},
							"_dd_father": map[string]interface{}{
								"_dd_line": 2,
							},
						},
						"father": map[string]interface{}{
							"_dd_lines": map[string]interface{}{
								"_dd__default": map[string]interface{}{
									"_dd_line": 2,
								},
								"_dd_son": map[string]interface{}{
									"_dd_arr": []interface{}{
										map[string]interface{}{
											"_dd__default": map[string]interface{}{
												"_dd_line": 4,
											},
										}, map[string]interface{}{
											"_dd__default": map[string]interface{}{
												"_dd_line": 5,
											},
										}, map[string]interface{}{
											"_dd__default": map[string]interface{}{
												"_dd_line": 6,
											},
										}, map[string]interface{}{
											"_dd__default": map[string]interface{}{
												"_dd_line": 7,
											},
										},
									},
									"_dd_line": 3,
								},
							},
							"son": []interface{}{
								1,
								2,
								3,
								0,
							},
						},
					},
				},
			},
			want:    7,
			wantErr: false,
		},
		{
			name: "unresolved path returns zero",
			args: args{
				pathComponents: []string{"missing", "path"},
				file: &model.FileMetadata{
					LineInfoDocument: map[string]interface{}{},
				},
			},
			want:    0,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetLineBySearchLine(tt.args.pathComponents, tt.args.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetLineBySearchLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetLineBySearchLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJSONPathLineOffset(t *testing.T) {
	statementObject := `{
  "Version": "2012-10-17",
  "Statement": {
    "Action": "es:*",
    "Effect": "Allow"
  }
}`
	statementArray := `{
  "Statement": [
    {
      "Action": [
        "read",
        "write"
      ]
    }
  ]
}`

	tests := []struct {
		name    string
		jsonStr string
		path    []string
		want    int
	}{
		{
			name:    "bare policy field",
			jsonStr: statementObject,
			path:    []string{"Statement"},
			want:    2,
		},
		{
			name:    "virtual statement object index zero",
			jsonStr: statementObject,
			path:    []string{"Statement", "0"},
			want:    2,
		},
		{
			name:    "nested statement object action",
			jsonStr: statementObject,
			path:    []string{"Statement", "0", "Action"},
			want:    3,
		},
		{
			name:    "virtual statement object rejects index one",
			jsonStr: statementObject,
			path:    []string{"Statement", "1"},
			want:    -1,
		},
		{
			name:    "array element",
			jsonStr: statementArray,
			path:    []string{"Statement", "0"},
			want:    2,
		},
		{
			name:    "nested array element",
			jsonStr: statementArray,
			path:    []string{"Statement", "0", "Action", "1"},
			want:    5,
		},
		{
			name:    "case insensitive object keys",
			jsonStr: statementArray,
			path:    []string{"statement", "0", "action"},
			want:    3,
		},
		{
			name:    "non-numeric array index",
			jsonStr: statementArray,
			path:    []string{"Statement", "first"},
			want:    -1,
		},
		{
			name:    "negative array index",
			jsonStr: statementArray,
			path:    []string{"Statement", "-1"},
			want:    -1,
		},
		{
			name:    "array index out of bounds",
			jsonStr: statementArray,
			path:    []string{"Statement", "2"},
			want:    -1,
		},
		{
			name:    "invalid JSON",
			jsonStr: `{"Statement": [`,
			path:    []string{"Statement", "0"},
			want:    -1,
		},
		{
			name:    "empty path",
			jsonStr: statementObject,
			path:    nil,
			want:    -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := jsonPathLineOffset(tt.jsonStr, tt.path); got != tt.want {
				t.Fatalf("jsonPathLineOffset() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestGetLineBySearchLine_HeredocStatementObject(t *testing.T) {
	lines := []string{
		`module "x" {`,
		`  access_policies = <<POLICIES`,
		`{`,
		`  "Version": "2012-10-17",`,
		`  "Statement": {`,
		`    "Action": "es:*",`,
		`    "Effect": "Allow"`,
		`  }`,
		`}`,
		`POLICIES`,
		`}`,
	}
	heredocJSON := strings.Join(lines[2:8], "\n") + "\n"
	file := &model.FileMetadata{
		LineInfoDocument: map[string]interface{}{
			"module": map[string]interface{}{
				"x": map[string]interface{}{
					"_dd_lines": map[string]interface{}{
						"_dd__default": map[string]interface{}{"_dd_line": 1},
						"_dd_access_policies": map[string]interface{}{
							"_dd_line": 2,
						},
					},
					"access_policies": heredocJSON,
				},
			},
		},
		LinesOriginalData: &lines,
	}
	got, err := GetLineBySearchLine([]string{"module", "x", "access_policies", "Statement", "0"}, file)
	if err != nil {
		t.Fatal(err)
	}
	if got != 5 {
		t.Fatalf("GetLineBySearchLine() = %d, want 5", got)
	}
	path := model.Path{
		{Key: "module"},
		{Key: "x"},
		{Key: "access_policies"},
		{Key: "Statement"},
		{Index: 0, IsIndex: true},
	}
	_, resolution, err := GetLineByPathWithResolution(path, file)
	if err != nil {
		t.Fatal(err)
	}
	if !resolution.StructuralExact || resolution.MatchedElements != len(path) {
		t.Fatalf("JSON fallback resolution = %+v, want exact", resolution)
	}
}
