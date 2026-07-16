/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

func TestGetLineBySearchLine_PerPlatform(t *testing.T) {
	tests := []struct {
		name string
		path []string
		doc  map[string]interface{}
		want int
	}{
		{
			name: "whole document",
			path: []string{},
			doc:  map[string]interface{}{},
			want: 1,
		},
		{
			// Terraform: intermediate "resource"/"<type>" maps carry no _dd_lines;
			// the walker descends through them to the resource body and resolves
			// the attribute from that body's _dd_lines.
			name: "terraform attribute through wrapper maps",
			path: []string{"resource", "aws_s3_bucket", "b", "acl"},
			doc: map[string]interface{}{
				"resource": map[string]interface{}{
					"aws_s3_bucket": map[string]interface{}{
						"b": map[string]interface{}{
							"_dd_lines": map[string]interface{}{
								"_dd__default": map[string]interface{}{"_dd_line": 1},
								"_dd_acl":      map[string]interface{}{"_dd_line": 3},
							},
							"acl": "public-read",
						},
					},
				},
			},
			want: 3,
		},
		{
			name: "terraform plan singleton set without index",
			path: []string{"resource", "aws_default_security_group", "default", "egress", "cidr_blocks"},
			doc: map[string]interface{}{
				"resource": map[string]interface{}{
					"aws_default_security_group": map[string]interface{}{
						"default": map[string]interface{}{
							"_dd_lines": map[string]interface{}{
								"_dd_egress": map[string]interface{}{
									"_dd_line": 15,
									"_dd_arr": []interface{}{
										map[string]interface{}{
											"_dd__default":    map[string]interface{}{"_dd_line": 15},
											"_dd_cidr_blocks": map[string]interface{}{"_dd_line": 17},
										},
									},
									"_dd_lines": map[string]interface{}{
										"_dd_constant_value": map[string]interface{}{"_dd_line": 282},
									},
								},
							},
							"egress": []interface{}{
								map[string]interface{}{"cidr_blocks": []interface{}{"0.0.0.0/0"}},
							},
						},
					},
				},
			},
			want: 17,
		},
		{
			// Terraform: absent attribute backs off to the resource body line.
			name: "terraform missing attribute backs off to block",
			path: []string{"resource", "aws_s3_bucket", "b", "versioning", "enabled"},
			doc: map[string]interface{}{
				"resource": map[string]interface{}{
					"aws_s3_bucket": map[string]interface{}{
						"b": map[string]interface{}{
							"_dd_lines": map[string]interface{}{
								"_dd__default": map[string]interface{}{"_dd_line": 1},
								"_dd_acl":      map[string]interface{}{"_dd_line": 3},
							},
							"acl": "public-read",
						},
					},
				},
			},
			want: 1,
		},
		{
			// CloudFormation / generic YAML-JSON nesting.
			name: "cloudformation nested properties",
			path: []string{"Resources", "MyBucket", "Properties", "VersioningConfiguration"},
			doc: map[string]interface{}{
				"Resources": map[string]interface{}{
					"_dd_lines": map[string]interface{}{
						"_dd__default": map[string]interface{}{"_dd_line": 1},
						"_dd_MyBucket": map[string]interface{}{"_dd_line": 2},
					},
					"MyBucket": map[string]interface{}{
						"_dd_lines": map[string]interface{}{
							"_dd__default":   map[string]interface{}{"_dd_line": 2},
							"_dd_Properties": map[string]interface{}{"_dd_line": 4},
						},
						"Properties": map[string]interface{}{
							"_dd_lines": map[string]interface{}{
								"_dd__default":                map[string]interface{}{"_dd_line": 4},
								"_dd_VersioningConfiguration": map[string]interface{}{"_dd_line": 6},
							},
							"VersioningConfiguration": map[string]interface{}{"Status": "Enabled"},
						},
					},
				},
			},
			want: 6,
		},
		{
			// Kubernetes: sequence element addressed via _dd_arr.
			name: "kubernetes container securityContext",
			path: []string{"spec", "containers", "0", "securityContext", "privileged"},
			doc: map[string]interface{}{
				"spec": map[string]interface{}{
					"_dd_lines": map[string]interface{}{
						"_dd__default": map[string]interface{}{"_dd_line": 5},
						"_dd_containers": map[string]interface{}{
							"_dd_line": 6,
							"_dd_arr": []interface{}{
								map[string]interface{}{
									"_dd__default":        map[string]interface{}{"_dd_line": 7},
									"_dd_securityContext": map[string]interface{}{"_dd_line": 9},
								},
							},
						},
					},
					"containers": []interface{}{
						map[string]interface{}{
							"securityContext": map[string]interface{}{
								"_dd_lines": map[string]interface{}{
									"_dd__default":   map[string]interface{}{"_dd_line": 9},
									"_dd_privileged": map[string]interface{}{"_dd_line": 10},
								},
								"privileged": true,
							},
						},
					},
				},
			},
			want: 10,
		},
		{
			// Dockerfile: line info is inline on the command element, no _dd_lines.
			name: "dockerfile inline command line",
			path: []string{"command", "ubuntu:latest", "1", "Value"},
			doc: map[string]interface{}{
				"command": map[string]interface{}{
					"ubuntu:latest": []interface{}{
						map[string]interface{}{"Cmd": "from", "_dd_line": 1},
						map[string]interface{}{"Cmd": "run", "_dd_line": 3},
					},
				},
			},
			want: 3,
		},
		{
			// Ansible flat playbook: root sequence element lines live under
			// _dd__default._dd_arr (getSeqLines) rather than a named key.
			name: "ansible root sequence task",
			path: []string{"playbooks", "0", "name"},
			doc: map[string]interface{}{
				"_dd_lines": map[string]interface{}{
					"_dd__default": map[string]interface{}{
						"_dd_arr": []interface{}{
							map[string]interface{}{
								"_dd__default": map[string]interface{}{"_dd_line": 2},
								"_dd_name":     map[string]interface{}{"_dd_line": 2},
							},
						},
					},
				},
				"playbooks": []interface{}{
					map[string]interface{}{"name": "install nginx"},
				},
			},
			want: 2,
		},
		{
			// CICD (GitHub Actions): nested job step, generic YAML nesting + _dd_arr.
			name: "cicd job step run",
			path: []string{"jobs", "build", "steps", "0", "run"},
			doc: map[string]interface{}{
				"jobs": map[string]interface{}{
					"_dd_lines": map[string]interface{}{
						"_dd__default": map[string]interface{}{"_dd_line": 3},
						"_dd_build":    map[string]interface{}{"_dd_line": 4},
					},
					"build": map[string]interface{}{
						"_dd_lines": map[string]interface{}{
							"_dd__default": map[string]interface{}{"_dd_line": 4},
							"_dd_steps": map[string]interface{}{
								"_dd_line": 5,
								"_dd_arr": []interface{}{
									map[string]interface{}{
										"_dd__default": map[string]interface{}{"_dd_line": 6},
										"_dd_run":      map[string]interface{}{"_dd_line": 6},
									},
								},
							},
						},
						"steps": []interface{}{
							map[string]interface{}{"run": "make build"},
						},
					},
				},
			},
			want: 6,
		},
		{
			name: "terraform jsonencode nested object metadata",
			path: []string{"resource", "aws_iam_policy", "p", "policy", "Statement", "0", "Action"},
			doc: map[string]interface{}{
				"resource": map[string]interface{}{
					"aws_iam_policy": map[string]interface{}{
						"p": map[string]interface{}{
							"_dd_lines": map[string]interface{}{
								"_dd__default": map[string]interface{}{"_dd_line": 1},
								"_dd_policy": map[string]interface{}{
									"_dd_line": 3,
									"_dd_lines": map[string]interface{}{
										"_dd__default": map[string]interface{}{"_dd_line": 3},
										"_dd_Statement": map[string]interface{}{
											"_dd_line": 5,
											"_dd_arr": []interface{}{
												map[string]interface{}{
													"_dd__default": map[string]interface{}{"_dd_line": 6},
													"_dd_Action":   map[string]interface{}{"_dd_line": 8},
												},
											},
										},
									},
								},
							},
							"policy": `{"Statement":[{"Action":"*"}]}`,
						},
					},
				},
			},
			want: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &model.FileMetadata{LineInfoDocument: tt.doc}
			got, err := GetLineBySearchLine(tt.path, file)
			if err != nil {
				t.Fatalf("GetLineBySearchLine() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("GetLineBySearchLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectLineByPathWithoutSourceLines(t *testing.T) {
	file := &model.FileMetadata{
		FilePath: "template.yaml",
		LineInfoDocument: map[string]interface{}{
			"_dd_lines": map[string]interface{}{
				"_dd__default": map[string]interface{}{"_dd_line": 1},
				"_dd_name":     map[string]interface{}{"_dd_line": 4},
			},
			"name": "example",
		},
	}

	got := NewDetectLine(3).DetectLineByPath(context.Background(), file, model.Path{{Key: "name"}})
	if got.Line != 4 || got.ResolvedFile != file.FilePath {
		t.Fatalf("DetectLineByPath() = %+v, want line 4 in %s", got, file.FilePath)
	}
	if got.VulnLines == nil || len(*got.VulnLines) != 0 {
		t.Errorf("DetectLineByPath() source lines = %v, want empty", got.VulnLines)
	}
}

func TestDetectLineByPathUnresolvedPreservesFile(t *testing.T) {
	file := &model.FileMetadata{
		FilePath:         "positive1.ini",
		LineInfoDocument: map[string]interface{}{},
	}

	got := NewDetectLine(3).DetectLineByPath(
		context.Background(),
		file,
		model.Path{{Key: "all"}, {Key: "children"}, {Key: "tower"}, {Key: "hosts"}},
	)
	if got.Line != -1 || got.ResolvedFile != file.FilePath {
		t.Fatalf("DetectLineByPath() = %+v, want unresolved line in %s", got, file.FilePath)
	}
}

func TestGetLineByPathDistinguishesNumericKeyAndIndex(t *testing.T) {
	file := &model.FileMetadata{LineInfoDocument: map[string]interface{}{
		"values": map[string]interface{}{
			"_dd_lines": map[string]interface{}{
				"_dd_0": map[string]interface{}{"_dd_line": 4},
			},
			"0": "object value",
		},
		"items": []interface{}{map[string]interface{}{"_dd_line": 8}},
	}}
	keyLine, err := GetLineByPath(model.Path{{Key: "values"}, {Key: "0"}}, file)
	if err != nil {
		t.Fatal(err)
	}
	indexLine, err := GetLineByPath(model.Path{{Key: "items"}, {Index: 0, IsIndex: true}}, file)
	if err != nil {
		t.Fatal(err)
	}
	if keyLine != 4 || indexLine != 8 {
		t.Fatalf("numeric key line=%d, index line=%d", keyLine, indexLine)
	}
}

func TestGetLineByPathTypedMetadata(t *testing.T) {
	file := &model.FileMetadata{LineInfoDocument: map[string]interface{}{
		"_dd_lines": map[string]model.LineObject{
			"_dd_items": {
				Line: 2,
				Arr: []map[string]*model.LineObject{{
					"_dd__default": {Line: 3},
					"_dd_name":     {Line: 4},
				}},
			},
		},
		"items": []model.Document{{"name": "example"}},
	}}
	path := model.Path{{Key: "items"}, {Index: 0, IsIndex: true}, {Key: "name"}}

	line, resolution, err := GetLineByPathWithResolution(path, file)
	if err != nil {
		t.Fatal(err)
	}
	if line != 4 {
		t.Fatalf("line = %d, want 4", line)
	}
	if !resolution.StructuralExact || resolution.MatchedElements != len(path) {
		t.Fatalf("resolution = %+v, want exact", resolution)
	}
}

func TestGetLineByPathConcurrentSameFile(t *testing.T) {
	file := &model.FileMetadata{LineInfoDocument: map[string]interface{}{
		"resource": model.Document{
			"example": model.Document{
				"_dd_lines": map[string]*model.LineObject{
					"_dd__default": {Line: 5},
					"_dd_enabled":  {Line: 7},
				},
				"enabled": true,
			},
		},
	}}
	path := model.Path{{Key: "resource"}, {Key: "example"}, {Key: "enabled"}}

	const workers = 32
	const iterations = 100
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				line, resolution, err := GetLineByPathWithResolution(path, file)
				if err != nil || line != 7 || !resolution.StructuralExact {
					errs <- "unexpected concurrent path resolution"
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func BenchmarkGetLineByPathTyped(b *testing.B) {
	file := &model.FileMetadata{LineInfoDocument: map[string]interface{}{
		"_dd_lines": map[string]model.LineObject{
			"_dd_items": {
				Line: 2,
				Arr: []map[string]*model.LineObject{{
					"_dd__default": {Line: 3},
					"_dd_name":     {Line: 4},
				}},
			},
		},
		"items": []model.Document{{"name": "example"}},
	}}
	path := model.Path{{Key: "items"}, {Index: 0, IsIndex: true}, {Key: "name"}}
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = GetLineByPathWithResolution(path, file)
	}
}
