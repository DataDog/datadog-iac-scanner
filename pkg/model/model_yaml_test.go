/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	json "encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type args struct {
	value *yaml.Node
}

/*
=============== TEST CASES ===================
===================#1=========================
key: false
key_object:
	null_object: null
	int_object: 24
	seq_object:
		- key_seq: key_val
	  	key_seq_2: key_val_2
		- second_key: second_val
      	second_key_2: second_val_2

===================#2=========================

- name: ansible
ansible_object:
name: object
- name: ansible_2
ansible_object_2:
name: object_2

===================#3=========================

array:
	- case1
	- case2
	- case3

=============== TEST CASES ===================
*/

var tests = []struct {
	name    string
	m       *Document
	args    args
	wantErr bool
	want    string
}{
	{
		name: "test simple unmarshal",
		args: args{
			value: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{
						Kind:  yaml.ScalarNode,
						Value: "key",
						Line:  1,
					},
					{
						Kind:  yaml.ScalarNode,
						Value: "false",
						Tag:   "!!bool",
					},
					{
						Kind:  yaml.ScalarNode,
						Value: "key_object",
						Line:  2,
					},
					{
						Kind: yaml.MappingNode,
						Content: []*yaml.Node{
							{
								Kind:  yaml.ScalarNode,
								Value: "null_object",
								Line:  3,
							},
							{
								Kind: yaml.ScalarNode,
								Tag:  "!!null",
							},
							{
								Kind:  yaml.ScalarNode,
								Value: "int_object",
								Line:  4,
							},
							{
								Kind:  yaml.ScalarNode,
								Tag:   "!!int",
								Value: "24",
							},
							{
								Kind:  yaml.ScalarNode,
								Value: "seq_object",
								Line:  5,
							},
							{
								Kind: yaml.SequenceNode,
								Content: []*yaml.Node{
									{
										Kind: yaml.MappingNode,
										Content: []*yaml.Node{
											{
												Kind:  yaml.ScalarNode,
												Value: "key_seq",
												Line:  6,
											},
											{
												Kind:  yaml.ScalarNode,
												Value: "key_val",
												Tag:   " !!str",
											},
											{
												Kind:  yaml.ScalarNode,
												Value: "key_seq_2",
												Line:  7,
											},
											{
												Kind:  yaml.ScalarNode,
												Value: "key_val_2",
												Tag:   " !!str",
											},
										},
									},
									{
										Kind: yaml.MappingNode,
										Content: []*yaml.Node{
											{
												Kind:  yaml.ScalarNode,
												Value: "second_key",
												Line:  8,
											},
											{
												Kind:  yaml.ScalarNode,
												Value: "second_val",
												Tag:   " !!str",
											},
											{
												Kind:  yaml.ScalarNode,
												Value: "second_key_2",
												Line:  9,
											},
											{
												Kind:  yaml.ScalarNode,
												Value: "second_val_2",
												Tag:   " !!str",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		m:       &Document{},
		wantErr: false,
		want: `{
			"_kics_lines": {
			  "_kics__default": {
				"_kics_line": 0
			  },
			  "_kics_key": {
				"_kics_line": 1
			  },
			  "_kics_key_object": {
				"_kics_line": 2
			  }
			},
			"key": false,
			"key_object": {
			  "_kics_lines": {
				"_kics__default": {
				  "_kics_line": 2
				},
				"_kics_int_object": {
				  "_kics_line": 4
				},
				"_kics_null_object": {
				  "_kics_line": 3
				},
				"_kics_seq_object": {
				  "_kics_arr": [
					{
					  "_kics__default": {
						"_kics_line": 6
					  },
					  "_kics_key_seq": {
						"_kics_line": 6
					  },
					  "_kics_key_seq_2": {
						"_kics_line": 7
					  }
					},
					{
					  "_kics__default": {
						"_kics_line": 8
					  },
					  "_kics_second_key": {
						"_kics_line": 8
					  },
					  "_kics_second_key_2": {
						"_kics_line": 9
					  }
					}
				  ],
				  "_kics_line": 5
				}
			  },
			  "int_object": 24,
			  "null_object": null,
			  "seq_object": [
				{
				  "key_seq": "key_val",
				  "key_seq_2": "key_val_2"
				},
				{
				  "second_key": "second_val",
				  "second_key_2": "second_val_2"
				}
			  ]
			}
		  }
		  `,
	},
	{
		name: "test playbooks yaml",
		m:    &Document{},
		args: args{
			value: &yaml.Node{
				Kind: yaml.SequenceNode,
				Content: []*yaml.Node{
					{
						Kind: yaml.MappingNode,
						Content: []*yaml.Node{
							{
								Kind:  yaml.ScalarNode,
								Line:  1,
								Value: "name",
							},
							{
								Kind:  yaml.ScalarNode,
								Value: "ansible",
							},
							{
								Kind:  yaml.ScalarNode,
								Value: "ansible_object",
								Line:  2,
							},
							{
								Kind: yaml.MappingNode,
								Content: []*yaml.Node{
									{
										Kind:  yaml.ScalarNode,
										Value: "name",
										Line:  3,
									},
									{
										Kind:  yaml.ScalarNode,
										Value: "object",
									},
								},
							},
						},
					},
					{
						Kind: yaml.MappingNode,
						Content: []*yaml.Node{
							{
								Kind:  yaml.ScalarNode,
								Line:  4,
								Value: "name",
							},
							{
								Kind:  yaml.ScalarNode,
								Value: "ansible_2",
							},
							{
								Kind:  yaml.ScalarNode,
								Value: "ansible_object_2",
								Line:  5,
							},
							{
								Kind: yaml.MappingNode,
								Content: []*yaml.Node{
									{
										Kind:  yaml.ScalarNode,
										Value: "name",
										Line:  6,
									},
									{
										Kind:  yaml.ScalarNode,
										Value: "object_2",
									},
								},
							},
						},
					},
				},
			},
		},
		wantErr: false,
		want: `{
			"_kics_lines": {
			  "_kics__default": {
				"_kics_arr": [
				  {
					"_kics__default": {
					  "_kics_line": 0
					},
					"_kics_ansible_object": {
					  "_kics_line": 2
					},
					"_kics_name": {
					  "_kics_line": 1
					}
				  },
				  {
					"_kics__default": {
					  "_kics_line": 0
					},
					"_kics_ansible_object_2": {
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
				"ansible_object": {
				  "_kics_lines": {
					"_kics__default": {
					  "_kics_line": 2
					},
					"_kics_name": {
					  "_kics_line": 3
					}
				  },
				  "name": "object"
				},
				"name": "ansible"
			  },
			  {
				"ansible_object_2": {
				  "_kics_lines": {
					"_kics__default": {
					  "_kics_line": 5
					},
					"_kics_name": {
					  "_kics_line": 6
					}
				  },
				  "name": "object_2"
				},
				"name": "ansible_2"
			  }
			]
		  }
		  `,
	},
	{
		name:    "test array scalar nodes",
		m:       &Document{},
		wantErr: false,
		args: args{
			value: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{
						Kind:  yaml.ScalarNode,
						Value: "array",
						Line:  1,
					},
					{
						Kind: yaml.SequenceNode,
						Content: []*yaml.Node{
							{
								Kind:  yaml.ScalarNode,
								Tag:   "!!str",
								Value: "case1",
								Line:  2,
							},
							{
								Kind:  yaml.ScalarNode,
								Tag:   "!!str",
								Value: "case2",
								Line:  3,
							},
							{
								Kind:  yaml.ScalarNode,
								Tag:   "!!str",
								Value: "case3",
								Line:  4,
							},
						},
					},
				},
			},
		},
		want: `{
			"_kics_lines": {
			  "_kics__default": {
				"_kics_line": 0
			  },
			  "_kics_array": {
				"_kics_arr": [
				  {
					"_kics__default": {
					  "_kics_line": 2
					}
				  },
				  {
					"_kics__default": {
					  "_kics_line": 3
					}
				  },
				  {
					"_kics__default": {
					  "_kics_line": 4
					}
				  }
				],
				"_kics_line": 1
			  }
			},
			"array": [
			  "case1",
			  "case2",
			  "case3"
			]
		  }
		  `,
	},
	{
		name:    "test scalar integer formats (hex, octal, binary, underscores)",
		m:       &Document{},
		wantErr: false,
		args: args{
			value: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "hex_int", Line: 1},
					{Kind: yaml.ScalarNode, Tag: "!!int", Value: "0x1A", Line: 1},
					{Kind: yaml.ScalarNode, Value: "octal_int", Line: 2},
					{Kind: yaml.ScalarNode, Tag: "!!int", Value: "0o755", Line: 2},
					{Kind: yaml.ScalarNode, Value: "binary_int", Line: 3},
					{Kind: yaml.ScalarNode, Tag: "!!int", Value: "0b1010", Line: 3},
					{Kind: yaml.ScalarNode, Value: "underscored_int", Line: 4},
					{Kind: yaml.ScalarNode, Tag: "!!int", Value: "1_000_000", Line: 4},
				},
			},
		},
		want: `{
			"_kics_lines": {
			  "_kics__default": {"_kics_line": 0},
			  "_kics_hex_int": {"_kics_line": 1},
			  "_kics_octal_int": {"_kics_line": 2},
			  "_kics_binary_int": {"_kics_line": 3},
			  "_kics_underscored_int": {"_kics_line": 4}
			},
			"hex_int": 26,
			"octal_int": 493,
			"binary_int": 10,
			"underscored_int": 1000000
		  }`,
	},
	{
		name:    "test float scalar",
		m:       &Document{},
		wantErr: false,
		args: args{
			value: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "ratio", Line: 1},
					{Kind: yaml.ScalarNode, Tag: "!!float", Value: "3.14", Line: 1},
					{Kind: yaml.ScalarNode, Value: "count", Line: 2},
					{Kind: yaml.ScalarNode, Tag: "!!int", Value: "42", Line: 2},
				},
			},
		},
		want: `{
			"_kics_lines": {
			  "_kics__default": {"_kics_line": 0},
			  "_kics_ratio": {"_kics_line": 1},
			  "_kics_count": {"_kics_line": 2}
			},
			"ratio": 3.14,
			"count": 42
		  }`,
	},
	{
		name:    "test bool and null scalars",
		m:       &Document{},
		wantErr: false,
		args: args{
			value: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "enabled", Line: 1},
					{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true", Line: 1},
					{Kind: yaml.ScalarNode, Value: "disabled", Line: 2},
					{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false", Line: 2},
					{Kind: yaml.ScalarNode, Value: "empty", Line: 3},
					{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null", Line: 3},
				},
			},
		},
		want: `{
			"_kics_lines": {
			  "_kics__default": {"_kics_line": 0},
			  "_kics_enabled": {"_kics_line": 1},
			  "_kics_disabled": {"_kics_line": 2},
			  "_kics_empty": {"_kics_line": 3}
			},
			"enabled": true,
			"disabled": false,
			"empty": null
		  }`,
	},
}

func TestDocument_UnmarshalYAML(t *testing.T) {
	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.m.UnmarshalYAML(ctx, tt.args.value, nil); (err != nil) != tt.wantErr {
				t.Errorf("Document.UnmarshalYAML() error = %v, wantErr %v", err, tt.wantErr)
			}
			compareJSONLine(t, tt.m, tt.want)
		})
	}
}

func compareJSONLine(t *testing.T, test1 interface{}, test2 string) {
	stringefiedJSON, err := json.Marshal(&test1)
	require.NoError(t, err)
	require.JSONEq(t, test2, string(stringefiedJSON))
}

func TestDocument_UnmarshalYAML_CircularReference(t *testing.T) {
	// Create nodes that will form a circular reference via aliases
	node1 := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{
				Kind:  yaml.ScalarNode,
				Value: "key1",
				Line:  1,
			},
			{
				Kind:  yaml.ScalarNode,
				Value: "value1",
			},
			{
				Kind:  yaml.ScalarNode,
				Value: "ref",
				Line:  2,
			},
			nil, // Will be set to create circular reference
		},
	}

	node2 := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{
				Kind:  yaml.ScalarNode,
				Value: "key2",
				Line:  3,
			},
			{
				Kind:  yaml.ScalarNode,
				Value: "value2",
			},
			{
				Kind:  yaml.ScalarNode,
				Value: "backref",
				Line:  4,
			},
			{
				Kind:  yaml.AliasNode,
				Alias: node1, // Creates circular reference
			},
		},
	}

	// Complete the circular reference
	node1.Content[3] = &yaml.Node{
		Kind:  yaml.AliasNode,
		Alias: node2,
	}

	// Test that the new code works correctly
	t.Run("new_code_succeeds", func(t *testing.T) {
		ctx := context.Background()
		doc := &Document{}
		ignore := &Ignore{}
		// This should not cause a stack overflow with the fix
		err := doc.UnmarshalYAML(ctx, node1, ignore)
		require.NoError(t, err)

		// Verify the document was parsed (even with nil values for circular refs)
		require.NotNil(t, doc)
	})
}

func TestDocument_UnmarshalYAML_CloudFormationShortFormIntrinsics(t *testing.T) {
	ctx := context.Background()

	type cfnCase struct {
		name     string
		yaml     string
		jsonPath []string
		want     interface{}
	}

	cases := []cfnCase{
		{
			name: "scalar !Sub",
			yaml: `Resources:
  S3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub my-app-bucket-${Owner}
`,
			jsonPath: []string{"Resources", "S3Bucket", "Properties", "BucketName"},
			want:     map[string]interface{}{"Fn::Sub": "my-app-bucket-${Owner}"},
		},
		{
			name: "scalar !Ref",
			yaml: `Resources:
  S3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref OwnerParameter
`,
			jsonPath: []string{"Resources", "S3Bucket", "Properties", "BucketName"},
			want:     map[string]interface{}{"Ref": "OwnerParameter"},
		},
		{
			name: "dotted scalar !GetAtt",
			yaml: `Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !GetAtt OtherBucket.Arn
`,
			jsonPath: []string{"Resources", "Bucket", "Properties", "BucketName"},
			want:     map[string]interface{}{"Fn::GetAtt": []interface{}{"OtherBucket", "Arn"}},
		},
		{
			name: "sequence !Sub with map of variables",
			yaml: `Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub
        - "my-app-bucket-${Env}"
        - Env: "prod"
`,
			jsonPath: []string{"Resources", "Bucket", "Properties", "BucketName"},
			want: map[string]interface{}{"Fn::Sub": []interface{}{
				"my-app-bucket-${Env}",
				map[string]interface{}{"Env": "prod"},
			}},
		},
		{
			name: "sequence !Join",
			yaml: `Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Join ["-", ["my-app", "prod"]]
`,
			jsonPath: []string{"Resources", "Bucket", "Properties", "BucketName"},
			want: map[string]interface{}{"Fn::Join": []interface{}{
				"-",
				[]interface{}{"my-app", "prod"},
			}},
		},
		{
			name: "scalar in sequence keeps short-form rewrite",
			yaml: `Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      Tags:
        - Key: Owner
          Value: !Ref OwnerParameter
`,
			jsonPath: []string{"Resources", "Bucket", "Properties", "Tags"},
			want: []interface{}{
				map[string]interface{}{
					"Key":   "Owner",
					"Value": map[string]interface{}{"Ref": "OwnerParameter"},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var root yaml.Node
			require.NoError(t, yaml.Unmarshal([]byte(tc.yaml), &root))
			require.Equal(t, yaml.DocumentNode, root.Kind)
			require.Len(t, root.Content, 1)

			doc := &Document{}
			require.NoError(t, doc.UnmarshalYAML(ctx, root.Content[0], nil))

			raw, err := json.Marshal(doc)
			require.NoError(t, err)
			var parsed map[string]interface{}
			require.NoError(t, json.Unmarshal(raw, &parsed))

			got := walkJSONPath(t, parsed, tc.jsonPath)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestDocument_UnmarshalYAML_CFNIntrinsicLineMetadata verifies that rewritten
// short-form intrinsics carry _kics_lines metadata on the wrapper map,
// matching what long-form mapping values produce.
func TestDocument_UnmarshalYAML_CFNIntrinsicLineMetadata(t *testing.T) {
	ctx := context.Background()

	src := []byte(`Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub my-app-${Env}
`)
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal(src, &root))
	require.Equal(t, yaml.DocumentNode, root.Kind)

	doc := &Document{}
	require.NoError(t, doc.UnmarshalYAML(ctx, root.Content[0], nil))

	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &parsed))

	// Walk to BucketName without stripping _kics_lines
	bucketName := parsed["Resources"].(map[string]interface{})["MyBucket"].(map[string]interface{})["Properties"].(map[string]interface{})["BucketName"]
	m, ok := bucketName.(map[string]interface{})
	require.True(t, ok, "BucketName should be a map after rewrite")
	require.Contains(t, m, "Fn::Sub", "rewritten map should have Fn::Sub key")
	require.Contains(t, m, "_kics_lines", "rewritten map should carry _kics_lines")
}

// TestDocument_UnmarshalYAML_ShortFormIntrinsicNonCloudFormation verifies that
// short-form intrinsic rewriting only applies to CloudFormation templates. A
// document without CloudFormation markers (no Resources / Transform /
// AWSTemplateFormatVersion) must keep custom-tagged scalars untouched.
func TestDocument_UnmarshalYAML_ShortFormIntrinsicNonCloudFormation(t *testing.T) {
	ctx := context.Background()

	src := []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
data:
  value: !Ref SomeKey
`)
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal(src, &root))
	require.Equal(t, yaml.DocumentNode, root.Kind)

	doc := &Document{}
	require.NoError(t, doc.UnmarshalYAML(ctx, root.Content[0], nil))

	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &parsed))

	value := parsed["data"].(map[string]interface{})["value"]
	_, isMap := value.(map[string]interface{})
	require.False(t, isMap, "non-CloudFormation document must not rewrite !Ref into a map")
}

// TestDocument_UnmarshalYAML_ShortFormIntrinsicDetectedByTransform verifies that
// a template identified only by a Transform declaration still gets short-form
// intrinsic rewriting.
func TestDocument_UnmarshalYAML_ShortFormIntrinsicDetectedByTransform(t *testing.T) {
	ctx := context.Background()

	src := []byte(`Transform: AWS::Serverless-2016-10-31
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref OwnerParameter
`)
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal(src, &root))
	require.Equal(t, yaml.DocumentNode, root.Kind)

	doc := &Document{}
	require.NoError(t, doc.UnmarshalYAML(ctx, root.Content[0], nil))

	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &parsed))

	bucketName := parsed["Resources"].(map[string]interface{})["Bucket"].(map[string]interface{})["Properties"].(map[string]interface{})["BucketName"]
	m, ok := bucketName.(map[string]interface{})
	require.True(t, ok, "CloudFormation document should rewrite !Ref into a map")
	require.Equal(t, "OwnerParameter", m["Ref"])
}

func walkJSONPath(t *testing.T, root interface{}, path []string) interface{} {
	t.Helper()
	cur := root
	for _, key := range path {
		m, ok := cur.(map[string]interface{})
		require.Truef(t, ok, "expected map at path segment %q, got %T", key, cur)
		next, exists := m[key]
		require.Truef(t, exists, "missing key %q at path; available keys: %v", key, keysOf(m))
		cur = next
	}
	return stripKicsLines(cur)
}

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func stripKicsLines(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			if k == "_kics_lines" {
				continue
			}
			out[k] = stripKicsLines(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, val := range t {
			out[i] = stripKicsLines(val)
		}
		return out
	default:
		return v
	}
}

// TestDocument_UnmarshalYAML_FromBytes verifies that parsing real YAML bytes (hex, octal, etc.)
// produces the correct numeric values via the full node pipeline (decoder sets Tag/Value, then we resolve).
func TestDocument_UnmarshalYAML_FromBytes(t *testing.T) {
	ctx := context.Background()

	yamlBytes := []byte(`
port: 0x1A
mode: 0o755
mask: 0b1111
replicas: 1_000_000
ratio: 2.5
enabled: true
`)

	var root yaml.Node
	err := yaml.Unmarshal(yamlBytes, &root)
	require.NoError(t, err)
	require.Equal(t, yaml.DocumentNode, root.Kind)
	require.Len(t, root.Content, 1)

	doc := &Document{}
	err = doc.UnmarshalYAML(ctx, root.Content[0], nil)
	require.NoError(t, err)

	// Values go through JSON round-trip so numbers become float64 in Document
	d := *doc
	require.Equal(t, float64(26), d["port"], "hex 0x1A = 26")
	require.Equal(t, float64(493), d["mode"], "octal 0o755 = 493")
	require.Equal(t, float64(15), d["mask"], "binary 0b1111 = 15")
	require.Equal(t, float64(1000000), d["replicas"], "underscored 1_000_000 = 1000000")
	require.Equal(t, 2.5, d["ratio"], "float 2.5")
	require.Equal(t, true, d["enabled"], "bool true")
}
