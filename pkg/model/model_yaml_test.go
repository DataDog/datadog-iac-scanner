/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	json "encoding/json"
	"fmt"
	"reflect"
	"strings"
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
			"_dd_lines": {
			  "_dd__default": {
				"_dd_line": 0
			  },
			  "_dd_key": {
				"_dd_line": 1
			  },
			  "_dd_key_object": {
				"_dd_line": 2
			  }
			},
			"key": false,
			"key_object": {
			  "_dd_lines": {
				"_dd__default": {
				  "_dd_line": 2
				},
				"_dd_int_object": {
				  "_dd_line": 4
				},
				"_dd_null_object": {
				  "_dd_line": 3
				},
				"_dd_seq_object": {
				  "_dd_arr": [
					{
					  "_dd__default": {
						"_dd_line": 6
					  },
					  "_dd_key_seq": {
						"_dd_line": 6
					  },
					  "_dd_key_seq_2": {
						"_dd_line": 7
					  }
					},
					{
					  "_dd__default": {
						"_dd_line": 8
					  },
					  "_dd_second_key": {
						"_dd_line": 8
					  },
					  "_dd_second_key_2": {
						"_dd_line": 9
					  }
					}
				  ],
				  "_dd_line": 5
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
			"_dd_lines": {
			  "_dd__default": {
				"_dd_arr": [
				  {
					"_dd__default": {
					  "_dd_line": 0
					},
					"_dd_ansible_object": {
					  "_dd_line": 2
					},
					"_dd_name": {
					  "_dd_line": 1
					}
				  },
				  {
					"_dd__default": {
					  "_dd_line": 0
					},
					"_dd_ansible_object_2": {
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
				"ansible_object": {
				  "_dd_lines": {
					"_dd__default": {
					  "_dd_line": 2
					},
					"_dd_name": {
					  "_dd_line": 3
					}
				  },
				  "name": "object"
				},
				"name": "ansible"
			  },
			  {
				"ansible_object_2": {
				  "_dd_lines": {
					"_dd__default": {
					  "_dd_line": 5
					},
					"_dd_name": {
					  "_dd_line": 6
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
			"_dd_lines": {
			  "_dd__default": {
				"_dd_line": 0
			  },
			  "_dd_array": {
				"_dd_arr": [
				  {
					"_dd__default": {
					  "_dd_line": 2
					}
				  },
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
				"_dd_line": 1
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
			"_dd_lines": {
			  "_dd__default": {"_dd_line": 0},
			  "_dd_hex_int": {"_dd_line": 1},
			  "_dd_octal_int": {"_dd_line": 2},
			  "_dd_binary_int": {"_dd_line": 3},
			  "_dd_underscored_int": {"_dd_line": 4}
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
			"_dd_lines": {
			  "_dd__default": {"_dd_line": 0},
			  "_dd_ratio": {"_dd_line": 1},
			  "_dd_count": {"_dd_line": 2}
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
			"_dd_lines": {
			  "_dd__default": {"_dd_line": 0},
			  "_dd_enabled": {"_dd_line": 1},
			  "_dd_disabled": {"_dd_line": 2},
			  "_dd_empty": {"_dd_line": 3}
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
// short-form intrinsics carry _dd_lines metadata on the wrapper map,
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

	// Walk to BucketName without stripping _dd_lines
	bucketName := parsed["Resources"].(map[string]interface{})["MyBucket"].(map[string]interface{})["Properties"].(map[string]interface{})["BucketName"]
	m, ok := bucketName.(map[string]interface{})
	require.True(t, ok, "BucketName should be a map after rewrite")
	require.Contains(t, m, "Fn::Sub", "rewritten map should have Fn::Sub key")
	require.Contains(t, m, "_dd_lines", "rewritten map should carry _dd_lines")
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

func TestDocument_UnmarshalYAML_CloudFormationForEachExpansion(t *testing.T) {
	ctx := context.Background()

	src := []byte(`Transform: AWS::LanguageExtensions
Parameters:
  Instances:
    Type: List<Number>
    Default: "0,1"
Resources:
  Fn::ForEach::RDSInstances:
    - Identifier
    - !Ref Instances
    - RDSInstance${Identifier}:
        Type: AWS::RDS::DBInstance
        Properties:
          DBName: !Sub app_${Identifier}
          Tags:
            - Key: logical
              Value: !Ref Identifier
`)

	var root yaml.Node
	require.NoError(t, yaml.Unmarshal(src, &root))
	require.Equal(t, yaml.DocumentNode, root.Kind)
	require.Len(t, root.Content, 1)

	doc := &Document{}
	require.NoError(t, doc.UnmarshalYAML(ctx, root.Content[0], nil))

	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &parsed))

	resources := parsed["Resources"].(map[string]interface{})
	require.Contains(t, resources, "RDSInstance0")
	require.Contains(t, resources, "RDSInstance1")
	require.NotContains(t, resources, "Fn::ForEach::RDSInstances")

	rds0 := resources["RDSInstance0"].(map[string]interface{})
	props0 := rds0["Properties"].(map[string]interface{})
	require.Equal(t, map[string]interface{}{"Fn::Sub": "app_0"}, stripDDLines(props0["DBName"]))
	tags0 := props0["Tags"].([]interface{})
	require.Equal(t, map[string]interface{}{
		"Key":   "logical",
		"Value": "0",
	}, stripDDLines(tags0[0]))

	rds1 := resources["RDSInstance1"].(map[string]interface{})
	props1 := rds1["Properties"].(map[string]interface{})
	require.Equal(t, map[string]interface{}{"Fn::Sub": "app_1"}, stripDDLines(props1["DBName"]))
	tags1 := props1["Tags"].([]interface{})
	require.Equal(t, map[string]interface{}{
		"Key":   "logical",
		"Value": "1",
	}, stripDDLines(tags1[0]))
}

func TestDocument_UnmarshalYAML_CloudFormationForEachNoTransform(t *testing.T) {
	ctx := context.Background()

	// Without Transform: AWS::LanguageExtensions, Fn::ForEach keys must not be expanded.
	src := []byte(`Resources:
  Fn::ForEach::RDSInstances:
    - Identifier
    - ["0"]
    - RDSInstance${Identifier}:
        Type: AWS::RDS::DBInstance
`)

	var root yaml.Node
	require.NoError(t, yaml.Unmarshal(src, &root))
	require.Len(t, root.Content, 1)

	doc := &Document{}
	require.NoError(t, doc.UnmarshalYAML(ctx, root.Content[0], nil))

	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &parsed))

	resources := parsed["Resources"].(map[string]interface{})
	require.Contains(t, resources, "Fn::ForEach::RDSInstances")
	require.NotContains(t, resources, "RDSInstance0")
}

func TestDocument_UnmarshalYAML_CloudFormationForEachLineMetadata(t *testing.T) {
	const header = `Transform: AWS::LanguageExtensions
Parameters:
  Names:
    Type: CommaDelimitedList
    Default: Blue,Green
Resources:
  Fn::ForEach::Buckets:
    - Name
`
	const template = `    - Bucket${Name}:
        Type: AWS::S3::Bucket
        Properties:
          BucketName: !Sub logs-${Name}
`

	for _, tc := range []struct {
		name         string
		collection   string
		templateLine int
	}{
		{"flow-style literal", "    - [Blue, Green]\n", 10},
		{"block-style literal", "    -\n      - Blue\n      - Green\n", 12},
		{"parameter reference", "    - !Ref Names\n", 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var root yaml.Node
			require.NoError(t, yaml.Unmarshal([]byte(header+tc.collection+template), &root))
			require.Len(t, root.Content, 1)

			var doc Document
			require.NoError(t, doc.UnmarshalYAML(context.Background(), root.Content[0], nil))
			resources := doc["Resources"].(map[string]interface{})
			require.Len(t, resources, 3, "two buckets and line metadata")
			require.NotContains(t, resources, "Fn::ForEach::Buckets")
			resourceLines := resources["_dd_lines"].(map[string]*LineObject)
			require.NotContains(t, resourceLines, "_dd_Fn::ForEach::Buckets")
			for _, name := range []string{"Blue", "Green"} {
				id := "Bucket" + name
				require.Contains(t, resources, id)
				bucket := resources[id].(map[string]interface{})
				require.Equal(t, "AWS::S3::Bucket", bucket["Type"])
				props := bucket["Properties"].(map[string]interface{})
				require.Equal(t, map[string]interface{}{"Fn::Sub": "logs-" + name}, stripDDLines(props["BucketName"]))
				lines := resourceLines["_dd_"+id]
				require.NotNil(t, lines)
				require.Equal(t, 7, lines.Line, "loop key line")
				require.Len(t, lines.Arr, 3, "loop argument metadata")
				templateLines := lines.Arr[2]["_dd_Bucket${Name}"]
				require.NotNil(t, templateLines)
				require.Equal(t, tc.templateLine, templateLines.Line)
			}
		})
	}
}

func TestCloudFormationResourceLoopLine(t *testing.T) {
	const source = `Transform: AWS::LanguageExtensions
Resources:
  Fn::ForEach::Buckets:
    - Colour
    - [Blue]
    - Bucket${Colour}:
        Type: AWS::S3::Bucket
  WrittenBucket:
    Type: AWS::S3::Bucket
  Sequence: [One, Two, Three]
`
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(source), &root))
	var doc Document
	require.NoError(t, doc.UnmarshalYAML(context.Background(), root.Content[0], nil))

	line, ok := CloudFormationResourceLoopLine(doc, "BucketBlue")
	require.True(t, ok)
	require.Equal(t, 3, line)
	for _, id := range []string{"WrittenBucket", "Sequence", "MissingBucket"} {
		_, ok := CloudFormationResourceLoopLine(doc, id)
		require.False(t, ok, "resource %s", id)
	}
}

func TestDocument_UnmarshalYAML_CloudFormationForEachDuplicateID(t *testing.T) {
	ctx := context.Background()

	// Duplicate collection items ("0,0") must not silently overwrite an already-expanded resource.
	src := []byte(`Transform: AWS::LanguageExtensions
Parameters:
  Instances:
    Type: CommaDelimitedList
    Default: "0,0"
Resources:
  Fn::ForEach::RDSInstances:
    - Identifier
    - !Ref Instances
    - RDSInstance${Identifier}:
        Type: AWS::RDS::DBInstance
        Properties:
          DBName: instance-${Identifier}
`)

	var root yaml.Node
	require.NoError(t, yaml.Unmarshal(src, &root))
	require.Len(t, root.Content, 1)

	doc := &Document{}
	require.NoError(t, doc.UnmarshalYAML(ctx, root.Content[0], nil))

	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &parsed))

	resources := parsed["Resources"].(map[string]interface{})
	require.Contains(t, resources, "RDSInstance0")
	// Only one entry for the duplicate ID — no data loss from overwrite.
	count := 0
	for k := range resources {
		if k == "RDSInstance0" {
			count++
		}
	}
	require.Equal(t, 1, count)
}

func TestDocument_UnmarshalYAML_CloudFormationForEachAmpersandPlaceholder(t *testing.T) {
	ctx := context.Background()

	src := []byte(`Transform: AWS::LanguageExtensions
Parameters:
  Envs:
    Type: CommaDelimitedList
    Default: "prod,staging"
Resources:
  Fn::ForEach::Queues:
    - Env
    - !Ref Envs
    - Queue&{Env}:
        Type: AWS::SQS::Queue
        Properties:
          QueueName: queue-&{Env}
`)

	var root yaml.Node
	require.NoError(t, yaml.Unmarshal(src, &root))
	require.Len(t, root.Content, 1)

	doc := &Document{}
	require.NoError(t, doc.UnmarshalYAML(ctx, root.Content[0], nil))

	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &parsed))

	resources := parsed["Resources"].(map[string]interface{})
	require.Contains(t, resources, "Queueprod")
	require.Contains(t, resources, "Queuestaging")
	require.NotContains(t, resources, "Fn::ForEach::Queues")

	prodProps := resources["Queueprod"].(map[string]interface{})["Properties"].(map[string]interface{})
	require.Equal(t, "queue-prod", stripDDLines(prodProps["QueueName"]))

	stagingProps := resources["Queuestaging"].(map[string]interface{})["Properties"].(map[string]interface{})
	require.Equal(t, "queue-staging", stripDDLines(stagingProps["QueueName"]))
}

func TestDocument_UnmarshalYAML_CloudFormationForEachNestedLoops(t *testing.T) {
	ctx := context.Background()

	src := []byte(`Transform: AWS::LanguageExtensions
Parameters:
  Regions:
    Type: CommaDelimitedList
    Default: "us,eu"
  Tiers:
    Type: CommaDelimitedList
    Default: "web,api"
Resources:
  Fn::ForEach::Regions:
    - Region
    - !Ref Regions
    - Fn::ForEach::Tiers:
        - Tier
        - !Ref Tiers
        - Bucket${Region}${Tier}:
            Type: AWS::S3::Bucket
            Properties:
              BucketName: bucket-${Region}-${Tier}
`)

	var root yaml.Node
	require.NoError(t, yaml.Unmarshal(src, &root))
	require.Len(t, root.Content, 1)

	doc := &Document{}
	require.NoError(t, doc.UnmarshalYAML(ctx, root.Content[0], nil))

	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &parsed))

	resources := parsed["Resources"].(map[string]interface{})

	for _, region := range []string{"us", "eu"} {
		for _, tier := range []string{"web", "api"} {
			key := "Bucket" + region + tier
			require.Contains(t, resources, key)
			props := resources[key].(map[string]interface{})["Properties"].(map[string]interface{})
			require.Equal(t, "bucket-"+region+"-"+tier, stripDDLines(props["BucketName"]))
		}
	}

	for k := range resources {
		require.False(t, strings.HasPrefix(k, "Fn::ForEach::"), "unexpected ForEach key: %s", k)
	}
}

func TestDocument_UnmarshalYAML_CloudFormationForEachUnresolvedNestedCollection(t *testing.T) {
	const source = `Transform: AWS::LanguageExtensions
Parameters:
  BlueNames:
    Type: CommaDelimitedList
  GreenNames:
    Type: CommaDelimitedList
    Default: Web
  RedNames:
    Type: CommaDelimitedList
Resources:
  Fn::ForEach::Colours:
    - Colour
    - [%s]
    - Fn::ForEach::Names:
        - Name
        - !Ref ${Colour}Names
        - ${Colour}${Name}Bucket:
            Type: AWS::S3::Bucket
`
	for _, colours := range []string{"Blue, Green, Red", "Green, Blue, Red"} {
		t.Run(colours, func(t *testing.T) {
			var root yaml.Node
			require.NoError(t, yaml.Unmarshal([]byte(fmt.Sprintf(source, colours)), &root))
			var doc Document
			require.NoError(t, doc.UnmarshalYAML(context.Background(), root.Content[0], nil))
			resources := doc["Resources"].(map[string]interface{})
			require.Contains(t, resources, "GreenWebBucket")
			require.Len(t, resources, 3, "one bucket, the unresolved directive and line metadata")
			unresolved := resources["Fn::ForEach::Names"].([]interface{})
			require.Equal(t, map[string]interface{}{"Ref": "BlueNames"}, stripDDLines(unresolved[1]))
			lines := resources["_dd_lines"].(map[string]*LineObject)
			require.Same(t, lines["_dd_Fn::ForEach::Names"], lines["_dd_GreenWebBucket"])
			require.Equal(t, 11, lines["_dd_GreenWebBucket"].Line)
		})
	}
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
	return stripDDLines(cur)
}

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func stripDDLines(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			if k == "_dd_lines" {
				continue
			}
			out[k] = stripDDLines(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, val := range t {
			out[i] = stripDDLines(val)
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

	// Scalar decoding (normalizeScalar) produces float64 numbers in Document
	d := *doc
	require.Equal(t, float64(26), d["port"], "hex 0x1A = 26")
	require.Equal(t, float64(493), d["mode"], "octal 0o755 = 493")
	require.Equal(t, float64(15), d["mask"], "binary 0b1111 = 15")
	require.Equal(t, float64(1000000), d["replicas"], "underscored 1_000_000 = 1000000")
	require.Equal(t, 2.5, d["ratio"], "float 2.5")
	require.Equal(t, true, d["enabled"], "bool true")
}

func TestGetIgnoreLines_usesOriginalCoordinates(t *testing.T) {
	original := `include:
  - included.yaml
services:
  foo:
    image: alpine
    # dd-iac-scan ignore-line
    ports:
      - "1111:1111"
`
	for _, path := range []string{"docker-compose.yaml", "included.YML", "included.YAML", "included.YaMl"} {
		got := GetIgnoreLines(&FileMetadata{
			FilePath:     path,
			OriginalData: original,
			LinesIgnore:  []int{12, 13},
		})
		require.Equal(t, []int{6, 7}, got)
	}
}

func TestGetIgnoreLines_leavesNonYAMLUnchanged(t *testing.T) {
	got := GetIgnoreLines(&FileMetadata{
		FilePath:     "main.tf",
		OriginalData: `// dd-iac-scan ignore-line`,
		LinesIgnore:  []int{4, 5},
	})
	require.Equal(t, []int{4, 5}, got)
}

func TestGetIgnoreLines_scalarReferenceWithIgnoreBlock(t *testing.T) {
	for _, directive := range []string{"ignore-line", "ignore-block"} {
		for _, leaf := range []string{"  value: *base", "  values:\n    - *base", "  <<: *base"} {
			t.Run(directive+"/"+leaf, func(t *testing.T) {
				lines := strings.Split(leaf, "\n")
				last := lines[len(lines)-1]
				lines = append(lines[:len(lines)-1], "  # dd-iac-scan "+directive, last)
				original := "base: &base {key: value}\njob:\n" + strings.Join(lines, "\n") + "\n"
				got := GetIgnoreLines(&FileMetadata{FilePath: "alias.yaml", OriginalData: original})
				line := strings.Count(original, "\n")
				require.ElementsMatch(t, []int{line - 1, line}, got)
			})
		}
	}
	original := `# dd-iac-scan ignore-block
./included.yaml
`
	got := GetIgnoreLines(&FileMetadata{
		FilePath:     "ref.yaml",
		OriginalData: original,
		LinesIgnore:  []int{99},
	})
	require.ElementsMatch(t, []int{1, 2}, got)
}

func TestGetIgnoreLines_anchorCycle(t *testing.T) {
	original := `cycle: &cycle
  self: *cycle
include:
  - included.yaml
services:
  foo:
    # dd-iac-scan ignore-line
    ports:
      - "1111:1111"
`
	got := GetIgnoreLines(&FileMetadata{
		FilePath:     "docker-compose.yaml",
		OriginalData: original,
		LinesIgnore:  []int{99},
	})
	require.Equal(t, []int{7, 8}, got)
}

func TestClearYAMLScalarInterner(t *testing.T) {
	t.Cleanup(ClearYAMLScalarInterner)
	ClearYAMLScalarInterner()

	internYAMLScalar("apiVersion")
	yamlScalarInternerMu.RLock()
	require.Equal(t, 1, len(yamlScalarInterner))
	yamlScalarInternerMu.RUnlock()

	ClearYAMLScalarInterner()
	yamlScalarInternerMu.RLock()
	require.Empty(t, yamlScalarInterner)
	yamlScalarInternerMu.RUnlock()

	got := internYAMLScalar("apiVersion")
	require.Equal(t, "apiVersion", got)
}

// UnmarshalSharedYAML builds the same document as UnmarshalYAML, aliases and
// merge keys included: each alias still gets its own copy of its target.
func TestDocument_UnmarshalSharedYAML_MatchesUnmarshalYAML(t *testing.T) {
	ctx := context.Background()
	for _, content := range []string{
		"base: &base\n  image: nginx\n  ports:\n    - 80\nweb:\n  <<: *base\n  name: web\nother: *base\n",
		"list:\n  - &item {a: 1}\n  - *item\n  - [1, [2, 3]]\nname: &n x\nalias: *n\n",
		"AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n" +
			"    Properties:\n      BucketName: !Sub '${AWS::StackName}-b'\n      Tags: !If [c, [a], [b]]\n",
		"- hosts: all\n  tasks:\n    - name: t\n      debug:\n        msg: x\n",
	} {
		var root yaml.Node
		require.NoError(t, yaml.Unmarshal([]byte(content), &root))
		want, got := Document{}, Document{}
		require.NoError(t, want.UnmarshalYAML(ctx, root.Content[0], nil))
		require.NoError(t, got.UnmarshalSharedYAML(ctx, root.Content[0]))
		wantJSON, err := json.Marshal(want)
		require.NoError(t, err)
		gotJSON, err := json.Marshal(got)
		require.NoError(t, err)
		require.JSONEq(t, string(wantJSON), string(gotJSON), content)
	}
}

// A node reached through several parents, as the file resolver shares the
// content of a file between its references, is converted once.
func TestDocument_UnmarshalSharedYAML_SharesNodeReachedTwice(t *testing.T) {
	scalar := func(v string, line int) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Value: v, Line: line} }
	inner := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{scalar("image", 0), scalar("nginx", 0)}}
	// Each reference gets its own copy of the referenced root, sharing its content.
	seq := &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{scalar("echo ok", 3)}}
	shared := []*yaml.Node{scalar("container", 0), inner, scalar("commands", 3), seq}
	root := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		scalar("a", 1), {Kind: yaml.MappingNode, Content: shared},
		scalar("b", 2), {Kind: yaml.MappingNode, Content: shared},
	}}

	doc := Document{}
	require.NoError(t, doc.UnmarshalSharedYAML(context.Background(), root))

	a := doc["a"].(map[string]interface{})
	b := doc["b"].(map[string]interface{})
	require.Equal(t, 1, a["_dd_lines"].(map[string]*LineObject)["_dd__default"].Line)
	require.Equal(t, 2, b["_dd_lines"].(map[string]*LineObject)["_dd__default"].Line)
	require.Equal(t, "nginx", a["container"].(map[string]interface{})["image"])
	require.Equal(t, reflect.ValueOf(a["container"]).Pointer(), reflect.ValueOf(b["container"]).Pointer())
	require.Equal(t, []interface{}{"echo ok"}, a["commands"])
	require.Equal(t, reflect.ValueOf(a["commands"]).Pointer(), reflect.ValueOf(b["commands"]).Pointer())
}

func TestGetIgnoreLines_SharedAliasGraphLinear(t *testing.T) {
	// Stacked alias reuse (6 refs per level over 9 levels = 6^9 paths) must
	// visit each YAML node once instead of walking every alias path.
	var sb strings.Builder
	sb.WriteString("a0: &a0 [\"x\", \"x\", \"x\", \"x\", \"x\", \"x\"]\n")
	for l := 1; l <= 9; l++ {
		fmt.Fprintf(&sb, "a%d: &a%d [*a%d, *a%d, *a%d, *a%d, *a%d, *a%d]\n", l, l, l-1, l-1, l-1, l-1, l-1, l-1)
	}
	sb.WriteString("# dd-iac-scan ignore-line\nignored: true\n")

	lines := GetIgnoreLines(&FileMetadata{
		FilePath:     "bomb.yml",
		OriginalData: sb.String(),
	})
	require.Contains(t, lines, 12)
}

// Source spans stop before YAML stream markers, including marker comments.
func TestSourceSnapshotDeclarationBoundaries(t *testing.T) {
	block := &SourceSnapshot{Content: "job:\n  script: |\n    --- # literal command\n"}
	block.RecordDeclarations(0, []int{1})
	_, end := block.DeclarationSpan(0, 1)
	require.Equal(t, 3, end, "indented marker-like command text belongs to the job")
	for _, marker := range []string{"---", "--- # next", "...", "... # end"} {
		t.Run(marker, func(t *testing.T) {
			snapshot := &SourceSnapshot{Content: "job:\n  script: echo ok\n" + marker + "\nnext:\n  script: echo next\n"}
			snapshot.RecordDeclarations(0, []int{1})
			snapshot.RecordDeclarations(1, []int{4})
			start, end := snapshot.DeclarationSpan(0, 2)
			require.Equal(t, 1, start)
			require.Equal(t, 2, end)
		})
	}
}
