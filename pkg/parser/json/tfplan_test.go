/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestJson_parseTFPlan(t *testing.T) {
	type args struct {
		doc model.Document
	}

	tests := []struct {
		name    string
		args    args
		want    model.Document
		wantErr bool
	}{
		{
			name: "test - parse as tfplan",
			args: args{
				doc: model.Document{
					"format_version":    "0.2",
					"terraform_version": "1.0.5",
					"variables":         map[string]interface{}{},
					"planned_values": map[string]interface{}{
						"root_module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address":        "fakewebservices_database.prod_db",
									"mode":           "managed",
									"type":           "fakewebservices_database",
									"name":           "prod_db",
									"provider_name":  "registry.terraform.io/hashicorp/fakewebservices",
									"schema_version": 0,
									"values": map[string]interface{}{
										"name": "Production DB",
										"size": 256,
									},
									"sensitive_values": map[string]interface{}{},
								},
							},
						},
					},
					"resource_changes": []map[string]interface{}{},
					"configuration":    map[string]interface{}{},
				},
			},
			want: model.Document{
				"resource": map[string]interface{}{
					"fakewebservices_database": map[string]interface{}{
						"prod_db": map[string]interface{}{
							"name": "Production DB",
							"size": (float64)(256),
						},
					},
				},
				"_dd_tfplan_meta": map[string]interface{}{
					"fakewebservices_database": map[string]interface{}{
						"prod_db": map[string]interface{}{
							"address": "fakewebservices_database.prod_db",
						},
					},
				},
				"resource_changes": []interface{}{},
				"configuration":    map[string]interface{}{},
			},
			wantErr: false,
		},
		{
			name: "test - resource_changes and configuration pass through",
			args: args{
				doc: model.Document{
					"format_version":    "1.2",
					"terraform_version": "1.5.0",
					"planned_values": map[string]interface{}{
						"root_module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "aws_s3_bucket.main",
									"mode":    "managed",
									"type":    "aws_s3_bucket",
									"name":    "main",
									"values": map[string]interface{}{
										"bucket": "main-bucket",
									},
								},
							},
						},
					},
					"resource_changes": []map[string]interface{}{
						{
							"address": "aws_s3_bucket.main",
							"mode":    "managed",
							"type":    "aws_s3_bucket",
							"name":    "main",
							"change": map[string]interface{}{
								"actions": []string{"create"},
								"before":  nil,
								"after": map[string]interface{}{
									"acl": "private",
								},
								"after_unknown": map[string]interface{}{
									"bucket": true,
									"id":     true,
								},
							},
						},
					},
					"configuration": map[string]interface{}{
						"root_module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "aws_s3_bucket.main",
									"mode":    "managed",
									"type":    "aws_s3_bucket",
									"name":    "main",
									"expressions": map[string]interface{}{
										"bucket": map[string]interface{}{
											"references": []string{"random_id.suffix"},
										},
									},
								},
							},
						},
					},
				},
			},
			want: model.Document{
				"resource": map[string]interface{}{
					"aws_s3_bucket": map[string]interface{}{
						"main": map[string]interface{}{
							"bucket": "main-bucket",
						},
					},
				},
				"_dd_tfplan_meta": map[string]interface{}{
					"aws_s3_bucket": map[string]interface{}{
						"main": map[string]interface{}{
							"address": "aws_s3_bucket.main",
							"after_unknown": map[string]interface{}{
								"bucket": true,
								"id":     true,
							},
							"configuration_expressions": map[string]interface{}{
								"bucket": map[string]interface{}{
									"references": []interface{}{"random_id.suffix"},
								},
							},
						},
					},
				},
				"resource_changes": []interface{}{
					map[string]interface{}{
						"address": "aws_s3_bucket.main",
						"mode":    "managed",
						"type":    "aws_s3_bucket",
						"name":    "main",
						"change": map[string]interface{}{
							"actions": []interface{}{"create"},
							"before":  nil,
							"after": map[string]interface{}{
								"acl": "private",
							},
							"after_unknown": map[string]interface{}{
								"bucket": true,
								"id":     true,
							},
						},
					},
				},
				"configuration": map[string]interface{}{
					"root_module": map[string]interface{}{
						"resources": []interface{}{
							map[string]interface{}{
								"address": "aws_s3_bucket.main",
								"mode":    "managed",
								"type":    "aws_s3_bucket",
								"name":    "main",
								"expressions": map[string]interface{}{
									"bucket": map[string]interface{}{
										"references": []interface{}{"random_id.suffix"},
									},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test - should not parse tfplan",
			args: args{
				doc: model.Document{
					"resource": map[string]interface{}{
						"name": "martin",
					},
				},
			},
			want:    model.Document{},
			wantErr: true,
		},
		{
			name: "test - multi-module with same resource type",
			args: args{
				doc: model.Document{
					"format_version":    "1.2",
					"terraform_version": "1.5.0",
					"planned_values": map[string]interface{}{
						"root_module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "aws_s3_bucket.main",
									"mode":    "managed",
									"type":    "aws_s3_bucket",
									"name":    "main",
									"values": map[string]interface{}{
										"bucket": "main-bucket",
										"acl":    "private",
									},
								},
								{
									"address": "aws_instance.web",
									"mode":    "managed",
									"type":    "aws_instance",
									"name":    "web",
									"values": map[string]interface{}{
										"instance_type": "t2.micro",
									},
								},
							},
							"child_modules": []map[string]interface{}{
								{
									"address": "module.storage",
									"resources": []map[string]interface{}{
										{
											"address": "module.storage.aws_s3_bucket.backup",
											"mode":    "managed",
											"type":    "aws_s3_bucket",
											"name":    "backup",
											"values": map[string]interface{}{
												"bucket": "backup-bucket",
												"acl":    "private",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: model.Document{
				"resource": map[string]interface{}{
					"aws_s3_bucket": map[string]interface{}{
						"main": map[string]interface{}{
							"bucket": "main-bucket",
							"acl":    "private",
						},
						"module.storage.backup": map[string]interface{}{
							"bucket": "backup-bucket",
							"acl":    "private",
						},
					},
					"aws_instance": map[string]interface{}{
						"web": map[string]interface{}{
							"instance_type": "t2.micro",
						},
					},
				},
				"_dd_tfplan_meta": map[string]interface{}{
					"aws_s3_bucket": map[string]interface{}{
						"main": map[string]interface{}{
							"address": "aws_s3_bucket.main",
						},
						"module.storage.backup": map[string]interface{}{
							"address": "module.storage.aws_s3_bucket.backup",
						},
					},
					"aws_instance": map[string]interface{}{
						"web": map[string]interface{}{
							"address": "aws_instance.web",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test - same resource name in different modules is preserved with module-prefixed keys",
			args: args{
				doc: model.Document{
					"format_version":    "1.2",
					"terraform_version": "1.5.0",
					"planned_values": map[string]interface{}{
						"root_module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "aws_instance.web",
									"mode":    "managed",
									"type":    "aws_instance",
									"name":    "web",
									"values": map[string]interface{}{
										"instance_type": "t2.large",
										"tags": map[string]interface{}{
											"Environment": "production",
										},
									},
								},
							},
							"child_modules": []map[string]interface{}{
								{
									"address": "module.staging",
									"resources": []map[string]interface{}{
										{
											"address": "module.staging.aws_instance.web",
											"mode":    "managed",
											"type":    "aws_instance",
											"name":    "web",
											"values": map[string]interface{}{
												"instance_type": "t2.micro",
												"tags": map[string]interface{}{
													"Environment": "staging",
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
			want: model.Document{
				"resource": map[string]interface{}{
					"aws_instance": map[string]interface{}{
						"web": map[string]interface{}{
							"instance_type": "t2.large",
							"tags": map[string]interface{}{
								"Environment": "production",
							},
						},
						"module.staging.web": map[string]interface{}{
							"instance_type": "t2.micro",
							"tags": map[string]interface{}{
								"Environment": "staging",
							},
						},
					},
				},
				"_dd_tfplan_meta": map[string]interface{}{
					"aws_instance": map[string]interface{}{
						"web": map[string]interface{}{
							"address": "aws_instance.web",
						},
						"module.staging.web": map[string]interface{}{
							"address": "module.staging.aws_instance.web",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test - deeply nested modules",
			args: args{
				doc: model.Document{
					"format_version":    "1.2",
					"terraform_version": "1.5.0",
					"planned_values": map[string]interface{}{
						"root_module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "aws_vpc.main",
									"mode":    "managed",
									"type":    "aws_vpc",
									"name":    "main",
									"values": map[string]interface{}{
										"cidr_block": "10.0.0.0/16",
									},
								},
							},
							"child_modules": []map[string]interface{}{
								{
									"address": "module.networking",
									"resources": []map[string]interface{}{
										{
											"address": "module.networking.aws_subnet.public",
											"mode":    "managed",
											"type":    "aws_subnet",
											"name":    "public",
											"values": map[string]interface{}{
												"cidr_block": "10.0.1.0/24",
											},
										},
									},
									"child_modules": []map[string]interface{}{
										{
											"address": "module.networking.module.security",
											"resources": []map[string]interface{}{
												{
													"address": "module.networking.module.security.aws_security_group.web",
													"mode":    "managed",
													"type":    "aws_security_group",
													"name":    "web",
													"values": map[string]interface{}{
														"description": "Web traffic",
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
			},
			want: model.Document{
				"resource": map[string]interface{}{
					"aws_vpc": map[string]interface{}{
						"main": map[string]interface{}{
							"cidr_block": "10.0.0.0/16",
						},
					},
					"aws_subnet": map[string]interface{}{
						"module.networking.public": map[string]interface{}{
							"cidr_block": "10.0.1.0/24",
						},
					},
					"aws_security_group": map[string]interface{}{
						"module.networking.module.security.web": map[string]interface{}{
							"description": "Web traffic",
						},
					},
				},
				"_dd_tfplan_meta": map[string]interface{}{
					"aws_vpc": map[string]interface{}{
						"main": map[string]interface{}{
							"address": "aws_vpc.main",
						},
					},
					"aws_subnet": map[string]interface{}{
						"module.networking.public": map[string]interface{}{
							"address": "module.networking.aws_subnet.public",
						},
					},
					"aws_security_group": map[string]interface{}{
						"module.networking.module.security.web": map[string]interface{}{
							"address": "module.networking.module.security.aws_security_group.web",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test - multiple sibling modules with same resource types is preserved with module-prefixed keys",
			args: args{
				doc: model.Document{
					"format_version":    "1.2",
					"terraform_version": "1.5.0",
					"planned_values": map[string]interface{}{
						"root_module": map[string]interface{}{
							"resources": []map[string]interface{}{},
							"child_modules": []map[string]interface{}{
								{
									"address": "module.app1",
									"resources": []map[string]interface{}{
										{
											"address": "module.app1.aws_s3_bucket.data",
											"mode":    "managed",
											"type":    "aws_s3_bucket",
											"name":    "data",
											"values": map[string]interface{}{
												"bucket": "app1-data",
											},
										},
									},
								},
								{
									"address": "module.app2",
									"resources": []map[string]interface{}{
										{
											"address": "module.app2.aws_s3_bucket.data",
											"mode":    "managed",
											"type":    "aws_s3_bucket",
											"name":    "data",
											"values": map[string]interface{}{
												"bucket": "app2-data",
											},
										},
									},
								},
							},
						},
					},
				},
			},
					want: model.Document{
				"resource": map[string]interface{}{
					"aws_s3_bucket": map[string]interface{}{
						"module.app1.data": map[string]interface{}{
							"bucket": "app1-data",
						},
						"module.app2.data": map[string]interface{}{
							"bucket": "app2-data",
						},
					},
				},
				"_dd_tfplan_meta": map[string]interface{}{
					"aws_s3_bucket": map[string]interface{}{
						"module.app1.data": map[string]interface{}{
							"address": "module.app1.aws_s3_bucket.data",
						},
						"module.app2.data": map[string]interface{}{
							"address": "module.app2.aws_s3_bucket.data",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test - count creates multiple resource instances",
			args: args{
				doc: model.Document{
					"format_version":    "1.2",
					"terraform_version": "1.5.0",
					"planned_values": map[string]interface{}{
						"root_module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "aws_instance.web[0]",
									"mode":    "managed",
									"type":    "aws_instance",
									"name":    "web",
									"index":   float64(0), // JSON numbers are float64
									"values": map[string]interface{}{
										"instance_type": "t2.micro",
										"tags": map[string]interface{}{
											"Name":  "web-0",
											"Index": float64(0),
										},
									},
								},
								{
									"address": "aws_instance.web[1]",
									"mode":    "managed",
									"type":    "aws_instance",
									"name":    "web",
									"index":   float64(1),
									"values": map[string]interface{}{
										"instance_type": "t2.micro",
										"tags": map[string]interface{}{
											"Name":  "web-1",
											"Index": float64(1),
										},
									},
								},
								{
									"address": "aws_instance.web[2]",
									"mode":    "managed",
									"type":    "aws_instance",
									"name":    "web",
									"index":   float64(2),
									"values": map[string]interface{}{
										"instance_type": "t2.micro",
										"tags": map[string]interface{}{
											"Name":  "web-2",
											"Index": float64(2),
										},
									},
								},
							},
						},
					},
				},
			},
			want: model.Document{
				"resource": map[string]interface{}{
					"aws_instance": map[string]interface{}{
						"web[0]": map[string]interface{}{
							"instance_type": "t2.micro",
							"tags": map[string]interface{}{
								"Name":  "web-0",
								"Index": float64(0),
							},
						},
						"web[1]": map[string]interface{}{
							"instance_type": "t2.micro",
							"tags": map[string]interface{}{
								"Name":  "web-1",
								"Index": float64(1),
							},
						},
						"web[2]": map[string]interface{}{
							"instance_type": "t2.micro",
							"tags": map[string]interface{}{
								"Name":  "web-2",
								"Index": float64(2),
							},
						},
					},
				},
				"_dd_tfplan_meta": map[string]interface{}{
					"aws_instance": map[string]interface{}{
						"web[0]": map[string]interface{}{
							"address": "aws_instance.web[0]",
						},
						"web[1]": map[string]interface{}{
							"address": "aws_instance.web[1]",
						},
						"web[2]": map[string]interface{}{
							"address": "aws_instance.web[2]",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test - for_each creates multiple resource instances",
			args: args{
				doc: model.Document{
					"format_version":    "1.2",
					"terraform_version": "1.5.0",
					"planned_values": map[string]interface{}{
						"root_module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "aws_s3_bucket.data[\"prod\"]",
									"mode":    "managed",
									"type":    "aws_s3_bucket",
									"name":    "data",
									"index":   "prod",
									"values": map[string]interface{}{
										"bucket": "prod-data-bucket",
										"acl":    "private",
									},
								},
								{
									"address": "aws_s3_bucket.data[\"staging\"]",
									"mode":    "managed",
									"type":    "aws_s3_bucket",
									"name":    "data",
									"index":   "staging",
									"values": map[string]interface{}{
										"bucket": "staging-data-bucket",
										"acl":    "private",
									},
								},
								{
									"address": "aws_s3_bucket.data[\"dev\"]",
									"mode":    "managed",
									"type":    "aws_s3_bucket",
									"name":    "data",
									"index":   "dev",
									"values": map[string]interface{}{
										"bucket": "dev-data-bucket",
										"acl":    "private",
									},
								},
							},
						},
					},
				},
			},
			want: model.Document{
				"resource": map[string]interface{}{
					"aws_s3_bucket": map[string]interface{}{
						"data[\"prod\"]": map[string]interface{}{
							"bucket": "prod-data-bucket",
							"acl":    "private",
						},
						"data[\"staging\"]": map[string]interface{}{
							"bucket": "staging-data-bucket",
							"acl":    "private",
						},
						"data[\"dev\"]": map[string]interface{}{
							"bucket": "dev-data-bucket",
							"acl":    "private",
						},
					},
				},
				"_dd_tfplan_meta": map[string]interface{}{
					"aws_s3_bucket": map[string]interface{}{
						"data[\"prod\"]": map[string]interface{}{
							"address": "aws_s3_bucket.data[\"prod\"]",
						},
						"data[\"staging\"]": map[string]interface{}{
							"address": "aws_s3_bucket.data[\"staging\"]",
						},
						"data[\"dev\"]": map[string]interface{}{
							"address": "aws_s3_bucket.data[\"dev\"]",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test - injects resource values line from _dd_lines",
			args: args{
				doc: model.Document{
					"format_version":    "0.2",
					"terraform_version": "1.0.5",
					"variables":         map[string]any{},
					"planned_values": map[string]any{
						"root_module": map[string]any{
							"_dd_lines": map[string]any{
								"_dd_resources": map[string]any{
									"_dd_arr": []map[string]any{
										{
											"_dd__default": map[string]any{"_dd_line": 5},
											"_dd_values":   map[string]any{"_dd_line": 7},
										},
									},
								},
							},
							"resources": []map[string]any{
								{
									"address": "fakewebservices_database.prod_db",
									"mode":    "managed",
									"type":    "fakewebservices_database",
									"name":    "prod_db",
									"values": map[string]any{
										"name": "Production DB",
										"size": 256,
									},
								},
							},
						},
					},
					"resource_changes": []map[string]any{},
					"configuration":    map[string]any{},
				},
			},
			want: model.Document{
				"resource": map[string]any{
					"fakewebservices_database": map[string]any{
						"_dd_lines": map[string]any{
							"_dd_prod_db": map[string]any{"_dd_line": (float64)(7)},
						},
						"prod_db": map[string]any{
							"name": "Production DB",
							"size": (float64)(256),
						},
					},
				},
				"_dd_tfplan_meta": map[string]any{
					"fakewebservices_database": map[string]any{
						"prod_db": map[string]any{
							"address": "fakewebservices_database.prod_db",
						},
					},
				},
				"resource_changes": []any{},
				"configuration":    map[string]any{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTFPlan(tt.args.doc)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

// TestJson_parseTFPlan_dd_tfplan_meta_correlation exercises _dd_tfplan_meta's
// direct-lookup contract for root/nested/count/for_each resources, including
// for_each keys with a dot, a "]", and an escaped quote.
func TestJson_parseTFPlan_dd_tfplan_meta_correlation(t *testing.T) {
	doc := model.Document{
		"format_version":    "1.2",
		"terraform_version": "1.5.0",
		"planned_values": map[string]interface{}{
			"root_module": map[string]interface{}{
				"resources": []map[string]interface{}{
					{
						"address": "aws_vpc.main",
						"mode":    "managed",
						"type":    "aws_vpc",
						"name":    "main",
						"values": map[string]interface{}{
							"cidr_block": "10.0.0.0/16",
						},
					},
					{
						"address": "aws_instance.web[0]",
						"mode":    "managed",
						"type":    "aws_instance",
						"name":    "web",
						"index":   float64(0),
						"values": map[string]interface{}{
							"instance_type": "t2.micro",
						},
					},
					{
						"address": "aws_s3_bucket.data[\"prod\"]",
						"mode":    "managed",
						"type":    "aws_s3_bucket",
						"name":    "data",
						"index":   "prod",
						"values": map[string]interface{}{
							"bucket": "prod-data-bucket",
						},
					},
					{
						"address": "aws_s3_bucket.data[\"a.b\"]",
						"mode":    "managed",
						"type":    "aws_s3_bucket",
						"name":    "data",
						"index":   "a.b",
						"values": map[string]interface{}{
							"bucket": "dotted-key-bucket",
						},
					},
					{
						"address": "aws_s3_bucket.data[\"a]b\"]",
						"mode":    "managed",
						"type":    "aws_s3_bucket",
						"name":    "data",
						"index":   "a]b",
						"values": map[string]interface{}{
							"bucket": "bracket-key-bucket",
						},
					},
					{
						"address": "aws_s3_bucket.data[\"a\\\"b\"]",
						"mode":    "managed",
						"type":    "aws_s3_bucket",
						"name":    "data",
						"index":   "a\"b",
						"values": map[string]interface{}{
							"bucket": "quote-key-bucket",
						},
					},
				},
				"child_modules": []map[string]interface{}{
					{
						"address": "module.networking",
						"resources": []map[string]interface{}{
							{
								"address": "module.networking.aws_subnet.public",
								"mode":    "managed",
								"type":    "aws_subnet",
								"name":    "public",
								"values": map[string]interface{}{
									"cidr_block": "10.0.1.0/24",
								},
							},
						},
					},
				},
			},
		},
		"resource_changes": []map[string]interface{}{
			{
				"address": "aws_vpc.main",
				"change": map[string]interface{}{
					"after_unknown": map[string]interface{}{"id": true},
				},
			},
			{
				"address": "aws_instance.web[0]",
				"change": map[string]interface{}{
					"after_unknown": map[string]interface{}{"arn": true},
				},
			},
			{
				"address": "aws_s3_bucket.data[\"prod\"]",
				"change": map[string]interface{}{
					"after_unknown": map[string]interface{}{"id": true},
				},
			},
			{
				"address": "aws_s3_bucket.data[\"a.b\"]",
				"change": map[string]interface{}{
					"after_unknown": map[string]interface{}{"id": true},
				},
			},
			{
				"address": "aws_s3_bucket.data[\"a]b\"]",
				"change": map[string]interface{}{
					"after_unknown": map[string]interface{}{"id": true},
				},
			},
			{
				"address": "aws_s3_bucket.data[\"a\\\"b\"]",
				"change": map[string]interface{}{
					"after_unknown": map[string]interface{}{"id": true},
				},
			},
			{
				"address": "module.networking.aws_subnet.public",
				"change": map[string]interface{}{
					"after_unknown": map[string]interface{}{"id": true},
				},
			},
		},
		"configuration": map[string]interface{}{
			"root_module": map[string]interface{}{
				"resources": []map[string]interface{}{
					{
						"address": "aws_vpc.main",
						"expressions": map[string]interface{}{
							"cidr_block": map[string]interface{}{"constant_value": "10.0.0.0/16"},
						},
					},
					{
						"address": "aws_instance.web",
						"expressions": map[string]interface{}{
							"instance_type": map[string]interface{}{"references": []string{"var.instance_type"}},
						},
					},
					{
						"address": "aws_s3_bucket.data",
						"expressions": map[string]interface{}{
							"bucket": map[string]interface{}{"references": []string{"var.bucket_name"}},
						},
					},
				},
				"module_calls": map[string]interface{}{
					"networking": map[string]interface{}{
						"module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "aws_subnet.public",
									"expressions": map[string]interface{}{
										"cidr_block": map[string]interface{}{"references": []string{"var.subnet_cidr"}},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	got, err := parseTFPlan(doc)
	require.NoError(t, err)

	meta := func(resourceType, key string) map[string]interface{} {
		ddMeta, ok := got["_dd_tfplan_meta"].(map[string]interface{})
		require.True(t, ok, "_dd_tfplan_meta not found")
		typeMap, ok := ddMeta[resourceType].(map[string]interface{})
		require.True(t, ok, "_dd_tfplan_meta.%s not found", resourceType)
		entry, ok := typeMap[key].(map[string]interface{})
		require.True(t, ok, "_dd_tfplan_meta.%s.%s not found", resourceType, key)
		return entry
	}

	// _dd_tfplan_meta must never be nested inside resource.<type>.
	resourceTypes, ok := got["resource"].(map[string]interface{})
	require.True(t, ok)
	for resourceType, typeMap := range resourceTypes {
		asMap, ok := typeMap.(map[string]interface{})
		require.True(t, ok)
		require.NotContains(t, asMap, "_dd_tfplan_meta", "resource.%s must not contain _dd_tfplan_meta", resourceType)
	}

	require.Equal(t, map[string]interface{}{
		"address":                   "aws_vpc.main",
		"after_unknown":             map[string]interface{}{"id": true},
		"configuration_expressions": map[string]interface{}{"cidr_block": map[string]interface{}{"constant_value": "10.0.0.0/16"}},
	}, meta("aws_vpc", "main"))

	require.Equal(t, map[string]interface{}{
		"address":                   "aws_instance.web[0]",
		"after_unknown":             map[string]interface{}{"arn": true},
		"configuration_expressions": map[string]interface{}{"instance_type": map[string]interface{}{"references": []interface{}{"var.instance_type"}}},
	}, meta("aws_instance", "web[0]"))

	require.Equal(t, map[string]interface{}{
		"address":                   "aws_s3_bucket.data[\"prod\"]",
		"after_unknown":             map[string]interface{}{"id": true},
		"configuration_expressions": map[string]interface{}{"bucket": map[string]interface{}{"references": []interface{}{"var.bucket_name"}}},
	}, meta("aws_s3_bucket", "data[\"prod\"]"))

	require.Equal(t, map[string]interface{}{
		"address":                   "aws_s3_bucket.data[\"a.b\"]",
		"after_unknown":             map[string]interface{}{"id": true},
		"configuration_expressions": map[string]interface{}{"bucket": map[string]interface{}{"references": []interface{}{"var.bucket_name"}}},
	}, meta("aws_s3_bucket", "data[\"a.b\"]"))

	require.Equal(t, map[string]interface{}{
		"address":                   "aws_s3_bucket.data[\"a]b\"]",
		"after_unknown":             map[string]interface{}{"id": true},
		"configuration_expressions": map[string]interface{}{"bucket": map[string]interface{}{"references": []interface{}{"var.bucket_name"}}},
	}, meta("aws_s3_bucket", "data[\"a]b\"]"))

	require.Equal(t, map[string]interface{}{
		"address":                   "aws_s3_bucket.data[\"a\\\"b\"]",
		"after_unknown":             map[string]interface{}{"id": true},
		"configuration_expressions": map[string]interface{}{"bucket": map[string]interface{}{"references": []interface{}{"var.bucket_name"}}},
	}, meta("aws_s3_bucket", "data[\"a\\\"b\"]"))

	require.Equal(t, map[string]interface{}{
		"address":                   "module.networking.aws_subnet.public",
		"after_unknown":             map[string]interface{}{"id": true},
		"configuration_expressions": map[string]interface{}{"cidr_block": map[string]interface{}{"references": []interface{}{"var.subnet_cidr"}}},
	}, meta("aws_subnet", "module.networking.public"))
}

func TestJson_parseTFPlan_dd_tfplan_meta_provisioners(t *testing.T) {
	doc := model.Document{
		"format_version":    "1.2",
		"terraform_version": "1.5.0",
		"planned_values": map[string]interface{}{
			"root_module": map[string]interface{}{
				"resources": []map[string]interface{}{
					{
						"address": "aws_instance.web",
						"mode":    "managed",
						"type":    "aws_instance",
						"name":    "web",
						"values":  map[string]interface{}{"instance_type": "t2.micro"},
					},
				},
			},
		},
		"resource_changes": []map[string]interface{}{},
		"configuration": map[string]interface{}{
			"root_module": map[string]interface{}{
				"resources": []map[string]interface{}{
					{
						"address": "aws_instance.web",
						"expressions": map[string]interface{}{
							"instance_type": map[string]interface{}{"constant_value": "t2.micro"},
						},
						"provisioners": []map[string]interface{}{
							{
								"type": "local-exec",
								"expressions": map[string]interface{}{
									"command": map[string]interface{}{"constant_value": "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
								},
							},
						},
					},
				},
			},
		},
	}

	got, err := parseTFPlan(doc)
	require.NoError(t, err)

	ddMeta, ok := got["_dd_tfplan_meta"].(map[string]interface{})
	require.True(t, ok)
	entry := ddMeta["aws_instance"].(map[string]interface{})["web"].(map[string]interface{})

	require.Equal(t, []interface{}{
		map[string]interface{}{
			"type": "local-exec",
			"expressions": map[string]interface{}{
				"command": map[string]interface{}{"constant_value": "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
			},
		},
	}, entry["provisioners"])
}

func TestJson_parseTFPlan_dd_tfplan_meta_module_call_var_resolution(t *testing.T) {
	doc := model.Document{
		"format_version":    "1.2",
		"terraform_version": "1.5.0",
		"planned_values": map[string]interface{}{
			"root_module": map[string]interface{}{
				"child_modules": []map[string]interface{}{
					{
						"address": "module.instance",
						"resources": []map[string]interface{}{
							{
								"address": "module.instance.aws_instance.web",
								"mode":    "managed",
								"type":    "aws_instance",
								"name":    "web",
								"values":  map[string]interface{}{},
							},
						},
					},
				},
			},
		},
		"resource_changes": []map[string]interface{}{},
		"configuration": map[string]interface{}{
			"root_module": map[string]interface{}{
				"module_calls": map[string]interface{}{
					"instance": map[string]interface{}{
						"expressions": map[string]interface{}{
							"user_data": map[string]interface{}{"constant_value": "IyEvYmluL2Jhc2gKZWNobyBoaQ=="},
						},
						"module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "aws_instance.web",
									"expressions": map[string]interface{}{
										"user_data": map[string]interface{}{"references": []string{"var.user_data"}},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	got, err := parseTFPlan(doc)
	require.NoError(t, err)

	ddMeta, ok := got["_dd_tfplan_meta"].(map[string]interface{})
	require.True(t, ok)
	entry := ddMeta["aws_instance"].(map[string]interface{})["module.instance.web"].(map[string]interface{})

	require.Equal(t, map[string]interface{}{
		"user_data": map[string]interface{}{"constant_value": "IyEvYmluL2Jhc2gKZWNobyBoaQ=="},
	}, entry["configuration_expressions"])
}
