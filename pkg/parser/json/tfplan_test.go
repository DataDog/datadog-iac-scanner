/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	stdjson "encoding/json"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
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

							"_dd_meta": map[string]interface{}{"address": "fakewebservices_database.prod_db"}},
					},
				},
				"resource_changes": []interface{}{},
				"configuration":    map[string]interface{}{},
			},
			wantErr: false,
		},
		{
			name: "test - planned data source and managed resource of the same type and name stay separate",
			args: args{
				doc: model.Document{
					"format_version":    "0.2",
					"terraform_version": "1.0.5",
					"variables":         map[string]interface{}{},
					"planned_values": map[string]interface{}{
						"root_module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address":       "aws_s3_bucket.x",
									"mode":          "managed",
									"type":          "aws_s3_bucket",
									"name":          "x",
									"provider_name": "registry.terraform.io/hashicorp/aws",
									"values":        map[string]interface{}{"bucket": "managed"},
								},
								{
									"address":       "data.aws_s3_bucket.x",
									"mode":          "data",
									"type":          "aws_s3_bucket",
									"name":          "x",
									"provider_name": "registry.terraform.io/hashicorp/aws",
									"values":        map[string]interface{}{"bucket": "planned-read"},
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
					"aws_s3_bucket": map[string]interface{}{
						"x": map[string]interface{}{"bucket": "managed", "_dd_meta": map[string]interface{}{"address": "aws_s3_bucket.x"}},
					},
				},
				"data": map[string]interface{}{
					"aws_s3_bucket": map[string]interface{}{
						"x": map[string]interface{}{"bucket": "planned-read", "_dd_meta": map[string]interface{}{"address": "data.aws_s3_bucket.x"}},
					},
				},
				"resource_changes": []interface{}{},
				"configuration":    map[string]interface{}{},
			},
			wantErr: false,
		},
		{
			name: "test - prior state fills only the data entries the plan does not carry",
			args: args{
				doc: model.Document{
					"format_version":    "0.2",
					"terraform_version": "1.0.5",
					"variables":         map[string]interface{}{},
					"planned_values": map[string]interface{}{
						"root_module": map[string]interface{}{
							"resources": []map[string]interface{}{
								{
									"address": "data.aws_s3_bucket.both",
									"mode":    "data",
									"type":    "aws_s3_bucket",
									"name":    "both",
									"values":  map[string]interface{}{"bucket": "planned"},
								},
							},
						},
					},
					"prior_state": map[string]interface{}{
						"format_version": "1.0",
						"values": map[string]interface{}{
							"root_module": map[string]interface{}{
								"resources": []map[string]interface{}{
									{
										"address": "data.aws_s3_bucket.both",
										"mode":    "data",
										"type":    "aws_s3_bucket",
										"name":    "both",
										"values":  map[string]interface{}{"bucket": "prior"},
									},
									{
										"address": "data.aws_s3_bucket.prior_only",
										"mode":    "data",
										"type":    "aws_s3_bucket",
										"name":    "prior_only",
										"values":  map[string]interface{}{"bucket": "prior-only"},
									},
								},
							},
						},
					},
					"resource_changes": []map[string]interface{}{},
					"configuration":    map[string]interface{}{},
				},
			},
			want: model.Document{
				"resource": map[string]interface{}{},
				"data": map[string]interface{}{
					"aws_s3_bucket": map[string]interface{}{
						"both":       map[string]interface{}{"bucket": "planned", "_dd_meta": map[string]interface{}{"address": "data.aws_s3_bucket.both"}},
						"prior_only": map[string]interface{}{"bucket": "prior-only", "_dd_meta": map[string]interface{}{"address": "data.aws_s3_bucket.prior_only"}},
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
										"acl": "private",
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
							"acl":    "private",
							"bucket": "${__dd_unknown__}",

							"_dd_meta": map[string]interface{}{
								"address":    "aws_s3_bucket.main",
								"unknown":    map[string]interface{}{"bucket": true},
								"configured": map[string]interface{}{"bucket": true},
								"references": map[string]interface{}{},
							}},
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

							"_dd_meta": map[string]interface{}{"address": "aws_s3_bucket.main"}},
						"module.storage.backup": map[string]interface{}{
							"bucket": "backup-bucket",
							"acl":    "private",

							"_dd_meta": map[string]interface{}{"address": "module.storage.aws_s3_bucket.backup"}},
					},
					"aws_instance": map[string]interface{}{
						"web": map[string]interface{}{
							"instance_type": "t2.micro",

							"_dd_meta": map[string]interface{}{"address": "aws_instance.web"}},
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

							"_dd_meta": map[string]interface{}{"address": "aws_instance.web"}},
						"module.staging.web": map[string]interface{}{
							"instance_type": "t2.micro",
							"tags": map[string]interface{}{
								"Environment": "staging",
							},

							"_dd_meta": map[string]interface{}{"address": "module.staging.aws_instance.web"}},
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

							"_dd_meta": map[string]interface{}{"address": "aws_vpc.main"}},
					},
					"aws_subnet": map[string]interface{}{
						"module.networking.public": map[string]interface{}{
							"cidr_block": "10.0.1.0/24",

							"_dd_meta": map[string]interface{}{"address": "module.networking.aws_subnet.public"}},
					},
					"aws_security_group": map[string]interface{}{
						"module.networking.module.security.web": map[string]interface{}{
							"description": "Web traffic",

							"_dd_meta": map[string]interface{}{"address": "module.networking.module.security.aws_security_group.web"}},
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

							"_dd_meta": map[string]interface{}{"address": "module.app1.aws_s3_bucket.data"}},
						"module.app2.data": map[string]interface{}{
							"bucket": "app2-data",

							"_dd_meta": map[string]interface{}{"address": "module.app2.aws_s3_bucket.data"}},
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

							"_dd_meta": map[string]interface{}{"address": "aws_instance.web[0]"}},
						"web[1]": map[string]interface{}{
							"instance_type": "t2.micro",
							"tags": map[string]interface{}{
								"Name":  "web-1",
								"Index": float64(1),
							},

							"_dd_meta": map[string]interface{}{"address": "aws_instance.web[1]"}},
						"web[2]": map[string]interface{}{
							"instance_type": "t2.micro",
							"tags": map[string]interface{}{
								"Name":  "web-2",
								"Index": float64(2),
							},

							"_dd_meta": map[string]interface{}{"address": "aws_instance.web[2]"}},
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

							"_dd_meta": map[string]interface{}{"address": "aws_s3_bucket.data[\"prod\"]"}},
						"data[\"staging\"]": map[string]interface{}{
							"bucket": "staging-data-bucket",
							"acl":    "private",

							"_dd_meta": map[string]interface{}{"address": "aws_s3_bucket.data[\"staging\"]"}},
						"data[\"dev\"]": map[string]interface{}{
							"bucket": "dev-data-bucket",
							"acl":    "private",

							"_dd_meta": map[string]interface{}{"address": "aws_s3_bucket.data[\"dev\"]"}},
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

							"_dd_meta": map[string]interface{}{"address": "fakewebservices_database.prod_db"}},
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

							"_dd_meta": map[string]interface{}{"address": "data.aws_kms_key.by_alias"}},
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
				"resource": map[string]any{},
				"data": map[string]any{
					"aws_kms_key": map[string]any{
						"_dd_lines": map[string]any{
							"_dd_by_alias": map[string]any{"_dd_line": (float64)(14)},
						},
						"by_alias": map[string]any{
							"key_id": "alias/aws/s3",

							"_dd_meta": map[string]interface{}{"address": "data.aws_kms_key.by_alias"}},
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

							"_dd_meta": map[string]interface{}{"address": `data.aws_kms_key.by_alias["prod"]`}},
						`by_alias["dev"]`: map[string]any{
							"key_id": "alias/dev",

							"_dd_meta": map[string]interface{}{"address": `data.aws_kms_key.by_alias["dev"]`}},
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

							"_dd_meta": map[string]interface{}{"address": "data.aws_kms_key.by_alias"}},
						"module.storage.by_alias": map[string]any{
							"key_id": "alias/storage",

							"_dd_meta": map[string]interface{}{"address": "module.storage.data.aws_kms_key.by_alias"}},
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

// TestJson_parseTFPlan_dd_meta_correlation exercises _dd_meta on each plan
// resource, including for_each keys with a dot, "]", or quote.
func TestJson_parseTFPlan_dd_meta_correlation(t *testing.T) {
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
					"after_unknown": map[string]interface{}{"id": true, "tags": true},
				},
			},
			{
				"address": "aws_instance.web[0]",
				"change": map[string]interface{}{
					"after_unknown": map[string]interface{}{"id": true, "instance_type": true},
				},
			},
			{
				"address": "aws_s3_bucket.data[\"prod\"]",
				"change": map[string]interface{}{
					"after_unknown": map[string]interface{}{"id": true, "bucket": true},
				},
			},
			{
				"address": "aws_s3_bucket.data[\"a.b\"]",
				"change": map[string]interface{}{
					"after_unknown": map[string]interface{}{"id": true, "bucket": true},
				},
			},
			{
				"address": "aws_s3_bucket.data[\"a]b\"]",
				"change": map[string]interface{}{
					"after_unknown": map[string]interface{}{"id": true, "bucket": true},
				},
			},
			{
				"address": "aws_s3_bucket.data[\"a\\\"b\"]",
				"change": map[string]interface{}{
					"after_unknown": map[string]interface{}{"id": true, "bucket": true},
				},
			},
			{
				"address": "module.networking.aws_subnet.public",
				"change": map[string]interface{}{
					"after_unknown": map[string]interface{}{"id": true, "cidr_block": true},
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
							"tags":       map[string]interface{}{"references": []string{"var.tags"}},
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
	require.NotContains(t, got, "_dd_tfplan_meta")

	meta := func(resourceType, key string) map[string]interface{} {
		resourceTypes, ok := got["resource"].(map[string]interface{})
		require.True(t, ok)
		typeMap, ok := resourceTypes[resourceType].(map[string]interface{})
		require.True(t, ok, "resource.%s not found", resourceType)
		require.NotContains(t, typeMap, "_dd_meta")
		block, ok := typeMap[key].(map[string]interface{})
		require.True(t, ok, "resource.%s.%s not found", resourceType, key)
		entry, ok := block["_dd_meta"].(map[string]interface{})
		require.True(t, ok, "resource.%s.%s._dd_meta not found", resourceType, key)
		// This test covers address and unknown; references and configured
		// have their own tests.
		entry = maps.Clone(entry)
		delete(entry, "references")
		delete(entry, "configured")
		return entry
	}

	require.Equal(t, map[string]interface{}{
		"address": "aws_vpc.main",
		"unknown": map[string]interface{}{"tags": true},
	}, meta("aws_vpc", "main"))

	require.Equal(t, map[string]interface{}{
		"address": "aws_instance.web[0]",
		"unknown": map[string]interface{}{"instance_type": true},
	}, meta("aws_instance", "web[0]"))

	require.Equal(t, map[string]interface{}{
		"address": "aws_s3_bucket.data[\"prod\"]",
		"unknown": map[string]interface{}{"bucket": true},
	}, meta("aws_s3_bucket", "data[\"prod\"]"))

	require.Equal(t, map[string]interface{}{
		"address": "aws_s3_bucket.data[\"a.b\"]",
		"unknown": map[string]interface{}{"bucket": true},
	}, meta("aws_s3_bucket", "data[\"a.b\"]"))

	require.Equal(t, map[string]interface{}{
		"address": "aws_s3_bucket.data[\"a]b\"]",
		"unknown": map[string]interface{}{"bucket": true},
	}, meta("aws_s3_bucket", "data[\"a]b\"]"))

	require.Equal(t, map[string]interface{}{
		"address": "aws_s3_bucket.data[\"a\\\"b\"]",
		"unknown": map[string]interface{}{"bucket": true},
	}, meta("aws_s3_bucket", "data[\"a\\\"b\"]"))

	require.Equal(t, map[string]interface{}{
		"address": "module.networking.aws_subnet.public",
		"unknown": map[string]interface{}{"cidr_block": true},
	}, meta("aws_subnet", "module.networking.public"))
}

func referencesPlanDoc(t *testing.T, plannedRoot string, changeAddrs []string, configRoot string) model.Document {
	t.Helper()
	changes := make([]string, len(changeAddrs))
	for i, a := range changeAddrs {
		changes[i] = fmt.Sprintf(`{"address":%q,"change":{"actions":["create"],"after_unknown":{}}}`, a)
	}
	raw := fmt.Sprintf(`{"format_version":"1.2","terraform_version":"1.9.0",
		"planned_values":{"root_module":%s},
		"resource_changes":[%s],
		"configuration":{"root_module":%s}}`, plannedRoot, strings.Join(changes, ","), configRoot)
	var doc model.Document
	require.NoError(t, stdjson.Unmarshal([]byte(raw), &doc))
	return doc
}

func planMetaFor(t *testing.T, doc model.Document, addr string) map[string]interface{} {
	t.Helper()
	return ddMetaFor(t, mustParse(t, doc), addr)
}

func ddMetaFor(t *testing.T, got model.Document, addr string) map[string]interface{} {
	t.Helper()
	for _, section := range []string{"resource", "data", "ephemeral"} {
		byType, _ := got[section].(map[string]interface{})
		for _, typeBlocks := range byType {
			blocks, _ := typeBlocks.(map[string]interface{})
			for _, raw := range blocks {
				block, ok := raw.(map[string]interface{})
				if !ok {
					continue
				}
				meta, _ := block["_dd_meta"].(map[string]interface{})
				if meta["address"] == addr {
					return meta
				}
			}
		}
	}
	require.Failf(t, "no plan meta", "address %s", addr)
	return nil
}

func planAddresses(doc model.Document) []string {
	var out []string
	for _, section := range []string{"resource", "data", "ephemeral"} {
		byType, _ := doc[section].(map[string]interface{})
		for _, typeBlocks := range byType {
			blocks, _ := typeBlocks.(map[string]interface{})
			for _, raw := range blocks {
				block, ok := raw.(map[string]interface{})
				if !ok {
					continue
				}
				meta, _ := block["_dd_meta"].(map[string]interface{})
				if addr, _ := meta["address"].(string); addr != "" {
					out = append(out, addr)
				}
			}
		}
	}
	return out
}

func TestPlanReferencesDirectAndIndexed(t *testing.T) {
	planned := `{"resources":[
		{"address":"aws_subnet.s[0]","mode":"managed","type":"aws_subnet","name":"s","index":0,"values":{}},
		{"address":"aws_subnet.s[1]","mode":"managed","type":"aws_subnet","name":"s","index":1,"values":{}},
		{"address":"aws_instance.web","mode":"managed","type":"aws_instance","name":"web","values":{}}]}`
	addrs := []string{"aws_subnet.s[0]", "aws_subnet.s[1]", "aws_instance.web"}
	config := func(refs string) string {
		return `{"resources":[
			{"address":"aws_subnet.s","mode":"managed","type":"aws_subnet","name":"s","count_expression":{"constant_value":2},"expressions":{}},
			{"address":"aws_instance.web","mode":"managed","type":"aws_instance","name":"web","expressions":{"subnet_id":{"references":` + refs + `}}}]}`
	}

	indexed := referencesPlanDoc(t, planned, addrs, config(`["aws_subnet.s[0].id","aws_subnet.s[0]","aws_subnet.s"]`))
	require.Equal(t, map[string]interface{}{"subnet_id": []interface{}{"aws_subnet.s[0]"}},
		planMetaFor(t, indexed, "aws_instance.web")["references"])

	whole := referencesPlanDoc(t, planned, addrs, config(`["aws_subnet.s.id","aws_subnet.s"]`))
	meta := planMetaFor(t, whole, "aws_instance.web")
	require.Equal(t, map[string]interface{}{"subnet_id": []interface{}{"aws_subnet.s[0]", "aws_subnet.s[1]"}}, meta["references"])
	require.Equal(t, map[string]interface{}{}, planMetaFor(t, whole, "aws_subnet.s[0]")["references"])

	targets := planAddresses(mustParse(t, whole))
	for _, a := range meta["references"].(map[string]interface{})["subnet_id"].([]interface{}) {
		require.Contains(t, targets, a)
	}
}

func mustParse(t *testing.T, doc model.Document) model.Document {
	t.Helper()
	got, err := parseTFPlan(doc)
	require.NoError(t, err)
	return got
}

func TestPlanReferencesThroughVariableAndOutput(t *testing.T) {
	planned := `{"resources":[
			{"address":"aws_subnet.s[0]","mode":"managed","type":"aws_subnet","name":"s","index":0,"values":{}},
			{"address":"aws_subnet.s[1]","mode":"managed","type":"aws_subnet","name":"s","index":1,"values":{}},
			{"address":"aws_instance.app","mode":"managed","type":"aws_instance","name":"app","values":{}}],
		"child_modules":[
			{"address":"module.net[0]","resources":[
				{"address":"module.net[0].aws_subnet.s","mode":"managed","type":"aws_subnet","name":"s","values":{}},
				{"address":"module.net[0].aws_instance.inner","mode":"managed","type":"aws_instance","name":"inner","values":{}}]},
			{"address":"module.net[1]","resources":[
				{"address":"module.net[1].aws_subnet.s","mode":"managed","type":"aws_subnet","name":"s","values":{}},
				{"address":"module.net[1].aws_instance.inner","mode":"managed","type":"aws_instance","name":"inner","values":{}}]}]}`
	addrs := []string{
		"aws_subnet.s[0]", "aws_subnet.s[1]", "aws_instance.app",
		"module.net[0].aws_subnet.s", "module.net[0].aws_instance.inner",
		"module.net[1].aws_subnet.s", "module.net[1].aws_instance.inner",
	}
	config := `{"resources":[
			{"address":"aws_subnet.s","mode":"managed","type":"aws_subnet","name":"s","count_expression":{"constant_value":2},"expressions":{}},
			{"address":"aws_instance.app","mode":"managed","type":"aws_instance","name":"app",
			 "expressions":{"subnet_id":{"references":["module.net.subnet_id","module.net"]}}}],
		"module_calls":{"net":{
			"count_expression":{"constant_value":2},
			"expressions":{"subnet_id":{"references":["aws_subnet.s[1].id","aws_subnet.s[1]","aws_subnet.s"]}},
			"module":{
				"outputs":{"subnet_id":{"expression":{"references":["aws_subnet.s.id","aws_subnet.s"]}}},
				"resources":[
					{"address":"aws_subnet.s","mode":"managed","type":"aws_subnet","name":"s","expressions":{}},
					{"address":"aws_instance.inner","mode":"managed","type":"aws_instance","name":"inner",
					 "expressions":{"subnet_id":{"references":["var.subnet_id"]}}}]}}}}`
	doc := referencesPlanDoc(t, planned, addrs, config)

	for _, inst := range []string{"module.net[0]", "module.net[1]"} {
		require.Equal(t, map[string]interface{}{"subnet_id": []interface{}{"aws_subnet.s[1]"}},
			planMetaFor(t, doc, inst+".aws_instance.inner")["references"])
	}
	require.Equal(t,
		map[string]interface{}{"subnet_id": []interface{}{"module.net[0].aws_subnet.s", "module.net[1].aws_subnet.s"}},
		planMetaFor(t, doc, "aws_instance.app")["references"])

	targets := planAddresses(mustParse(t, doc))
	for _, a := range []string{"aws_subnet.s[1]", "module.net[0].aws_subnet.s", "module.net[1].aws_subnet.s"} {
		require.Contains(t, targets, a)
	}
}

func TestPlanReferencesNestedBlocksAndLocals(t *testing.T) {
	planned := `{"resources":[
		{"address":"aws_security_group.a","mode":"managed","type":"aws_security_group","name":"a","values":{}},
		{"address":"aws_security_group.b","mode":"managed","type":"aws_security_group","name":"b","values":{}},
		{"address":"aws_security_group.c","mode":"managed","type":"aws_security_group","name":"c","values":{}},
		{"address":"aws_s3_bucket.only_local","mode":"managed","type":"aws_s3_bucket","name":"only_local","values":{}}]}`
	addrs := []string{"aws_security_group.a", "aws_security_group.b", "aws_security_group.c", "aws_s3_bucket.only_local"}
	config := `{"resources":[
		{"address":"aws_security_group.c","mode":"managed","type":"aws_security_group","name":"c","expressions":{
			"name":{"references":["local.prefix"]},
			"ingress":[
				{"security_groups":{"references":["aws_security_group.a.id","aws_security_group.a"]}},
				{"security_groups":{"references":["aws_security_group.b.id","aws_security_group.b"]},"cidr_blocks":{"references":["local.cidrs"]}}]}},
		{"address":"aws_s3_bucket.only_local","mode":"managed","type":"aws_s3_bucket","name":"only_local","expressions":{
			"bucket":{"references":["local.name"]}}}]}`
	doc := referencesPlanDoc(t, planned, addrs, config)

	require.Equal(t, map[string]interface{}{
		"ingress": []interface{}{
			map[string]interface{}{"security_groups": []interface{}{"aws_security_group.a"}},
			map[string]interface{}{"security_groups": []interface{}{"aws_security_group.b"}},
		},
	}, planMetaFor(t, doc, "aws_security_group.c")["references"])
	require.Equal(t, map[string]interface{}{}, planMetaFor(t, doc, "aws_s3_bucket.only_local")["references"])
}

// A read of a block the plan neither plans nor declares cannot be traced: the
// attribute is left out of references rather than recorded as reading nothing.
func TestPlanReferencesUndeclaredBlockIsUntraced(t *testing.T) {
	planned := `{"resources":[{"address":"aws_instance.web","mode":"managed","type":"aws_instance","name":"web","values":{}}]}`
	config := `{"resources":[
		{"address":"aws_subnet.gone","mode":"managed","type":"aws_subnet","name":"gone","count_expression":{"constant_value":0},"expressions":{}},
		{"address":"aws_instance.web","mode":"managed","type":"aws_instance","name":"web","expressions":{
			"subnet_id":{"references":["aws_subnet.missing.id","aws_subnet.missing"]},
			"zero":{"references":["aws_subnet.gone.id","aws_subnet.gone"]}}}]}`
	doc := referencesPlanDoc(t, planned, []string{"aws_instance.web"}, config)

	require.Equal(t, map[string]interface{}{"zero": []interface{}{}},
		planMetaFor(t, doc, "aws_instance.web")["references"],
		"a declared block with no instance reads nothing; an undeclared one is untraced")
}

func TestPlanReferencesDataAndEphemeral(t *testing.T) {
	planned := `{"resources":[
		{"address":"aws_iam_role_policy.p","mode":"managed","type":"aws_iam_role_policy","name":"p","values":{}},
		{"address":"data.aws_iam_policy_document.p","mode":"data","type":"aws_iam_policy_document","name":"p","values":{}}]}`
	config := `{"resources":[
		{"address":"aws_iam_role.r","mode":"managed","type":"aws_iam_role","name":"r","count_expression":{"constant_value":0},"expressions":{}},
		{"address":"data.aws_iam_policy_document.p","mode":"data","type":"aws_iam_policy_document","name":"p","expressions":{
			"source_policy_documents":{"references":["aws_iam_role.r.arn","aws_iam_role.r"]}}},
		{"address":"aws_iam_role_policy.p","mode":"managed","type":"aws_iam_role_policy","name":"p","expressions":{
			"policy":{"references":["data.aws_iam_policy_document.p.json","data.aws_iam_policy_document.p"]},
			"secret":{"references":["ephemeral.random_password.pw.result","ephemeral.random_password.pw"]}}}]}`
	doc := referencesPlanDoc(t, planned, []string{"aws_iam_role_policy.p"}, config)

	require.Equal(t, map[string]interface{}{"policy": []interface{}{"data.aws_iam_policy_document.p"}},
		planMetaFor(t, doc, "aws_iam_role_policy.p")["references"])
	require.Equal(t, map[string]interface{}{"source_policy_documents": []interface{}{}},
		planMetaFor(t, doc, "data.aws_iam_policy_document.p")["references"])
}

func TestPlanReferencesSkipDestroyedPriorStateInstances(t *testing.T) {
	planned := `{"resources":[
		{"address":"aws_subnet.s[0]","mode":"managed","type":"aws_subnet","name":"s","index":0,"values":{}},
		{"address":"aws_subnet.s[1]","mode":"managed","type":"aws_subnet","name":"s","index":1,"values":{}},
		{"address":"aws_instance.web","mode":"managed","type":"aws_instance","name":"web","values":{}}]}`
	config := `{"resources":[
		{"address":"aws_subnet.s","mode":"managed","type":"aws_subnet","name":"s","count_expression":{"constant_value":2},"expressions":{}},
		{"address":"aws_instance.web","mode":"managed","type":"aws_instance","name":"web","expressions":{
			"subnet_id":{"references":["aws_subnet.s.id","aws_subnet.s"]}}}]}`
	doc := referencesPlanDoc(t, planned, []string{"aws_subnet.s[0]", "aws_subnet.s[1]", "aws_instance.web"}, config)
	var extra map[string]interface{}
	require.NoError(t, stdjson.Unmarshal([]byte(`{
		"resource_changes":[
			{"address":"aws_subnet.s[2]","change":{"actions":["delete"],"after_unknown":{}}}],
		"prior_state":{"format_version":"1.0","values":{"root_module":{"resources":[
			{"address":"aws_subnet.s[0]","mode":"managed","type":"aws_subnet","name":"s","index":0,"values":{}},
			{"address":"aws_subnet.s[2]","mode":"managed","type":"aws_subnet","name":"s","index":2,"values":{}},
			{"address":"aws_subnet.s[3]","mode":"managed","type":"aws_subnet","name":"s","index":3,"values":{}}]}}}}`), &extra))
	doc["resource_changes"] = append(doc["resource_changes"].([]interface{}), extra["resource_changes"].([]interface{})...)
	doc["prior_state"] = extra["prior_state"]

	require.Equal(t, map[string]interface{}{"subnet_id": []interface{}{"aws_subnet.s[0]", "aws_subnet.s[1]"}},
		planMetaFor(t, doc, "aws_instance.web")["references"])
}

func TestPlanReferencesIgnoreAddressesNoDocumentCarries(t *testing.T) {
	planned := `{"resources":[
		{"address":"aws_subnet.s[0]","mode":"managed","type":"aws_subnet","name":"s","index":0,"values":{}},
		{"address":"aws_instance.web","mode":"managed","type":"aws_instance","name":"web","values":{}}]}`
	config := `{"resources":[
		{"address":"aws_subnet.s","mode":"managed","type":"aws_subnet","name":"s","count_expression":{"constant_value":1},"expressions":{}},
		{"address":"aws_instance.web","mode":"managed","type":"aws_instance","name":"web","expressions":{
			"subnet_id":{"references":["aws_subnet.s[5].id","aws_subnet.s[5]","aws_subnet.s"]},
			"secret":{"references":["ephemeral.random_password.pw[0].result","ephemeral.random_password.pw[0]","ephemeral.random_password.pw"]},
			"other":{"references":["aws_subnet.s[0].id","aws_subnet.s[0]","aws_subnet.s"]}}}]}`
	doc := referencesPlanDoc(t, planned, []string{"aws_subnet.s[0]", "aws_instance.web"}, config)

	require.Equal(t, map[string]interface{}{"other": []interface{}{"aws_subnet.s[0]"}, "subnet_id": []interface{}{}},
		planMetaFor(t, doc, "aws_instance.web")["references"])
}

func TestPlanReferencesIgnoreLocalEachCountAndPathLookalikes(t *testing.T) {
	planned := `{"resources":[
		{"address":"local.x","mode":"managed","type":"local","name":"x","values":{}},
		{"address":"each.value","mode":"managed","type":"each","name":"value","values":{}},
		{"address":"count.index","mode":"managed","type":"count","name":"index","values":{}},
		{"address":"terraform.data","mode":"managed","type":"terraform","name":"data","values":{}},
		{"address":"aws_instance.web","mode":"managed","type":"aws_instance","name":"web","values":{}}]}`
	addrs := []string{"local.x", "each.value", "count.index", "terraform.data", "aws_instance.web"}
	config := `{"resources":[
		{"address":"aws_instance.web","mode":"managed","type":"aws_instance","name":"web","expressions":{
			"a":{"references":["local.x"]},
			"b":{"references":["each.value"]},
			"c":{"references":["count.index"]},
			"d":{"references":["terraform.data"]}}}]}`
	doc := referencesPlanDoc(t, planned, addrs, config)

	require.Equal(t, map[string]interface{}{"c": []interface{}{}, "d": []interface{}{}},
		planMetaFor(t, doc, "aws_instance.web")["references"])
}

func chainModuleConfig(level, depth int) string {
	refs := `["aws_x.y"]`
	resources := `[{"address":"aws_x.y","mode":"managed","type":"aws_x","name":"y","expressions":{}}]`
	calls := `{}`
	if level < depth {
		next := fmt.Sprintf("module.l%d", level+1)
		refs = fmt.Sprintf(`[%q,%q]`, next+".o", next+".p")
		resources = `[]`
		calls = fmt.Sprintf(`{"l%d":{"expressions":{},"module":%s}}`, level+1, chainModuleConfig(level+1, depth))
	}
	out := `{"expression":{"references":` + refs + `}}`
	return fmt.Sprintf(`{"outputs":{"o":%s,"p":%s},"resources":%s,"module_calls":%s}`, out, out, resources, calls)
}

func TestPlanConfigOutputsAndModuleCalls(t *testing.T) {
	planned := `{"resources":[
		{"address":"aws_security_group.temporal_opensearch[\"dev\"]","mode":"managed","type":"aws_security_group","name":"temporal_opensearch","index":"dev","values":{}},
		{"address":"aws_security_group.temporal_opensearch[\"prod\"]","mode":"managed","type":"aws_security_group","name":"temporal_opensearch","index":"prod","values":{}}]}`
	config := `{"outputs":{"sg":{"expression":{"references":["aws_security_group.temporal_opensearch"]}}},
		"module_calls":{"child":{"source":"./child","expressions":{"id":{"references":["aws_security_group.temporal_opensearch[\"dev\"].id","aws_security_group.temporal_opensearch[\"dev\"]"]}}}},
		"resources":[{"address":"aws_security_group.temporal_opensearch","mode":"managed","type":"aws_security_group","name":"temporal_opensearch","expressions":{}}]}`
	doc := mustParse(t, referencesPlanDoc(t, planned, []string{
		`aws_security_group.temporal_opensearch["dev"]`,
		`aws_security_group.temporal_opensearch["prod"]`,
	}, config))

	output := doc["output"].(map[string]interface{})["sg"].(map[string]interface{})
	require.Equal(t, "${__dd_unknown__}", output["value"])
	meta := output["_dd_meta"].(map[string]interface{})
	require.Equal(t, "output.sg", meta["address"])
	require.ElementsMatch(t, []interface{}{
		`aws_security_group.temporal_opensearch["dev"]`,
		`aws_security_group.temporal_opensearch["prod"]`,
	}, meta["references"].(map[string]interface{})["value"])

	call := doc["module"].(map[string]interface{})["child"].(map[string]interface{})
	require.Equal(t, "./child", call["source"])
	require.Equal(t, []interface{}{`aws_security_group.temporal_opensearch["dev"]`},
		call["_dd_meta"].(map[string]interface{})["references"].(map[string]interface{})["id"])
	require.Equal(t, "${__dd_unknown__}", call["id"], "a referenced argument is present and unknown")
	require.Equal(t, map[string]interface{}{"id": true}, call["_dd_meta"].(map[string]interface{})["unknown"])
	require.Equal(t, map[string]interface{}{"value": true}, meta["unknown"])
}

func TestPlanConfigOutputSensitiveModuleVersionAndZeroCalls(t *testing.T) {
	planned := `{"resources":[{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","values":{}}]}`
	config := `{"outputs":{"secret":{"sensitive":true,"expression":{"constant_value":"x"}}},
		"module_calls":{
			"pinned":{"source":"org/mod/aws","version_constraint":"~> 1.2","expressions":{}},
			"none":{"source":"./none","count_expression":{"constant_value":0},"expressions":{}},
			"empty":{"source":"./empty","for_each_expression":{"constant_value":{}},"expressions":{}},
			"computed":{"source":"./computed","count_expression":{"references":["var.n"]},"expressions":{}}},
		"resources":[{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","expressions":{}}]}`
	doc := mustParse(t, referencesPlanDoc(t, planned, []string{"aws_s3_bucket.b"}, config))

	output := doc["output"].(map[string]interface{})["secret"].(map[string]interface{})
	require.Equal(t, true, output["sensitive"])
	require.Equal(t, "x", output["value"])

	calls := doc["module"].(map[string]interface{})
	require.Equal(t, "~> 1.2", calls["pinned"].(map[string]interface{})["version"])
	require.NotContains(t, calls, "none", "count = 0 declares no instance")
	require.NotContains(t, calls, "empty", "an empty for_each declares no instance")
	require.Contains(t, calls, "computed", "a computed count may still expand")
}

func TestPlanReferencesDeepModuleChainStaysLinear(t *testing.T) {
	const depth = 18
	deepest := ""
	for i := 1; i <= depth; i++ {
		deepest += fmt.Sprintf("module.l%d.", i)
	}
	deepest += "aws_x.y"
	planned := fmt.Sprintf(`{"resources":[{"address":"aws_instance.app","mode":"managed","type":"aws_instance","name":"app","values":{}}],
		"child_modules":[{"address":%q,"resources":[{"address":%q,"mode":"managed","type":"aws_x","name":"y","values":{}}]}]}`,
		strings.TrimSuffix(deepest, ".aws_x.y"), deepest)
	config := fmt.Sprintf(`{"resources":[{"address":"aws_instance.app","mode":"managed","type":"aws_instance","name":"app",
			"expressions":{"x":{"references":["module.l1.o","module.l1.p"]}}}],
		"module_calls":{"l1":{"expressions":{},"module":%s}}}`, chainModuleConfig(1, depth))
	doc := referencesPlanDoc(t, planned, []string{"aws_instance.app", deepest}, config)

	start := time.Now()
	meta := planMetaFor(t, doc, "aws_instance.app")
	require.Equal(t, map[string]interface{}{"x": []interface{}{deepest}}, meta["references"])
	require.Less(t, time.Since(start), 3*time.Second)
}

func valuesPlanDoc(t *testing.T, values, afterUnknown, expressions string) model.Document {
	t.Helper()
	raw := fmt.Sprintf(`{"format_version":"1.2","terraform_version":"1.9.0",
		"planned_values":{"root_module":{"resources":[
			{"address":"aws_instance.web[0]","mode":"managed","type":"aws_instance","name":"web","index":0,"values":%s}]}},
		"resource_changes":[{"address":"aws_instance.web[0]","mode":"managed","type":"aws_instance","name":"web","index":0,
			"change":{"actions":["create"],"before":null,"after":%s,"after_unknown":%s}}],
		"configuration":{"root_module":{"resources":[
			{"address":"aws_instance.web","mode":"managed","type":"aws_instance","name":"web",
			 "expressions":%s,"count_expression":{"constant_value":1}}]}}}`, values, values, afterUnknown, expressions)
	var doc model.Document
	require.NoError(t, stdjson.Unmarshal([]byte(raw), &doc))
	return doc
}

func plannedWeb(t *testing.T, doc model.Document) (values, meta map[string]interface{}) {
	t.Helper()
	got := mustParse(t, doc)
	block := got["resource"].(map[string]interface{})["aws_instance"].(map[string]interface{})["web[0]"].(map[string]interface{})
	meta, _ = block["_dd_meta"].(map[string]interface{})
	values = map[string]interface{}{}
	for k, v := range block {
		if k != "_dd_meta" {
			values[k] = v
		}
	}
	return values, meta
}

func TestPlanValuesUnknownPlaceholder(t *testing.T) {
	values, meta := plannedWeb(t, valuesPlanDoc(t, `{"name":"a"}`, `{"id":true,"arn":true,"name":false}`,
		`{"name":{"constant_value":"a"},"id":{"references":["var.id"]},"arn":{"references":["var.arn"]}}`))
	require.Equal(t, map[string]interface{}{"name": "a", "id": "${__dd_unknown__}", "arn": "${__dd_unknown__}"}, values)
	require.Equal(t, map[string]interface{}{"id": true, "arn": true}, meta["unknown"])
	require.NotContains(t, meta, "after_unknown")

	values, meta = plannedWeb(t, valuesPlanDoc(t, `{"name":"a"}`, `{"name":false}`, `{"name":{"constant_value":"a"}}`))
	require.Equal(t, map[string]interface{}{"name": "a"}, values)
	require.NotContains(t, meta, "unknown")
}

func TestPlanValuesUnknownListPositions(t *testing.T) {
	values, meta := plannedWeb(t, valuesPlanDoc(t, `{"ips":["a",null,"c"]}`, `{"ips":[false,true,false]}`,
		`{"ips":{"references":["aws_eip.e.public_ip","aws_eip.e"]}}`))
	require.Equal(t, map[string]interface{}{"ips": []interface{}{"a", "${__dd_unknown__}", "c"}}, values)
	require.Equal(t, map[string]interface{}{"ips": []interface{}{false, true, false}}, meta["unknown"])

	values, meta = plannedWeb(t, valuesPlanDoc(t, `{"ips":["a",null,"c"],"rules":[null,{"port":1}]}`, `{}`,
		`{"ips":{"references":["var.ips"]}}`))
	require.Equal(t, map[string]interface{}{
		"ips":   []interface{}{"a", nil, "c"},
		"rules": []interface{}{nil, map[string]interface{}{"port": float64(1)}},
	}, values)
	require.NotContains(t, meta, "unknown")
}

func TestPlanValuesUnknownListMissingFromValues(t *testing.T) {
	values, meta := plannedWeb(t, valuesPlanDoc(t, `{"name":"a"}`,
		`{"name":false,"ips":[true,true],"ingress":[{"id":true},{}],"matrix":[[true],false]}`,
		`{"name":{"constant_value":"a"},"ips":{"references":["var.ips"]},"matrix":{"references":["var.matrix"]},
		  "ingress":[{"id":{"references":["var.id"]}},{}]}`))
	require.Equal(t, map[string]interface{}{
		"name": "a",
		"ips":  []interface{}{"${__dd_unknown__}", "${__dd_unknown__}"},
		"ingress": []interface{}{
			map[string]interface{}{"id": "${__dd_unknown__}"},
			map[string]interface{}{},
		},
		"matrix": []interface{}{[]interface{}{"${__dd_unknown__}"}, nil},
	}, values)
	require.Equal(t, map[string]interface{}{
		"ips":     []interface{}{true, true},
		"ingress": []interface{}{map[string]interface{}{"id": true}, map[string]interface{}{}},
		"matrix":  []interface{}{[]interface{}{true}, false},
	}, meta["unknown"])

	values, _ = plannedWeb(t, valuesPlanDoc(t, `{"ips":null}`, `{"ips":[true]}`, `{"ips":{"references":["var.ips"]}}`))
	require.Equal(t, map[string]interface{}{"ips": []interface{}{"${__dd_unknown__}"}}, values)
}

func TestPlanValuesConfiguredEmptyListInAnyBlockOrder(t *testing.T) {
	values, _ := plannedWeb(t, valuesPlanDoc(t,
		`{"ingress":[{"from_port":443,"ipv6_cidr_blocks":[]},{"from_port":80,"prefix_list_ids":[]}]}`,
		`{"ingress":[{},{}]}`,
		`{"ingress":[{"from_port":{"constant_value":80}},{"from_port":{"constant_value":443},"ipv6_cidr_blocks":{"constant_value":[]}}]}`))
	require.Equal(t, map[string]interface{}{"ingress": []interface{}{
		map[string]interface{}{"from_port": float64(443), "ipv6_cidr_blocks": []interface{}{}},
		map[string]interface{}{"from_port": float64(80)},
	}}, values)
}

func TestPlanValuesConfiguredEmptyListPastConfiguredBlocks(t *testing.T) {
	values, _ := plannedWeb(t, valuesPlanDoc(t,
		`{"ingress":[{"from_port":80,"cidr_blocks":[]},{"from_port":81,"cidr_blocks":[]},{"from_port":82,"cidr_blocks":[]}]}`,
		`{"ingress":[{},{},{}]}`,
		`{"ingress":[{"from_port":{"references":["each.value"]},"cidr_blocks":{"constant_value":[]}}]}`))
	block := func(port float64) map[string]interface{} {
		return map[string]interface{}{"from_port": port, "cidr_blocks": []interface{}{}}
	}
	require.Equal(t, map[string]interface{}{"ingress": []interface{}{block(80), block(81), block(82)}}, values)
}

func TestPlanValuesDynamicBlockDropsEmptyLists(t *testing.T) {
	values, _ := plannedWeb(t, valuesPlanDoc(t,
		`{"ingress":[{"from_port":80,"cidr_blocks":[],"self":false}],"egress":[],"name":"a"}`,
		`{"ingress":[{}]}`,
		`{"name":{"constant_value":"a"}}`))
	require.Equal(t, map[string]interface{}{
		"ingress": []interface{}{map[string]interface{}{"from_port": float64(80), "self": false}},
		"name":    "a",
	}, values)
}

func TestPlanUnknownShapeMatchesSourceUnknowns(t *testing.T) {
	unknownString := cty.UnknownVal(cty.String)
	r := &tfeval.ResolvedResource{Attributes: map[string]cty.Value{
		"name": cty.StringVal("a"),
		"id":   unknownString,
		"ingress": cty.ListVal([]cty.Value{
			cty.ObjectVal(map[string]cty.Value{"cidr_blocks": cty.ListVal([]cty.Value{cty.StringVal("10.0.0.0/8")})}),
			cty.ObjectVal(map[string]cty.Value{"cidr_blocks": cty.ListVal([]cty.Value{unknownString, cty.StringVal("10.0.0.0/8")})}),
		}),
		"matrix": cty.TupleVal([]cty.Value{
			cty.ListVal([]cty.Value{cty.StringVal("a")}),
			cty.ListVal([]cty.Value{unknownString, cty.StringVal("b")}),
		}),
	}}
	var values, afterUnknown map[string]any
	require.NoError(t, stdjson.Unmarshal([]byte(`{"name":"a","ingress":[{"cidr_blocks":["10.0.0.0/8"]},{"cidr_blocks":[null,"10.0.0.0/8"]}],"matrix":[["a"],[null,"b"]]}`), &values))
	require.NoError(t, stdjson.Unmarshal([]byte(`{"name":false,"id":true,"ingress":[{"cidr_blocks":[false]},{"cidr_blocks":[true,false]}],"matrix":[[false],[true,false]]}`), &afterUnknown))
	want := map[string]any{
		"id":      true,
		"ingress": []any{map[string]any{}, map[string]any{"cidr_blocks": []any{true, false}}},
		"matrix":  []any{false, []any{true, false}},
	}
	require.Equal(t, want, tfeval.Unknowns(r, nil))
	unknown, _ := planValues(values, afterUnknown, nil)
	require.Equal(t, want, unknown)
}

func TestPlanValuesUnknownNestedBlock(t *testing.T) {
	values, meta := plannedWeb(t, valuesPlanDoc(t,
		`{"ingress":[{"from_port":80},{"from_port":443}]}`,
		`{"ingress":[{},{"id":true,"description":true}]}`,
		`{"ingress":[{"from_port":{"constant_value":80}},{"from_port":{"constant_value":443},"description":{"references":["var.d"]}}]}`))
	require.Equal(t, map[string]interface{}{"ingress": []interface{}{
		map[string]interface{}{"from_port": float64(80)},
		map[string]interface{}{"from_port": float64(443), "description": "${__dd_unknown__}"},
	}}, values)
	require.Equal(t, map[string]interface{}{"ingress": []interface{}{map[string]interface{}{}, map[string]interface{}{"description": true}}}, meta["unknown"])

	// after_unknown marks the block type as a whole when a dynamic sibling
	// makes the count unknown. Written instances stay in the body.
	values, meta = plannedWeb(t, valuesPlanDoc(t, `{}`, `{"ingress":true}`, `{"ingress":[{"from_port":{"references":["var.p"]}}]}`))
	require.Equal(t, map[string]interface{}{"ingress": []interface{}{map[string]interface{}{"from_port": "${__dd_unknown__}"}}}, values)
	require.Equal(t, map[string]interface{}{"ingress": true}, meta["unknown"])
}

func TestPlanValuesOmitUnconfiguredUnknowns(t *testing.T) {
	values, meta := plannedWeb(t, valuesPlanDoc(t,
		`{"name":"a","tags":{"env":"x"},"ingress":[{"from_port":80}],"ips":["a",null],"timeouts":[{"create":null}]}`,
		`{"id":true,"name":false,"tags":{"owner":true},"ingress":[{"cidr":true,"rule_id":true}],"ips":[false,true],"timeouts":[{"create":true}],"blocks":[{"id":true}]}`,
		`{"name":{"constant_value":"a"},"tags":{"references":["var.owner"]},"ingress":[{"from_port":{"constant_value":80},"cidr":{"references":["var.cidr"]}}]}`))
	require.Equal(t, map[string]interface{}{
		"name":     "a",
		"tags":     map[string]interface{}{"env": "x", "owner": "${__dd_unknown__}"},
		"ingress":  []interface{}{map[string]interface{}{"from_port": float64(80), "cidr": "${__dd_unknown__}"}},
		"ips":      []interface{}{"a", nil},
		"timeouts": []interface{}{map[string]interface{}{"create": "${__dd_unknown__}"}},
	}, values)
	require.Equal(t, map[string]interface{}{
		"tags":     map[string]interface{}{"owner": true},
		"ingress":  []interface{}{map[string]interface{}{"cidr": true}},
		"timeouts": []interface{}{map[string]interface{}{"create": true}},
	}, meta["unknown"], "computed id, rule_id, ips and blocks are not written; timeouts is a list of blocks, so it may be dynamic")
}

// Configuration expressions leave dynamic blocks out, so a planned list of
// blocks nobody configured counts as written. A computed list of objects the
// provider fills looks the same in a plan: it is listed as written too.
func TestPlanValuesUnconfiguredListOfObjectsCountsAsWritten(t *testing.T) {
	values, meta := plannedWeb(t, valuesPlanDoc(t,
		`{"bucket":"b","versioning":[{"enabled":false,"mfa_delete":false}],"tags_all":{"env":"x"},"domain_validation_options":[]}`,
		`{"arn":true,"versioning":[{}],"tags_all":{}}`,
		`{"bucket":{"constant_value":"b"}}`))
	require.Equal(t, map[string]interface{}{
		"bucket":     "b",
		"versioning": []interface{}{map[string]interface{}{"enabled": false, "mfa_delete": false}},
		"tags_all":   map[string]interface{}{"env": "x"},
	}, values)
	require.Equal(t, map[string]interface{}{
		"bucket": true,
		"versioning": []interface{}{map[string]interface{}{"enabled": true, "mfa_delete": true}},
	}, meta["configured"],
		"an unconfigured list of objects is written as a list of shapes, not a boolean")
	require.NotContains(t, meta, "unknown")
}

func TestPlanValuesComputedMapIsNotConfigured(t *testing.T) {
	values, meta := plannedWeb(t, valuesPlanDoc(t,
		`{"bucket":"b","tags_all":{"_dd_lines":{"_dd__default":{"_dd_line":3}}}}`,
		`{"tags_all":{"owner":true}}`,
		`{"bucket":{"constant_value":"b"}}`))
	require.Equal(t, map[string]interface{}{"bucket": true}, meta["configured"],
		"line info does not make an empty computed map look written")
	require.NotContains(t, meta, "unknown")
	require.NotContains(t, values["tags_all"], "owner")
}

func TestPlanValuesFillUnknownsInDynamicBlock(t *testing.T) {
	values, meta := plannedWeb(t, valuesPlanDoc(t,
		`{"ingress":[{"from_port":80}]}`,
		`{"ingress":[{"description":true}]}`,
		`{}`))
	require.Equal(t, map[string]interface{}{"ingress": []interface{}{
		map[string]interface{}{"from_port": float64(80), "description": "${__dd_unknown__}"},
	}}, values)
	require.Equal(t, map[string]interface{}{"ingress": []interface{}{map[string]interface{}{"description": true}}}, meta["unknown"])

	values, _ = plannedWeb(t, valuesPlanDoc(t, `{"tags":{}}`, `{"tags":{"owner":true}}`, `{}`))
	require.Equal(t, map[string]interface{}{"tags": map[string]interface{}{}}, values)
}

func TestPlanValuesDropNulls(t *testing.T) {
	values, _ := plannedWeb(t, valuesPlanDoc(t,
		`{"description":null,"enabled":false,"count":0,"name":"","tags":{},"ingress":[{"description":null,"from_port":80}]}`,
		`{"ingress":[{}]}`,
		`{"enabled":{"constant_value":false},"ingress":[{"from_port":{"constant_value":80}}]}`))
	require.Equal(t, map[string]interface{}{
		"enabled": false, "count": float64(0), "name": "", "tags": map[string]interface{}{},
		"ingress": []interface{}{map[string]interface{}{"from_port": float64(80)}},
	}, values)
}

func TestPlanValuesDropUnconfiguredEmptyBlocks(t *testing.T) {
	values, _ := plannedWeb(t, valuesPlanDoc(t,
		`{"ebs_block_device":[],"ingress":[],"root_block_device":[{"tags":[],"throughput":[]}]}`,
		`{"ebs_block_device":[],"ingress":[],"root_block_device":[{}]}`,
		`{"ingress":[],"root_block_device":[{"throughput":{"constant_value":[]}}]}`))
	require.Equal(t, map[string]interface{}{
		"ingress":           []interface{}{},
		"root_block_device": []interface{}{map[string]interface{}{"throughput": []interface{}{}}},
	}, values)

	doc := valuesPlanDoc(t, `{"ebs_block_device":[],"name":"a"}`, `{}`, `{}`)
	doc["configuration"] = map[string]interface{}{}
	values, _ = plannedWeb(t, doc)
	require.Equal(t, map[string]interface{}{"name": "a"}, values)
}

func TestPlanValuesKeepEmptyListsInsideAttributes(t *testing.T) {
	values, _ := plannedWeb(t, valuesPlanDoc(t,
		`{"settings":{"mode":"x","ports":[],"note":null},"rules":[{"cidrs":[]}],"computed":{"ports":[]},
		  "statement":[{"principals":[],"effect":"Allow"}]}`,
		`{}`,
		`{"settings":{"constant_value":{"mode":"x","ports":[]}},"rules":{"references":["var.rules"]}}`))
	require.Equal(t, map[string]interface{}{
		"settings":  map[string]interface{}{"mode": "x", "ports": []interface{}{}},
		"rules":     []interface{}{map[string]interface{}{"cidrs": []interface{}{}}},
		"computed":  map[string]interface{}{},
		"statement": []interface{}{map[string]interface{}{"effect": "Allow"}},
	}, values, "an empty list is kept only in a written attribute's value")
}

func TestPlanValuesKeepLineBookkeeping(t *testing.T) {
	values, _ := plannedWeb(t, valuesPlanDoc(t,
		`{"description":null,"name":"a","_dd_lines":{"_dd_description":{"_dd_line":7},"_dd_name":{"_dd_line":8}}}`,
		`{}`, `{"name":{"constant_value":"a"}}`))
	require.Equal(t, map[string]interface{}{
		"name": "a",
		"_dd_lines": map[string]interface{}{
			"_dd_description": map[string]interface{}{"_dd_line": float64(7)},
			"_dd_name":        map[string]interface{}{"_dd_line": float64(8)},
		},
	}, values)
}

func TestPlanValuesPriorStateData(t *testing.T) {
	raw := `{"format_version":"1.2","terraform_version":"1.9.0",
		"planned_values":{"root_module":{}},
		"prior_state":{"format_version":"1.0","values":{"root_module":{"resources":[
			{"address":"data.aws_ami.u","mode":"data","type":"aws_ami","name":"u","values":{"id":"ami-1","kernel_id":null,"block_device_mappings":[]}}]}}},
		"resource_changes":[],
		"configuration":{"root_module":{"resources":[
			{"address":"data.aws_ami.u","mode":"data","type":"aws_ami","name":"u","expressions":{"most_recent":{"constant_value":true}}}]}}}`
	var doc model.Document
	require.NoError(t, stdjson.Unmarshal([]byte(raw), &doc))
	got := mustParse(t, doc)
	block := got["data"].(map[string]interface{})["aws_ami"].(map[string]interface{})["u"].(map[string]interface{})
	require.Equal(t, "ami-1", block["id"])
	require.Equal(t, map[string]interface{}{
		"address":    "data.aws_ami.u",
		"references": map[string]interface{}{"most_recent": []interface{}{}},
	}, block["_dd_meta"])
}

func TestPlanValuesPlannedDataSourceUnknown(t *testing.T) {
	raw := `{"format_version":"1.2","terraform_version":"1.9.0",
		"planned_values":{"root_module":{"resources":[
			{"address":"data.aws_ami.u","mode":"data","type":"aws_ami","name":"u","values":{"most_recent":true,"kernel_id":null}}]}},
		"prior_state":{"format_version":"1.0","values":{"root_module":{"resources":[
			{"address":"data.aws_ami.u","mode":"data","type":"aws_ami","name":"u","values":{"most_recent":true,"id":"ami-0"}}]}}},
		"resource_changes":[{"address":"data.aws_ami.u","mode":"data","type":"aws_ami","name":"u",
			"change":{"actions":["read"],"before":null,"after":{"most_recent":true},"after_unknown":{"id":true,"kernel_id":true}}}],
		"configuration":{"root_module":{"resources":[
			{"address":"data.aws_ami.u","mode":"data","type":"aws_ami","name":"u","expressions":{"most_recent":{"constant_value":true}}}]}}}`
	var doc model.Document
	require.NoError(t, stdjson.Unmarshal([]byte(raw), &doc))
	got := mustParse(t, doc)
	block := got["data"].(map[string]interface{})["aws_ami"].(map[string]interface{})["u"].(map[string]interface{})
	require.Equal(t, true, block["most_recent"])
	require.Equal(t, map[string]interface{}{
		"address":    "data.aws_ami.u",
		"references": map[string]interface{}{"most_recent": []interface{}{}},
		"configured": map[string]interface{}{"most_recent": true},
	}, block["_dd_meta"], "the computed id and kernel_id are not written")
}

func TestPlanValuesPriorStateKeepsPlannedDataSourceMeta(t *testing.T) {
	const planned = `"planned_values":{"root_module":{"resources":[
			{"address":"data.aws_ami.u","mode":"data","type":"aws_ami","name":"u","values":{"owners":["self"]}}]}},
		"resource_changes":[{"address":"data.aws_ami.u","mode":"data","type":"aws_ami","name":"u",
			"change":{"actions":["read"],"before":null,"after":{"owners":["self"]},"after_unknown":{"id":true,"name_regex":true}}}],
		"configuration":{"root_module":{"resources":[
			{"address":"data.aws_ami.u","mode":"data","type":"aws_ami","name":"u","expressions":{
				"owners":{"references":["var.owner"]},"name_regex":{"references":["var.regex"]}}}]}}`
	const prior = `"prior_state":{"format_version":"1.0","values":{"root_module":{"resources":[
			{"address":"data.aws_ami.u","mode":"data","type":"aws_ami","name":"u","values":{"owners":["self"],"id":"ami-0"}}]}}},`
	parse := func(raw string) map[string]interface{} {
		var doc model.Document
		require.NoError(t, stdjson.Unmarshal([]byte(raw), &doc))
		block := mustParse(t, doc)["data"].(map[string]interface{})["aws_ami"].(map[string]interface{})["u"].(map[string]interface{})
		return block["_dd_meta"].(map[string]interface{})
	}
	want := parse(`{"format_version":"1.2","terraform_version":"1.9.0",` + planned + `}`)
	require.Equal(t, map[string]interface{}{
		"address":    "data.aws_ami.u",
		"unknown":    map[string]interface{}{"name_regex": true},
		"references": map[string]interface{}{"owners": []interface{}{}, "name_regex": []interface{}{}},
		"configured": map[string]interface{}{"owners": true, "name_regex": true},
	}, want)
	require.Equal(t, want, parse(`{"format_version":"1.2","terraform_version":"1.9.0",`+prior+planned+`}`))
}

func TestPlanValuesConfiguredConstantWinsOverUnknown(t *testing.T) {
	// Providers sometimes mark a constant empty string as after_unknown.
	// The configuration still sets "", so the value is known.
	values, meta := plannedWeb(t, valuesPlanDoc(t,
		`{"name":"a","email":""}`,
		`{"email":true,"id":true}`,
		`{"name":{"constant_value":"a"},"email":{"constant_value":""}}`))
	require.Equal(t, "", values["email"])
	require.NotContains(t, meta, "unknown")
	require.Equal(t, map[string]interface{}{"name": true, "email": true}, meta["configured"])

	// Once the constant clears the only unknown of a nested block, no empty
	// unknown object is left behind.
	_, meta = plannedWeb(t, valuesPlanDoc(t,
		`{"logging":[{"prefix":""}]}`,
		`{"logging":[{"prefix":true}]}`,
		`{"logging":[{"prefix":{"constant_value":""}}]}`))
	require.NotContains(t, meta, "unknown")
}

func TestPlanValuesConstantNullIsUnconfigured(t *testing.T) {
	values, meta := plannedWeb(t, valuesPlanDoc(t,
		`{"name":"a","kms_key_id":null,"subnet_id":null}`,
		`{"kms_key_id":true,"subnet_id":true,"arn":true}`,
		`{"name":{"constant_value":"a"},"kms_key_id":{"constant_value":null},"subnet_id":{"references":["var.s"]}}`))
	require.Equal(t, map[string]interface{}{"name": "a", "subnet_id": "${__dd_unknown__}"}, values)
	require.Equal(t, map[string]interface{}{"subnet_id": true}, meta["unknown"])
	require.Equal(t, map[string]interface{}{"name": true, "subnet_id": true}, meta["configured"])

	// Line info is stored on the expression object. It must not make a null
	// look configured, or a reference look unreadable.
	values, meta = plannedWeb(t, valuesPlanDoc(t,
		`{"name":"a","kms_key_id":null}`,
		`{"kms_key_id":true,"id":true}`,
		`{"kms_key_id":{"constant_value":null,"_dd_lines":{"_dd_line":4}},"id":{"references":["var.id"],"_dd_lines":{"_dd_line":5}}}`))
	require.NotContains(t, values, "kms_key_id")
	configured, _ := meta["configured"].(map[string]interface{})
	require.NotContains(t, configured, "kms_key_id")
	require.Equal(t, "${__dd_unknown__}", values["id"])
	require.Equal(t, []interface{}{}, meta["references"].(map[string]interface{})["id"])
}

func TestPlanValuesConfiguredMarksOnlyWrittenAttributes(t *testing.T) {
	_, meta := plannedWeb(t, valuesPlanDoc(t,
		`{"name":"a","description":"Managed by Terraform","backup_retention_period":1,
		  "ingress":[{"from_port":80,"self":false}],"tags":{"env":"x"}}`,
		`{"ingress":[{}]}`,
		`{"name":{"constant_value":"a"},"tags":{"constant_value":{"env":"x"}},
		  "ingress":[{"from_port":{"constant_value":80}}]}`))
	require.Equal(t, map[string]interface{}{
		"name":    true,
		"tags":    true,
		"ingress": []interface{}{map[string]interface{}{"from_port": true}},
	}, meta["configured"])
}

func TestPlanValuesUserDataUsesConfiguredText(t *testing.T) {
	values, _ := plannedWeb(t, valuesPlanDoc(t,
		`{"user_data":"5b1e8d7f0c8d8e5f0b6a1e8b2f3c4d5e6f708192","user_data_base64":null}`,
		`{}`,
		`{"user_data":{"constant_value":"#!/bin/bash\nexport TOKEN=secret"}}`))
	require.Equal(t, "#!/bin/bash\nexport TOKEN=secret", values["user_data"])

	values, _ = plannedWeb(t, valuesPlanDoc(t,
		`{"user_data":"5b1e8d7f0c8d8e5f0b6a1e8b2f3c4d5e6f708192"}`,
		`{}`,
		`{"user_data":{"references":["local.script"]}}`))
	require.Equal(t, "5b1e8d7f0c8d8e5f0b6a1e8b2f3c4d5e6f708192", values["user_data"])
}

func TestPlanProvisionersFromConfiguration(t *testing.T) {
	doc := valuesPlanDoc(t, `{"name":"a"}`, `{}`, `{"name":{"constant_value":"a"}}`)
	resource := doc["configuration"].(map[string]interface{})["root_module"].(map[string]interface{})["resources"].([]interface{})[0].(map[string]interface{})
	var provisioners []interface{}
	require.NoError(t, stdjson.Unmarshal([]byte(`[
		{"type":"local-exec","expressions":{"command":{"constant_value":"echo secret"}}},
		{"type":"local-exec","expressions":{"command":{"references":["self.private_ip"]}}},
		{"type":"remote-exec","expressions":{"inline":{"constant_value":["a","b"]},"on_failure":{"constant_value":null}}}]`),
		&provisioners))
	resource["provisioners"] = provisioners
	values, meta := plannedWeb(t, doc)
	require.Equal(t, map[string]interface{}{
		"local-exec": []interface{}{
			map[string]interface{}{"command": "echo secret"},
			map[string]interface{}{"command": "${__dd_unknown__}"},
		},
		"remote-exec": []interface{}{map[string]interface{}{"inline": []interface{}{"a", "b"}}},
	}, values["provisioner"], "provisioner.<type> is a list even when written once")
	require.Nil(t, meta["unknown"])
}

func TestPlanReferencesTracedToNothingIsEmpty(t *testing.T) {
	planned := `{"resources":[
		{"address":"aws_instance.web","mode":"managed","type":"aws_instance","name":"web","values":{}},
		{"address":"data.terraform_remote_state.net","mode":"data","type":"terraform_remote_state","name":"net","values":{}}],
		"child_modules":[{"address":"module.m","resources":[
			{"address":"module.m.aws_instance.inner","mode":"managed","type":"aws_instance","name":"inner","values":{}}]}]}`
	config := `{"resources":[
		{"address":"aws_instance.web","mode":"managed","type":"aws_instance","name":"web","expressions":{
			"literal":{"constant_value":"x"},
			"root_var":{"references":["var.subnet_id"]},
			"remote":{"references":["data.terraform_remote_state.net.outputs.id","data.terraform_remote_state.net.outputs","data.terraform_remote_state.net"]},
			"local":{"references":["local.id"]},
			"mixed":{"references":["var.a","local.b"]},
			"each":{"references":["each.value"]}}}],
		"module_calls":{"m":{"expressions":{},"module":{"resources":[
			{"address":"aws_instance.inner","mode":"managed","type":"aws_instance","name":"inner","expressions":{
				"defaulted":{"references":["var.unset"]}}}]}}}}`
	doc := referencesPlanDoc(t, planned, []string{"aws_instance.web", "module.m.aws_instance.inner"}, config)
	require.Equal(t, map[string]interface{}{
		"literal":  []interface{}{},
		"root_var": []interface{}{},
		"remote":   []interface{}{"data.terraform_remote_state.net"},
	}, planMetaFor(t, doc, "aws_instance.web")["references"])
	require.Equal(t, map[string]interface{}{"defaulted": []interface{}{}},
		planMetaFor(t, doc, "module.m.aws_instance.inner")["references"])
}

func TestPlanReferencesDynamicIndexReadsEveryInstance(t *testing.T) {
	planned := `{"resources":[
		{"address":"aws_subnet.s[0]","mode":"managed","type":"aws_subnet","name":"s","index":0,"values":{}},
		{"address":"aws_subnet.s[1]","mode":"managed","type":"aws_subnet","name":"s","index":1,"values":{}},
		{"address":"aws_subnet.f[\"a\"]","mode":"managed","type":"aws_subnet","name":"f","index":"a","values":{}},
		{"address":"aws_subnet.f[\"b\"]","mode":"managed","type":"aws_subnet","name":"f","index":"b","values":{}},
		{"address":"aws_route_table_association.c[1]","mode":"managed","type":"aws_route_table_association","name":"c","index":1,"values":{}},
		{"address":"aws_route_table_association.e[\"b\"]","mode":"managed","type":"aws_route_table_association","name":"e","index":"b","values":{}},
		{"address":"aws_route_table_association.single","mode":"managed","type":"aws_route_table_association","name":"single","values":{}}]}`
	addrs := []string{"aws_subnet.s[0]", "aws_subnet.s[1]", `aws_subnet.f["a"]`, `aws_subnet.f["b"]`,
		"aws_route_table_association.c[1]", `aws_route_table_association.e["b"]`, "aws_route_table_association.single"}
	config := `{"resources":[
		{"address":"aws_route_table_association.c","mode":"managed","type":"aws_route_table_association","name":"c",
		 "count_expression":{"constant_value":2},"expressions":{
			"subnet_id":{"references":["aws_subnet.s","count.index"]},
			"mixed":{"references":["aws_subnet.s","count.index","aws_subnet.s[1].id","aws_subnet.s[1]","aws_subnet.s"]},
			"all":{"references":["aws_subnet.s"]}}},
		{"address":"aws_route_table_association.e","mode":"managed","type":"aws_route_table_association","name":"e",
		 "for_each_expression":{"references":["aws_subnet.f"]},"expressions":{
			"subnet_id":{"references":["aws_subnet.f","each.key"]},
			"value":{"references":["each.value.id","each.value"]}}},
		{"address":"aws_route_table_association.single","mode":"managed","type":"aws_route_table_association","name":"single","expressions":{
			"literal":{"references":["aws_subnet.s[1].id","aws_subnet.s[1]","aws_subnet.s"]},
			"choice":{"references":["var.on","aws_subnet.f[\"a\"]","aws_subnet.f","aws_subnet.s[0]","aws_subnet.s"]}}}]}`
	doc := referencesPlanDoc(t, planned, addrs, config)

	counted := planMetaFor(t, doc, "aws_route_table_association.c[1]")
	every := []interface{}{"aws_subnet.s[0]", "aws_subnet.s[1]"}
	require.Equal(t, map[string]interface{}{
		"subnet_id": every,
		"mixed":     every,
		"all":       every,
	}, counted["references"])
	require.Equal(t, map[string]interface{}{"subnet_id": true, "mixed": true}, counted["ambiguous"])

	each := planMetaFor(t, doc, `aws_route_table_association.e["b"]`)
	require.Equal(t, map[string]interface{}{
		"subnet_id": []interface{}{`aws_subnet.f["a"]`, `aws_subnet.f["b"]`},
		"value":     []interface{}{`aws_subnet.f["b"]`},
	}, each["references"])
	require.Equal(t, map[string]interface{}{"subnet_id": true}, each["ambiguous"])

	single := planMetaFor(t, doc, "aws_route_table_association.single")
	require.Equal(t, map[string]interface{}{
		"literal": []interface{}{"aws_subnet.s[1]"},
		"choice":  []interface{}{`aws_subnet.f["a"]`, "aws_subnet.s[0]"},
	}, single["references"])
	require.Equal(t, map[string]interface{}{"choice": true}, single["ambiguous"])
}

func TestPlanReferencesModuleCallWithoutPlannedResources(t *testing.T) {
	planned := `{"resources":[
		{"address":"aws_s3_bucket.reader","mode":"managed","type":"aws_s3_bucket","name":"reader","values":{}}]}`
	config := `{"resources":[
		{"address":"aws_s3_bucket.reader","mode":"managed","type":"aws_s3_bucket","name":"reader","expressions":{
			"single":{"references":["module.single.out","module.single"]},
			"repeated":{"references":["module.repeated.out","module.repeated"]}}}],
		"module_calls":{
			"single":{"source":"./single","module":{"outputs":{"out":{"expression":{"constant_value":"x"}}}}},
			"repeated":{"source":"./single","count_expression":{"references":["var.n"]},
			 "module":{"outputs":{"out":{"expression":{"constant_value":"x"}}}}}}}`
	doc := referencesPlanDoc(t, planned, []string{"aws_s3_bucket.reader"}, config)

	meta := planMetaFor(t, doc, "aws_s3_bucket.reader")
	require.Equal(t, map[string]interface{}{"single": []interface{}{}}, meta["references"])
}
