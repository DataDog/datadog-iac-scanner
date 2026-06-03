/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package bicep

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestParser_GetKind(t *testing.T) {
	p := &Parser{}
	require.Equal(t, model.KindBICEP, p.GetKind())
}

func TestParser_SupportedTypes(t *testing.T) {
	p := &Parser{}
	require.Equal(t, map[string]bool{"bicep": true, "azureresourcemanager": true}, p.SupportedTypes())
}

func TestParser_SupportedExtensions(t *testing.T) {
	p := &Parser{}
	require.Equal(t, []string{".bicep"}, p.SupportedExtensions())
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
			name: "Bicep stringify content",
			p:    &Parser{},
			args: args{
				content: []byte(`param vmName string = 'simple-vm'`),
			},
			want:    `param vmName string = 'simple-vm'`,
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

// Test_GetCommentToken must get the token that represents a comment
func Test_GetCommentToken(t *testing.T) {
	parser := &Parser{}
	require.Equal(t, "//", parser.GetCommentToken())
}

func TestParseBicepFile(t *testing.T) {
	parser := &Parser{}
	tests := []struct {
		name     string
		filename string
		want     string
		wantErr  bool
	}{
		{
			name:     "Parse Bicep file with Unsuported Content",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "bicep_test", "unsuported.bicep"),
			want: `{
					"parameters": {
						"diagnosticLogCategoriesToEnable": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 44
								},
								"_dd_type": {
									"_dd_line": 44
								}
							},
							"allowedValues": [
								[
									"allLogs",
									"ConnectedClientList"
								]
							],
							"defaultValue": [
								"allLogs"
							],
							"metadata": {
								"description": "Optional. The name of logs that will be streamed. \"allLogs\" includes all possible logs for the resource."
							},
							"type": "array"
						},
						"diagnosticMetricsToEnable": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 52
								},
								"_dd_type": {
									"_dd_line": 52
								}
							},
							"allowedValues": [
								[
									"AllMetrics"
								]
							],
							"defaultValue": [
								"AllMetrics"
							],
							"metadata": {
								"description": "Optional. The name of metrics that will be streamed."
							},
							"type": "array"
						},
						"diagnosticSettingsName": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 32
								},
								"_dd_type": {
									"_dd_line": 32
								}
							},
							"defaultValue": "'${parameters('name')}-diagnosticSettings'",
							"metadata": {
								"description": "Optional. The name of the diagnostic setting, if deployed."
							},
							"type": "string"
						},
						"diagnosticWorkspaceId": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 35
								},
								"_dd_type": {
									"_dd_line": 35
								}
							},
							"defaultValue": "",
							"metadata": {
								"description": "Optional. Resource ID of the diagnostic log analytics workspace. For security reasons, it is recommended to set diagnostic settings to send data to either storage account, log analytics workspace or event hub."
							},
							"type": "string"
						},
						"keyvaultName": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 23
								},
								"_dd_type": {
									"_dd_line": 23
								}
							},
							"metadata": {
								"description": "The name of an existing keyvault, that it will be used to store secrets (connection string)"
							},
							"type": "string"
						},
						"name": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 20
								},
								"_dd_type": {
									"_dd_line": 20
								}
							},
							"maxLength": 63,
							"metadata": {
								"description": "Required. The name of the Redis cache resource. Start and end with alphanumeric. Consecutive hyphens not allowed"
							},
							"minLength": 1,
							"type": "string"
						}
					},
					"resources": [
						{
							"_dd_lines": {
								"_dd__default": {
									"_dd_line": 110
								},
								"_dd_apiVersion": {
									"_dd_line": 110
								},
								"_dd_name": {
									"_dd_line": 111
								},
								"_dd_type": {
									"_dd_line": 110
								}
							},
							"apiVersion": "2022-11-01",
							"identifier": "keyVault",
							"name": "[parameters('keyvaultName')]",
							"type": "Microsoft.KeyVault/vaults"
						},
						{
							"apiVersion": "2021-05-01-preview",
							"identifier": "redisCache_diagnosticSettings",
							"type": "Microsoft.Insights/diagnosticSettings"
						}
					],
					"variables": {
						"diagnosticsLogs": {
							"value": null
						},
						"diagnosticsLogsSpecified": {
							"value": null
						},
						"diagnosticsMetrics": {
							"value": null
						},
						"dogs": {
							"value": [
								{
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 73
										},
										"_dd_age": {
											"_dd_line": 75
										},
										"_dd_name": {
											"_dd_line": 74
										}
									},
									"age": 3,
									"name": "Fido"
								},
								{
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 77
										},
										"_dd_age": {
											"_dd_line": 79
										},
										"_dd_name": {
											"_dd_line": 78
										}
									},
									"age": 7,
									"name": "Rex"
								}
							]
						}
					}
				}`,
		},
		{
			name:     "Parse Bicep file with parameters",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "bicep_test", "parameters.bicep"),
			want: `{
					"parameters": {
						"array": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 17
								},
								"_dd_type": {
									"_dd_line": 17
								}
							},
							"defaultValue": [
								"string"
							],
							"type": "string"
						},
						"isNumber": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 9
								},
								"_dd_type": {
									"_dd_line": 9
								}
							},
							"defaultValue": true,
							"metadata": {
								"description": "This is a test bool param declaration."
							},
							"type": "bool"
						},
						"middleString": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 12
								},
								"_dd_type": {
									"_dd_line": 12
								}
							},
							"defaultValue": "'teste-${parameters('numberNodes')}${parameters('isNumber')}-teste'",
							"metadata": {
								"description": "This is a test middle string param declaration."
							},
							"type": "string"
						},
						"null": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 19
								},
								"_dd_type": {
									"_dd_line": 19
								}
							},
							"defaultValue": null,
							"type": "string"
						},
						"numberNodes": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 6
								},
								"_dd_type": {
									"_dd_line": 6
								}
							},
							"defaultValue": 2,
							"metadata": {
								"description": "This is a test int param declaration."
							},
							"type": "int"
						},
						"projectName": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 3
								},
								"_dd_type": {
									"_dd_line": 3
								}
							},
							"defaultValue": "[newGuid()]",
							"metadata": {
								"description": "This is a test param with secure declaration."
							},
							"type": "secureString"
						},
						"secObj": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 15
								},
								"_dd_type": {
									"_dd_line": 15
								}
							},
							"defaultValue": false,
							"type": "secureObject"
						}
					},
					"resources": [],
					"variables": {}
				}`,
			wantErr: false,
		},
		{
			name:     "Parse Bicep file with variables",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "bicep_test", "variables.bicep"),
			want: `{
					"variables": {
						"nicName": {
							"metadata": {
								"description": "This is a test var declaration."
							},
							"value": "myVMNic"
						},
						"storageAccountName": {
							"metadata": {
								"description": "This is a test var declaration."
							},
							"value": "'bootdiags${[uniqueString(resourceGroup().id)]}'"
						}
					},
					"resources": [],
					"parameters": {}
				}`,
			wantErr: false,
		},
		{
			name:     "Parse completed Bicep file",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "bicep_test", "resources.bicep"),
			want: `{
					"parameters": {
						"OSVersion": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 42
								},
								"_dd_type": {
									"_dd_line": 42
								}
							},
							"allowedValues": [
								[
									"2008-R2-SP1",
									"2012-Datacenter",
									"2012-R2-Datacenter",
									"2016-Nano-Server",
									"2016-Datacenter-with-Containers",
									"2016-Datacenter",
									"2019-Datacenter",
									"2019-Datacenter-Core",
									"2019-Datacenter-Core-smalldisk",
									"2019-Datacenter-Core-with-Containers",
									"2019-Datacenter-Core-with-Containers-smalldisk",
									"2019-Datacenter-smalldisk",
									"2019-Datacenter-with-Containers",
									"2019-Datacenter-with-Containers-smalldisk"
								]
							],
							"defaultValue": "2019-Datacenter",
							"metadata": {
								"description": "The Windows version for the VM. This will pick a fully patched image of this given Windows version."
							},
							"type": "string"
						},
						"adminPassword": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 9
								},
								"_dd_type": {
									"_dd_line": 9
								}
							},
							"metadata": {
								"description": "Password for the Virtual Machine."
							},
							"minLength": 12,
							"type": "secureString"
						},
						"adminUsername": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 4
								},
								"_dd_type": {
									"_dd_line": 4
								}
							},
							"metadata": {
								"description": "Username for the Virtual Machine."
							},
							"type": "string"
						},
						"arrayP": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 136
								},
								"_dd_type": {
									"_dd_line": 136
								}
							},
							"defaultValue": [
								"allLogs",
								"ConnectedClientList"
							],
							"type": "array"
						},
						"capacity": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 65
								},
								"_dd_type": {
									"_dd_line": 65
								}
							},
							"allowedValues": [
								[
									0,
									1,
									2,
									3,
									4,
									5,
									6
								]
							],
							"defaultValue": 2,
							"metadata": {
								"description": "Optional. The size of the Redis cache to deploy. Valid values: for C (Basic/Standard) family (0, 1, 2, 3, 4, 5, 6), for P (Premium) family (1, 2, 3, 4)."
							},
							"type": "int"
						},
						"diagnosticLogCategoriesToEnable": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 18
								},
								"_dd_type": {
									"_dd_line": 18
								}
							},
							"allowedValues": [
								[
									"allLogs",
									"ConnectedClientList"
								]
							],
							"defaultValue": [
								"allLogs"
							],
							"metadata": {
								"description": "Optional. The name of logs that will be streamed. \"allLogs\" includes all possible logs for the resource."
							},
							"type": "array"
						},
						"diagnosticMetricsToEnable": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 93
								},
								"_dd_type": {
									"_dd_line": 93
								}
							},
							"allowedValues": [
								[
									"AllMetrics"
								]
							],
							"defaultValue": [
								"AllMetrics"
							],
							"metadata": {
								"description": "Optional. The name of metrics that will be streamed."
							},
							"type": "array"
						},
						"diagnosticSettingsName": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 82
								},
								"_dd_type": {
									"_dd_line": 82
								}
							},
							"defaultValue": "'${name}-diagnosticSettings'",
							"metadata": {
								"description": "Optional. The name of the diagnostic setting, if deployed."
							},
							"type": "string"
						},
						"diagnosticWorkspaceId": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 85
								},
								"_dd_type": {
									"_dd_line": 85
								}
							},
							"defaultValue": "",
							"metadata": {
								"description": "Optional. Resource ID of the diagnostic log analytics workspace. For security reasons, it is recommended to set diagnostic settings to send data to either storage account, log analytics workspace or event hub."
							},
							"type": "string"
						},
						"enableNonSslPort": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 99
								},
								"_dd_type": {
									"_dd_line": 99
								}
							},
							"defaultValue": false,
							"metadata": {
								"description": "Optional. Specifies whether the non-ssl Redis server port (6379) is enabled."
							},
							"type": "bool"
						},
						"existingContainerSubnetName": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 126
								},
								"_dd_type": {
									"_dd_line": 126
								}
							},
							"metadata": {
								"description": "Name of the subnet to use for cloud shell containers."
							},
							"type": "string"
						},
						"existingStorageSubnetName": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 123
								},
								"_dd_type": {
									"_dd_line": 123
								}
							},
							"metadata": {
								"description": "Name of the subnet to use for storage account."
							},
							"type": "string"
						},
						"existingVNETName": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 120
								},
								"_dd_type": {
									"_dd_line": 120
								}
							},
							"metadata": {
								"description": "Name of the virtual network to use for cloud shell containers."
							},
							"type": "string"
						},
						"hasPrivateLink": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 96
								},
								"_dd_type": {
									"_dd_line": 96
								}
							},
							"defaultValue": false,
							"metadata": {
								"description": "Has the resource private endpoint?"
							},
							"type": "bool"
						},
						"keyvaultName": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 68
								},
								"_dd_type": {
									"_dd_line": 68
								}
							},
							"metadata": {
								"description": "The name of an existing keyvault, that it will be used to store secrets (connection string)"
							},
							"type": "string"
						},
						"location": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 112
								},
								"_dd_type": {
									"_dd_line": 112
								}
							},
							"defaultValue": "[resourceGroup().location]",
							"metadata": {
								"description": "Location for all resources."
							},
							"type": "string"
						},
						"name": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 131
								},
								"_dd_type": {
									"_dd_line": 131
								}
							},
							"maxLength": 63,
							"metadata": {
								"description": "Required. The name of the Redis cache resource. Start and end with alphanumeric. Consecutive hyphens not allowed"
							},
							"minLength": 1,
							"type": "string"
						},
						"parenthesis": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 117
								},
								"_dd_type": {
									"_dd_line": 117
								}
							},
							"defaultValue": "simple-vm",
							"type": "string"
						},
						"redisConfiguration": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 102
								},
								"_dd_type": {
									"_dd_line": 102
								}
							},
							"defaultValue": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 102
									}
								}
							},
							"metadata": {
								"description": "Optional. All Redis Settings. Few possible keys: rdb-backup-enabled,rdb-storage-connection-string,rdb-backup-frequency,maxmemory-delta,maxmemory-policy,notify-keyspace-events,maxmemory-samples,slowlog-log-slower-than,slowlog-max-len,list-max-ziplist-entries,list-max-ziplist-value,hash-max-ziplist-entries,hash-max-ziplist-value,set-max-intset-entries,zset-max-ziplist-entries,zset-max-ziplist-value etc."
							},
							"type": "object"
						},
						"replicasPerMaster": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 106
								},
								"_dd_type": {
									"_dd_line": 106
								}
							},
							"defaultValue": 1,
							"metadata": {
								"description": "Optional. The number of replicas to be created per primary."
							},
							"minValue": 1,
							"type": "int"
						},
						"replicasPerPrimary": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 49
								},
								"_dd_type": {
									"_dd_line": 49
								}
							},
							"defaultValue": 1,
							"metadata": {
								"description": "Optional. The number of replicas to be created per primary."
							},
							"minValue": 1,
							"type": "int"
						},
						"shardCount": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 53
								},
								"_dd_type": {
									"_dd_line": 53
								}
							},
							"defaultValue": 1,
							"metadata": {
								"description": "Optional. The number of shards to be created on a Premium Cluster Cache."
							},
							"minValue": 1,
							"type": "int"
						},
						"skuName": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 76
								},
								"_dd_type": {
									"_dd_line": 76
								}
							},
							"allowedValues": [
								[
									"Basic",
									"Premium",
									"Standard"
								]
							],
							"defaultValue": "Standard",
							"metadata": {
								"description": "Optional, default is Standard. The type of Redis cache to deploy."
							},
							"type": "string"
						},
						"subnetId": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 79
								},
								"_dd_type": {
									"_dd_line": 79
								}
							},
							"defaultValue": "",
							"metadata": {
								"description": "Optional. The full resource ID of a subnet in a virtual network to deploy the Redis cache in. Example format: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/Microsoft.{Network|ClassicNetwork}/VirtualNetworks/vnet1/subnets/subnet1."
							},
							"type": "string"
						},
						"tags": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 45
								},
								"_dd_type": {
									"_dd_line": 45
								}
							},
							"defaultValue": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 45
									}
								}
							},
							"metadata": {
								"description": "Optional. Tags of the resource."
							},
							"type": "object"
						},
						"vmName": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 115
								},
								"_dd_type": {
									"_dd_line": 115
								}
							},
							"defaultValue": "simple-vm",
							"metadata": {
								"description": "Name of the virtual machine."
							},
							"type": "string"
						},
						"vmSize": {
							"_dd_lines": {
								"_dd_defaultValue": {
									"_dd_line": 109
								},
								"_dd_type": {
									"_dd_line": 109
								}
							},
							"defaultValue": "Standard_D2_v3",
							"metadata": {
								"description": "Size of the virtual machine."
							},
							"type": "string"
						}
					},
					"resources": [
						{
							"_dd_lines": {
								"_dd__default": {
									"_dd_line": 173
								},
								"_dd_apiVersion": {
									"_dd_line": 172
								},
								"_dd_dependsOn": {
									"_dd_arr": [
										{
											"_dd__default": {
												"_dd_line": 222
											}
										}
									],
									"_dd_line": 222
								},
								"_dd_location": {
									"_dd_line": 175
								},
								"_dd_name": {
									"_dd_line": 174
								},
								"_dd_properties": {
									"_dd_line": 176
								},
								"_dd_type": {
									"_dd_line": 172
								}
							},
							"apiVersion": "2021-03-01",
							"dependsOn": [
								{
									"resourceId": [
										"Microsoft.Network/networkInterfaces",
										"variables('nicName')"
									]
								},
								{
									"resourceId": [
										"Microsoft.Storage/storageAccounts",
										"variables('storageAccountName')"
									]
								}
							],
							"identifier": "vm",
							"location": "[parameters('location')]",
							"metadata": {
								"description": "This is a test description for resources"
							},
							"name": "[parameters('vmName')]",
							"properties": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 176
									},
									"_dd_diagnosticsProfile": {
										"_dd_line": 213
									},
									"_dd_hardwareProfile": {
										"_dd_line": 177
									},
									"_dd_networkProfile": {
										"_dd_line": 206
									},
									"_dd_osProfile": {
										"_dd_line": 180
									},
									"_dd_storageProfile": {
										"_dd_line": 185
									}
								},
								"diagnosticsProfile": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 213
										},
										"_dd_bootDiagnostics": {
											"_dd_line": 214
										}
									},
									"bootDiagnostics": {
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 214
											},
											"_dd_enabled": {
												"_dd_line": 215
											},
											"_dd_storageUri": {
												"_dd_line": 216
											}
										},
										"enabled": true,
										"storageUri": "[reference(resourceId(Microsoft.Storage/storageAccounts, variables('storageAccountName'))).primaryEndpoints.blob]"
									}
								},
								"hardwareProfile": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 177
										},
										"_dd_vmSize": {
											"_dd_line": 178
										}
									},
									"vmSize": "[parameters('vmSize')]"
								},
								"networkProfile": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 206
										},
										"_dd_networkInterfaces": {
											"_dd_arr": [
												{
													"_dd__default": {
														"_dd_line": 207
													}
												}
											],
											"_dd_line": 207
										}
									},
									"networkInterfaces": [
										{
											"_dd_lines": {
												"_dd__default": {
													"_dd_line": 208
												},
												"_dd_id": {
													"_dd_line": 209
												}
											},
											"id": {
												"resourceId": [
													"Microsoft.Network/networkInterfaces",
													"nick"
												]
											}
										}
									]
								},
								"osProfile": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 180
										},
										"_dd_adminPassword": {
											"_dd_line": 183
										},
										"_dd_adminUsername": {
											"_dd_line": 182
										},
										"_dd_computerName": {
											"_dd_line": 181
										}
									},
									"adminPassword": "[parameters('adminPassword')]",
									"adminUsername": "[parameters('adminUsername')]",
									"computerName": "computer"
								},
								"storageProfile": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 185
										},
										"_dd_dataDisks": {
											"_dd_arr": [
												{
													"_dd__default": {
														"_dd_line": 198
													}
												}
											],
											"_dd_line": 198
										},
										"_dd_imageReference": {
											"_dd_line": 186
										},
										"_dd_osDisk": {
											"_dd_line": 192
										}
									},
									"dataDisks": [
										{
											"_dd_lines": {
												"_dd__default": {
													"_dd_line": 199
												},
												"_dd_createOption": {
													"_dd_line": 202
												},
												"_dd_diskSizeGB": {
													"_dd_line": 200
												},
												"_dd_lun": {
													"_dd_line": 201
												}
											},
											"createOption": "Empty",
											"diskSizeGB": 1023,
											"lun": 0
										}
									],
									"imageReference": {
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 186
											},
											"_dd_offer": {
												"_dd_line": 188
											},
											"_dd_publisher": {
												"_dd_line": 187
											},
											"_dd_sku": {
												"_dd_line": 189
											},
											"_dd_version": {
												"_dd_line": 190
											}
										},
										"offer": "WindowsServer",
										"publisher": "MicrosoftWindowsServer",
										"sku": "[parameters('OSVersion')]",
										"version": "latest"
									},
									"osDisk": {
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 192
											},
											"_dd_createOption": {
												"_dd_line": 193
											},
											"_dd_managedDisk": {
												"_dd_line": 194
											}
										},
										"createOption": "FromImage",
										"managedDisk": {
											"_dd_lines": {
												"_dd__default": {
													"_dd_line": 194
												},
												"_dd_storageAccountType": {
													"_dd_line": 195
												}
											},
											"storageAccountType": "StandardSSD_LRS"
										}
									}
								}
							},
							"type": "Microsoft.Compute/virtualMachines"
						},
						{
							"_dd_lines": {
								"_dd__default": {
									"_dd_line": 228
								},
								"_dd_apiVersion": {
									"_dd_line": 228
								},
								"_dd_assignableScopes": {
									"_dd_arr": [
										{
											"_dd__default": {
												"_dd_line": 238
											}
										}
									],
									"_dd_line": 238
								},
								"_dd_location": {
									"_dd_line": 230
								},
								"_dd_name": {
									"_dd_line": 229
								},
								"_dd_type": {
									"_dd_line": 228
								},
								"_dd_userAssignedIdentities": {
									"_dd_line": 235
								}
							},
							"apiVersion": "2021-03-01",
							"assignableScopes": [
								"[subscription().id]"
							],
							"identifier": "nic",
							"location": null,
							"name": null,
							"type": "Microsoft.Network/networkInterfaces",
							"userAssignedIdentities": {
								"'${[resourceId(Microsoft.ManagedIdentity/userAssignedIdentities, variables('nicName'))]}'": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 236
										}
									}
								},
								"_dd_lines": {
									"_dd_'${[resourceId(Microsoft.ManagedIdentity/userAssignedIdentities, variables('nicName'))]}'": {
										"_dd_line": 236
									},
									"_dd__default": {
										"_dd_line": 235
									}
								}
							}
						},
						{
							"_dd_lines": {
								"_dd__default": {
									"_dd_line": 241
								},
								"_dd_apiVersion": {
									"_dd_line": 241
								},
								"_dd_kind": {
									"_dd_line": 248
								},
								"_dd_location": {
									"_dd_line": 243
								},
								"_dd_name": {
									"_dd_line": 242
								},
								"_dd_properties": {
									"_dd_line": 249
								},
								"_dd_sku": {
									"_dd_line": 244
								},
								"_dd_type": {
									"_dd_line": 241
								}
							},
							"apiVersion": "2019-06-01",
							"identifier": "storageAccount",
							"kind": "StorageV2",
							"location": "[parameters('location')]",
							"name": "[variables('storageAccountName')]",
							"properties": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 249
									},
									"_dd_accessTier": {
										"_dd_line": 278
									},
									"_dd_encryption": {
										"_dd_line": 265
									},
									"_dd_networkAcls": {
										"_dd_line": 250
									},
									"_dd_supportsHttpsTrafficOnly": {
										"_dd_line": 264
									}
								},
								"accessTier": "Cool",
								"encryption": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 265
										},
										"_dd_keySource": {
											"_dd_line": 276
										},
										"_dd_services": {
											"_dd_line": 266
										}
									},
									"keySource": "Microsoft.Storage",
									"services": {
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 266
											},
											"_dd_blob": {
												"_dd_line": 271
											},
											"_dd_file": {
												"_dd_line": 267
											}
										},
										"blob": {
											"_dd_lines": {
												"_dd__default": {
													"_dd_line": 271
												},
												"_dd_enabled": {
													"_dd_line": 273
												},
												"_dd_keyType": {
													"_dd_line": 272
												}
											},
											"enabled": true,
											"keyType": "Account"
										},
										"file": {
											"_dd_lines": {
												"_dd__default": {
													"_dd_line": 267
												},
												"_dd_enabled": {
													"_dd_line": 269
												},
												"_dd_keyType": {
													"_dd_line": 268
												}
											},
											"enabled": true,
											"keyType": "Account"
										}
									}
								},
								"networkAcls": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 250
										},
										"_dd_bypass": {
											"_dd_line": 251
										},
										"_dd_defaultAction": {
											"_dd_line": 262
										},
										"_dd_virtualNetworkRules": {
											"_dd_arr": [
												{
													"_dd__default": {
														"_dd_line": 252
													}
												}
											],
											"_dd_line": 252
										}
									},
									"bypass": "None",
									"defaultAction": "Deny",
									"virtualNetworkRules": [
										{
											"_dd_lines": {
												"_dd__default": {
													"_dd_line": 253
												},
												"_dd_action": {
													"_dd_line": 255
												},
												"_dd_id": {
													"_dd_line": 254
												}
											},
											"action": "Allow",
											"id": "[variables('containerSubnetRef')]"
										},
										{
											"_dd_lines": {
												"_dd__default": {
													"_dd_line": 257
												},
												"_dd_action": {
													"_dd_line": 259
												},
												"_dd_id": {
													"_dd_line": 258
												}
											},
											"action": "Allow",
											"id": "[variables('storageSubnetRef')]"
										}
									]
								},
								"supportsHttpsTrafficOnly": true
							},
							"resources": [
								{
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 282
										},
										"_dd_apiVersion": {
											"_dd_line": 282
										},
										"_dd_name": {
											"_dd_line": 284
										},
										"_dd_parent": {
											"_dd_line": 283
										},
										"_dd_properties": {
											"_dd_line": 289
										},
										"_dd_sku": {
											"_dd_line": 285
										},
										"_dd_type": {
											"_dd_line": 282
										}
									},
									"apiVersion": "2019-06-01",
									"identifier": "storageAccountName_default",
									"name": "default",
									"parent": "storageAccount",
									"properties": {
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 289
											},
											"_dd_deleteRetentionPolicy": {
												"_dd_line": 290
											}
										},
										"deleteRetentionPolicy": {
											"_dd_lines": {
												"_dd__default": {
													"_dd_line": 290
												},
												"_dd_enabled": {
													"_dd_line": 291
												}
											},
											"enabled": false
										}
									},
									"resources": [
										{
											"_dd_lines": {
												"_dd__default": {
													"_dd_line": 296
												},
												"_dd_apiVersion": {
													"_dd_line": 296
												},
												"_dd_name": {
													"_dd_line": 298
												},
												"_dd_parent": {
													"_dd_line": 297
												},
												"_dd_properties": {
													"_dd_line": 299
												},
												"_dd_type": {
													"_dd_line": 296
												}
											},
											"apiVersion": "2019-06-01",
											"identifier": "storageAccountName_default_container",
											"name": "container",
											"parent": "storageAccountName_default",
											"properties": {
												"_dd_lines": {
													"_dd__default": {
														"_dd_line": 299
													},
													"_dd_denyEncryptionScopeOverride": {
														"_dd_line": 300
													},
													"_dd_metadata": {
														"_dd_line": 302
													},
													"_dd_publicAccess": {
														"_dd_line": 301
													}
												},
												"denyEncryptionScopeOverride": true,
												"metadata": {
													"_dd_lines": {
														"_dd__default": {
															"_dd_line": 302
														}
													}
												},
												"publicAccess": "Blob"
											},
											"type": "containers"
										}
									],
									"sku": {
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 285
											},
											"_dd_name": {
												"_dd_line": 286
											},
											"_dd_tier": {
												"_dd_line": 287
											}
										},
										"name": "Standard_LRS",
										"tier": "Standard"
									},
									"type": "blobServices"
								}
							],
							"sku": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 244
									},
									"_dd_name": {
										"_dd_line": 245
									},
									"_dd_tier": {
										"_dd_line": 246
									}
								},
								"name": "Standard_LRS",
								"tier": "Standard"
							},
							"type": "Microsoft.Storage/storageAccounts"
						},
						{
							"_dd_lines": {
								"_dd__default": {
									"_dd_line": 306
								},
								"_dd_apiVersion": {
									"_dd_line": 306
								},
								"_dd_location": {
									"_dd_line": 308
								},
								"_dd_name": {
									"_dd_line": 307
								},
								"_dd_properties": {
									"_dd_line": 311
								},
								"_dd_tags": {
									"_dd_line": 309
								},
								"_dd_type": {
									"_dd_line": 306
								},
								"_dd_zones": {
									"_dd_line": 327
								}
							},
							"apiVersion": "2021-06-01",
							"identifier": "redisCache",
							"location": "[parameters('location')]",
							"name": "[parameters('name')]",
							"properties": {
								"_dd_lines": {
									"_dd__default": {
										"_dd_line": 311
									},
									"_dd_enableNonSslPort": {
										"_dd_line": 312
									},
									"_dd_minimumTlsVersion": {
										"_dd_line": 313
									},
									"_dd_publicNetworkAccess": {
										"_dd_line": 314
									},
									"_dd_redisConfiguration": {
										"_dd_line": 315
									},
									"_dd_redisVersion": {
										"_dd_line": 316
									},
									"_dd_replicasPerMaster": {
										"_dd_line": 317
									},
									"_dd_replicasPerPrimary": {
										"_dd_line": 318
									},
									"_dd_shardCount": {
										"_dd_line": 319
									},
									"_dd_sku": {
										"_dd_line": 320
									},
									"_dd_subnetId": {
										"_dd_line": 325
									}
								},
								"enableNonSslPort": "[parameters('enableNonSslPort')]",
								"minimumTlsVersion": "1.2",
								"publicNetworkAccess": null,
								"redisConfiguration": null,
								"redisVersion": "6",
								"replicasPerMaster": null,
								"replicasPerPrimary": null,
								"shardCount": null,
								"sku": {
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 320
										},
										"_dd_capacity": {
											"_dd_line": 321
										},
										"_dd_family": {
											"_dd_line": 322
										},
										"_dd_name": {
											"_dd_line": 323
										}
									},
									"capacity": "[parameters('capacity')]",
									"family": null,
									"name": "[parameters('skuName')]"
								},
								"subnetId": null
							},
							"tags": "[parameters('tags')]",
							"type": "Microsoft.Cache/redis",
							"zones": null
						},
						{
							"apiVersion": "2021-05-01-preview",
							"identifier": "redisCache_diagnosticSettings",
							"type": "Microsoft.Insights/diagnosticSettings"
						},
						{
							"_dd_lines": {
								"_dd__default": {
									"_dd_line": 351
								},
								"_dd_apiVersion": {
									"_dd_line": 351
								},
								"_dd_name": {
									"_dd_line": 352
								},
								"_dd_type": {
									"_dd_line": 351
								}
							},
							"apiVersion": "2022-11-01",
							"identifier": "keyVault",
							"name": "[parameters('keyvaultName')]",
							"resources": [
								{
									"_dd_lines": {
										"_dd__default": {
											"_dd_line": 330
										},
										"_dd_apiVersion": {
											"_dd_line": 330
										},
										"_dd_name": {
											"_dd_line": 331
										},
										"_dd_parent": {
											"_dd_line": 332
										},
										"_dd_properties": {
											"_dd_line": 333
										},
										"_dd_type": {
											"_dd_line": 330
										}
									},
									"apiVersion": "2018-02-14",
									"identifier": "redisConnectionStringSecret",
									"name": "redisConStrSecret",
									"parent": "keyVault",
									"properties": {
										"_dd_lines": {
											"_dd__default": {
												"_dd_line": 333
											},
											"_dd_value": {
												"_dd_line": 334
											}
										},
										"value": "['${redisCache.properties.hostName},password=${redisCache.listKeys().primaryKey},ssl=True,abortConnect=False']"
									},
									"type": "secrets"
								}
							],
							"type": "Microsoft.KeyVault/vaults"
						}
					],
					"variables": {
						"containerSubnetRef": {
							"value": {
								"resourceId": [
									"Microsoft.Network/virtualNetworks/subnets",
									"parameters('existingVNETName')",
									"parameters('existingContainerSubnetName')"
								]
							}
						},
						"diagnosticsLogs": {
							"value": null
						},
						"diagnosticsLogsSpecified": {
							"value": null
						},
						"diagnosticsMetrics": {
							"value": null
						},
						"nicName": {
							"value": "myVMNic"
						},
						"storageAccountName": {
							"value": "'bootdiags${[uniqueString(resourceGroup().id)]}'"
						},
						"storageSubnetRef": {
							"value": {
								"resourceId": [
									"Microsoft.Network/virtualNetworks/subnets",
									"parameters('existingVNETName')",
									"parameters('existingStorageSubnetName')"
								]
							}
						}
					}
				}`,
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, document, _, _, err := parser.Parse(ctx, nil, tt.filename, true, 15)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parser.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Len(t, document, 1)
			//get first element of parsed file
			parsedDoc := document[0]
			fileString, err := json.Marshal(parsedDoc)
			require.NoError(t, err)
			require.JSONEq(t, tt.want, string(fileString))
		})
	}
}
