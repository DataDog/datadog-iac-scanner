/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// filepath: filepath.FromSlash("../../test/fixtures/test_helm"),

type mergeMapsTest struct {
	name string
	args struct {
		baseMap converter.VariableMap
		newMap  converter.VariableMap
	}
	want converter.VariableMap
}

type inputVarTest struct {
	name     string
	filename string
	want     converter.VariableMap
	wantErr  bool
}

func setInputVariablesDefaultValues(filename string) (converter.VariableMap, error) {
	parsedFile, err := readAndParseFile(vfs.DiskFS{}, filename, false)
	if err != nil || parsedFile == nil {
		return nil, err
	}
	content, _, _ := parsedFile.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{
				Type:       "variable",
				LabelNames: []string{"name"},
			},
		},
	})

	defaultValuesMap := make(converter.VariableMap)
	for _, block := range content.Blocks {
		if len(block.Labels) == 0 || block.Labels[0] == "" {
			continue
		}
		attr, _ := block.Body.JustAttributes()
		if len(attr) == 0 {
			continue
		}
		if defaultValue, exists := attr["default"]; exists {
			defaultVar, _ := defaultValue.Expr.Value(nil)
			defaultValuesMap[block.Labels[0]] = defaultVar
		}
	}
	return defaultValuesMap, nil
}

func TestMergeMaps(t *testing.T) {
	tests := []mergeMapsTest{
		{
			name: "Should merge the second map on the first map",
			args: struct {
				baseMap converter.VariableMap
				newMap  converter.VariableMap
			}{
				baseMap: converter.VariableMap{
					"test": cty.StringVal("test"),
				},
				newMap: converter.VariableMap{
					"new": cty.StringVal("new"),
				},
			},
			want: converter.VariableMap{
				"test": cty.StringVal("test"),
				"new":  cty.StringVal("new"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mergeMaps(tt.args.baseMap, tt.args.newMap)
			require.Equal(t, tt.want, tt.args.baseMap)
		})
	}
}

func TestSetInputVariablesDefaultValues(t *testing.T) {
	tests := []inputVarTest{
		{
			name:     "Should get default variable values from tf file",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_variables", "test.tf"),
			want: converter.VariableMap{
				"local_default_var": cty.StringVal("local_default"),
			},
			wantErr: false,
		},
		{
			name:     "Should get default variable values from tf file",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_variables", "variables.tf"),
			want: converter.VariableMap{
				"default_var_file": cty.StringVal("default_var_file"),
			},
			wantErr: false,
		},
		{
			name:     "Should get empty map from variable blockless file",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_variables", "test_without_variables_block.tf"),
			want:     converter.VariableMap{},
			wantErr:  false,
		},
		{
			name:     "Should get an error when trying to set input variables from inexistent file",
			filename: filepath.FromSlash("not_found.tf"),
			want:     nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaultValues, err := setInputVariablesDefaultValues(tt.filename)
			if tt.wantErr {
				require.NotNil(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, defaultValues)
		})
	}
}

func TestGetInputVariablesFromFile(t *testing.T) {
	tests := []inputVarTest{
		{
			name:     "Should get variables from file",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_variables", "variable_set.auto.tfvars"),
			want: converter.VariableMap{
				"test1": cty.BoolVal(false),
				"test2": cty.TupleVal([]cty.Value{cty.BoolVal(false), cty.BoolVal(true)}),
				"map1": cty.ObjectVal(map[string]cty.Value{
					"map1key1": cty.StringVal("map2Key1"),
				}),
				"map2": cty.ObjectVal(map[string]cty.Value{
					"map2Key1": cty.StringVal("nestedMap"),
				}),
			},
			wantErr: false,
		},
		{
			name:     "Should get an error when trying to set input variables from inexistent file",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_variables", "invalid.tfvars"),
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "Should get an error when trying to set input variables from inexistent file 2",
			filename: filepath.FromSlash("not_found.tf"),
			want:     nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputVars, err := getInputVariablesFromFile(vfs.DiskFS{}, tt.filename)
			if tt.wantErr {
				require.NotNil(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, inputVars)
		})
	}
}

func TestGetInputVariables(t *testing.T) {
	tests := []inputVarTest{
		{
			name:     "Should load input variables",
			filename: filepath.FromSlash("../../../test/fixtures/test_terraform_variables"),
			want: converter.VariableMap{
				"var": cty.ObjectVal(map[string]cty.Value{
					"test1": cty.BoolVal(false),
					"test2": cty.TupleVal([]cty.Value{cty.BoolVal(false), cty.BoolVal(true)}),
					"map1": cty.ObjectVal(map[string]cty.Value{
						"map1key1": cty.StringVal("map2Key1"),
					}),
					"map2": cty.ObjectVal(map[string]cty.Value{
						"map2Key1": cty.StringVal("nestedMap"),
					}),
					"map3": cty.ObjectVal(map[string]cty.Value{
						"map3Key1": cty.StringVal("givenByVar"),
					}),
					"test_terraform":    cty.StringVal("terraform.tfvars"),
					"default_var_file":  cty.StringVal("default_var_file"),
					"local_default_var": cty.StringVal("local_default"),
				}),
				"local": cty.EmptyObjectVal,
			},
			wantErr: false,
		},
		{
			name:     "Should load input variables",
			filename: filepath.FromSlash("../../../test/fixtures/test_terraform_variables/test_variables_comment_path.tf"),
			want: converter.VariableMap{
				"var": cty.ObjectVal(map[string]cty.Value{
					"map3": cty.ObjectVal(map[string]cty.Value{
						"map3Key1": cty.StringVal("givenByVar"),
					}),
				}),
				"local": cty.EmptyObjectVal,
			},
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileContent, _ := os.ReadFile(tt.filename)
			result := getInputVariables(ctx, vfs.DiskFS{}, tt.filename, string(fileContent), "../../../test/fixtures/test_terraform_variables/varsToUse/varsToUse.tf", nil, "")
			require.Equal(t, tt.want, result)
		})
	}
}

func TestGetInputVariables_TofuShadowsTf(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "variables.tf"), []byte(`
variable "bucket" { default = "from-tf" }
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "variables.tofu"), []byte(`
variable "bucket" { default = "from-tofu" }
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.tf"), []byte(`
variable "other" { default = "kept" }
`), 0o600))

	got := getInputVariables(context.Background(), vfs.DiskFS{}, dir, "", "", nil, "")
	vars := got["var"].AsValueMap()
	require.Equal(t, "from-tofu", vars["bucket"].AsString())
	require.Equal(t, "kept", vars["other"].AsString())
}

func TestGetInputVariables_ExcludedTofuTwinKept(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "variables.tf")
	tofu := filepath.Join(dir, "variables.tofu")
	require.NoError(t, os.WriteFile(tf, []byte(`
variable "bucket" { default = "from-tf" }
`), 0o600))
	require.NoError(t, os.WriteFile(tofu, []byte(`
variable "bucket" { default = "from-tofu" }
`), 0o600))

	allow := map[string]struct{}{filepath.ToSlash(tf): {}}
	got := getInputVariables(context.Background(), vfs.DiskFS{}, dir, "", "", allow, "")
	vars := got["var"].AsValueMap()
	require.Equal(t, "from-tf", vars["bucket"].AsString())
}

func TestGetInputVariables_InventoriedTwinKeepsOwnVars(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "variables.tf")
	tofu := filepath.Join(dir, "variables.tofu")
	require.NoError(t, os.WriteFile(tf, []byte(`
variable "bucket" { default = "from-tf" }
`), 0o600))
	require.NoError(t, os.WriteFile(tofu, []byte(`
variable "bucket" { default = "from-tofu" }
`), 0o600))

	allow := map[string]struct{}{
		filepath.ToSlash(tf):   {},
		filepath.ToSlash(tofu): {},
	}
	fromTF := getInputVariables(context.Background(), vfs.DiskFS{}, dir, "", "", allow, tf)
	require.Equal(t, "from-tf", fromTF["var"].AsValueMap()["bucket"].AsString())
	fromTofu := getInputVariables(context.Background(), vfs.DiskFS{}, dir, "", "", allow, tofu)
	require.Equal(t, "from-tofu", fromTofu["var"].AsValueMap()["bucket"].AsString())
}

func TestGetInputVariables_AllowMissFallsBackToDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "variables.tf"), []byte(`
variable "bucket" { default = "from-tf" }
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "variables.tofu"), []byte(`
variable "bucket" { default = "from-tofu" }
`), 0o600))

	allow := map[string]struct{}{filepath.ToSlash(filepath.Join(t.TempDir(), "other.tf")): {}}
	got := getInputVariables(context.Background(), vfs.DiskFS{}, dir, "", "", allow, "")
	vars := got["var"].AsValueMap()
	require.Equal(t, "from-tofu", vars["bucket"].AsString())
}
