/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package source

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/open-policy-agent/opa/ast"
	"github.com/stretchr/testify/require"
)

// mergeLibraries return custom library and embedded library merged, overwriting embedded library functions, if necessary
func mergeLibraries(ctx context.Context, customLib, embeddedLib string) (string, error) {
	contextLogger := logger.FromContext(ctx)
	if customLib == "" {
		return embeddedLib, nil
	}
	statements, _, err := ast.NewParser().WithReader(strings.NewReader(customLib)).Parse()
	if err != nil {
		contextLogger.Err(err).Msg("Could not parse custom library")
		return "", err
	}
	headers := make(map[string]string)
	variables := make(map[string]string)
	for _, st := range statements {
		if rule, ok := st.(*ast.Rule); ok {
			headers[string(rule.Head.Name)] = ""
		}
		if regoPackage, ok := st.(ast.Body); ok {
			variableSet := regoPackage.Vars(ast.SafetyCheckVisitorParams)
			for variable := range variableSet {
				variables[variable.String()] = ""
			}
		}
	}
	statements, _, err = ast.NewParser().WithReader(strings.NewReader(embeddedLib)).Parse()
	if err != nil {
		contextLogger.Err(err).Msg("Could not parse default library")
		return "", err
	}
	for _, st := range statements {
		if rule, ok := st.(*ast.Rule); ok {
			if _, remove := headers[string(rule.Head.Name)]; remove {
				embeddedLib = strings.Replace(embeddedLib, string(rule.Location.Text), "", 1)
			}
			continue
		}
		if regoPackage, ok := st.(*ast.Package); ok {
			firstHalf := strings.Join(strings.Split(embeddedLib, "\n")[:regoPackage.Location.Row-1], "\n")
			secondHalf := strings.Join(strings.Split(embeddedLib, "\n")[regoPackage.Location.Row+1:], "\n")
			embeddedLib = firstHalf + "\n" + secondHalf
			continue
		}
		if body, ok := st.(ast.Body); ok {
			variableSet := body.Vars(ast.SafetyCheckVisitorParams)
			for variable := range variableSet {
				if _, remove := variables[variable.String()]; remove {
					embeddedLib = strings.Replace(embeddedLib, string(body.Loc().Text), "", 1)
					break
				}
			}
		}
	}
	customLib += "\n" + embeddedLib

	return customLib, nil
}

func TestMergeLibraries(t *testing.T) { //nolint
	tests := []struct {
		name        string
		customLib   string
		embeddedLib string
		expected    string
		errExpected bool
	}{
		{
			name:      "Should return default library",
			customLib: "",
			embeddedLib: `dummy_test(a) {
	a
			}`,
			expected: `dummy_test(a) {
	a
			}`,
			errExpected: false,
		},
		{
			name: "Should return just custom library",
			customLib: `dummy_test(b) {
	b
			}`,
			embeddedLib: `dummy_test(a) {
	a
			}`,
			expected: `dummy_test(b) {
	b
			}
`,
			errExpected: false,
		},
		{
			name: "Should return merged libraries",
			customLib: `other_dummy_test(b) {
	b
			}`,
			embeddedLib: `dummy_test(a) {
	a
			}`,
			expected: `other_dummy_test(b) {
	b
			}
dummy_test(a) {
	a
			}`,
			errExpected: false,
		},
		{
			name: "Should return merged libraries with overwritten functions",
			customLib: `other_dummy_test(b) {
	b
			}
`,
			embeddedLib: `dummy_test(a) {
	a
			}
other_dummy_test(c) {
	c
			}`,
			expected: `other_dummy_test(b) {
	b
			}

dummy_test(a) {
	a
			}
`,
			errExpected: false,
		},
		{
			name: "Should return error since custom lib is invalid",
			customLib: `other_dummy_test(b) {
	b
			`,
			embeddedLib: `dummy_test(a) {
	a
			}`,
			expected:    "",
			errExpected: true,
		},
		{
			name: "Should return error since embedded lib is invalid",
			customLib: `other_dummy_test(b) {
	b
			}`,
			embeddedLib: `dummy_test(a) {
	a
			`,
			expected:    "",
			errExpected: true,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mergeLibraries(ctx, tt.customLib, tt.embeddedLib)
			if tt.errExpected {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.expected, got)
		})
	}
}

// TestMergeInputData tests mergeInputData function
func TestMergeInputData(t *testing.T) {
	tests := []struct {
		name        string
		customData  string
		defaultData string
		want        string
	}{
		{
			name:        "Should merge input data strings",
			defaultData: `{"test": "success"}`,
			customData:  `{"test": "merge", "merge": "success"}`,
			want:        `{"test": "merge","merge": "success"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MergeInputData(tt.defaultData, tt.customData)
			require.NoError(t, err)
			wantJSON := map[string]interface{}{}
			gotJSON := map[string]interface{}{}
			err = json.Unmarshal([]byte(tt.want), &wantJSON)
			require.NoError(t, err)
			err = json.Unmarshal([]byte(got), &gotJSON)
			require.NoError(t, err)
			require.Equal(t, wantJSON, gotJSON)
		})
	}
}
