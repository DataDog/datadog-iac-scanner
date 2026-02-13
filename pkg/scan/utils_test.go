package scan

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/analyzer"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/stretchr/testify/require"
)

func contributionAppeal(customPrint *consolePrinter.Printer, queriesPath []string) {
	if usingCustomQueries(queriesPath) {
		msg := "\nAre you using a custom query? If so, feel free to contribute to KICS!\n"
		contributionPage := "Check out how to do it: https://github.com/DataDog/datadog-iac-scanner/blob/master/docs/CONTRIBUTING.md\n"

		output := customPrint.ContributionMessage.Sprintf(msg + contributionPage)
		fmt.Println(output)
	}
}

func Test_GetQueryPath(t *testing.T) {
	tests := []struct {
		name       string
		scanParams Parameters
		want       int
	}{
		{
			name: "multiple queries path",
			scanParams: Parameters{
				QueriesPath: []string{
					filepath.Join("..", "..", "assets", "queries", "terraform", "aws"),
					filepath.Join("..", "..", "assets", "queries", "terraform", "azure"),
				},
				ChangedDefaultQueryPath: true,
			},
			want: 2,
		},
		{
			name: "single query path",
			scanParams: Parameters{
				QueriesPath: []string{
					filepath.Join("..", "..", "assets", "queries", "terraform", "aws"),
				},
				ChangedDefaultQueryPath: true,
			},
			want: 1,
		},
		{
			name: "default query path",
			scanParams: Parameters{
				QueriesPath: []string{filepath.Join("..", "..", "assets", "queries")},
			},
			want: 1,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := Client{
				ScanParams: &tt.scanParams,
			}

			client.GetQueryPath(ctx)

			if got := client.ScanParams.QueriesPath; !reflect.DeepEqual(len(got), tt.want) {
				t.Errorf("GetQueryPath() = %v, want %v", len(got), tt.want)
			}
		})
	}
}

func Test_ContributionAppeal(t *testing.T) {
	tests := []struct {
		name           string
		consolePrinter *consolePrinter.Printer
		queriesPath    []string
		expectedOutput string
	}{
		{
			name:           "test custom query",
			consolePrinter: consolePrinter.NewPrinter(),
			queriesPath:    []string{filepath.Join("custom", "query", "path")},
			expectedOutput: "\nAre you using a custom query? If so, feel free to contribute to KICS!\nCheck out how to do it: https://github.com/DataDog/datadog-iac-scanner/blob/master/docs/CONTRIBUTING.md",
		},
		{
			name:           "test non custom query",
			consolePrinter: consolePrinter.NewPrinter(),
			queriesPath:    []string{filepath.Join("assets", "queries", "path")},
			expectedOutput: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			contributionAppeal(tt.consolePrinter, tt.queriesPath)

			_ = w.Close()
			out, _ := ioutil.ReadAll(r)
			os.Stdout = rescueStdout

			if tt.expectedOutput != "" {
				require.Contains(t, string(out), tt.expectedOutput)
			} else {
				require.Equal(t, tt.expectedOutput, string(out))
			}
		})
	}

}

func Test_GetTotalFiles(t *testing.T) {
	tests := []struct {
		name           string
		paths          []string
		expectedOutput int
	}{
		{
			name:           "count utils folder files",
			paths:          []string{filepath.Join("..", "..", "pkg", "utils")},
			expectedOutput: 16,
		},
		{
			name:           "count analyzer folder files",
			paths:          []string{filepath.Join("..", "..", "pkg", "analyzer")},
			expectedOutput: 2,
		},
		{
			name:           "count analyzer and utils folder files",
			paths:          []string{filepath.Join("..", "..", "pkg", "analyzer"), filepath.Join("..", "..", "pkg", "utils")},
			expectedOutput: 18,
		},
		{
			name:           "count invalid folder",
			paths:          []string{filepath.Join("pkg", "nonexistent")},
			expectedOutput: 0,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			v := getTotalFiles(ctx, tt.paths)
			require.Equal(t, tt.expectedOutput, v)

		})
	}
}

func Test_LogLoadingQueriesType(t *testing.T) {
	tests := []struct {
		name           string
		types          []string
		expectedOutput string
	}{
		{
			name:           "empty types",
			types:          []string{},
			expectedOutput: "",
		},
		{
			name:           "type terraform",
			types:          []string{"terraform"},
			expectedOutput: "",
		},
		{
			name:           "multiple types",
			types:          []string{"terraform", "cloudformation"},
			expectedOutput: "",
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			logLoadingQueriesType(ctx, tt.types)

			w.Close()
			out, _ := ioutil.ReadAll(r)
			os.Stdout = rescueStdout

			require.Equal(t, tt.expectedOutput, string(out))

		})
	}

}

func Test_ExtractPathType(t *testing.T) {
	tests := []struct {
		name               string
		paths              []string
		expectedKuberneter []string
		expectedPaths      []string
	}{
		{
			name:               "kuberneter",
			paths:              []string{"kuberneter::*:*:*"},
			expectedKuberneter: []string{"*:*:*"},
			expectedPaths:      []string(nil),
		},
		{
			name:               "count progress and utils folder files",
			paths:              []string{filepath.Join("..", "..", "pkg", "progress"), filepath.Join("..", "..", "pkg", "utils")},
			expectedKuberneter: []string(nil),
			expectedPaths:      []string{filepath.Join("..", "..", "pkg", "progress"), filepath.Join("..", "..", "pkg", "utils")},
		},
		{
			name:               "empty",
			paths:              []string{},
			expectedKuberneter: []string(nil),
			expectedPaths:      []string(nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			vPaths, vKuberneter := extractPathType(tt.paths)

			require.Equal(t, tt.expectedKuberneter, vKuberneter)
			require.Equal(t, tt.expectedPaths, vPaths)

		})
	}
}

func Test_CombinePaths(t *testing.T) {
	tests := []struct {
		name           string
		kuberneter     provider.ExtractedPath
		regular        provider.ExtractedPath
		expectedOutput provider.ExtractedPath
	}{
		{
			name: "kuberneter ExtractedPath",
			kuberneter: provider.ExtractedPath{
				Path: []string{""},
				ExtractionMap: map[string]model.ExtractedPathObject{
					"": {
						Path:      "",
						LocalPath: true,
					},
				},
			},
			regular: provider.ExtractedPath{},
			expectedOutput: provider.ExtractedPath{
				Path: []string{""},
				ExtractionMap: map[string]model.ExtractedPathObject{
					"": {
						Path:      "",
						LocalPath: true,
					},
				},
			},
		},
		{
			name: "one regular ExtractedPath",
			regular: provider.ExtractedPath{
				Path: []string{"kics/assets/queries/terraform/alicloud/action_trail_logging_all_regions_disabled"},
				ExtractionMap: map[string]model.ExtractedPathObject{
					"": {
						Path:      "./assets/queries/terraform/alicloud/action_trail_logging_all_regions_disabled",
						LocalPath: true,
					},
				},
			},
			kuberneter: provider.ExtractedPath{},
			expectedOutput: provider.ExtractedPath{
				Path: []string{"kics/assets/queries/terraform/alicloud/action_trail_logging_all_regions_disabled"},
				ExtractionMap: map[string]model.ExtractedPathObject{
					"": {
						Path:      "./assets/queries/terraform/alicloud/action_trail_logging_all_regions_disabled",
						LocalPath: true,
					},
				},
			},
		},
		{
			name: "multiple regular ExtractedPath",
			regular: provider.ExtractedPath{
				Path: []string{
					"/home/miguel/cx/kics/assets/queries/terraform/alicloud/action_trail_logging_all_regions_disabled",
					"/home/miguel/cx/kics/assets/queries/terraform/alicloud/actiontrail_trail_oss_bucket_is_publicly_accessible",
				},
				ExtractionMap: map[string]model.ExtractedPathObject{
					"/tmp/kics-extract-872644142": {
						Path:      "github.com/DataDog/datadog-iac-scanner/pkg/model.ExtractedPathObject",
						LocalPath: true,
					},
					"/tmp/kics-extract-539696053": {
						Path:      "github.com/DataDog/datadog-iac-scanner/pkg/model.ExtractedPathObject",
						LocalPath: true,
					},
				},
			},

			kuberneter: provider.ExtractedPath{},
			expectedOutput: provider.ExtractedPath{
				Path: []string{
					"/home/miguel/cx/kics/assets/queries/terraform/alicloud/action_trail_logging_all_regions_disabled",
					"/home/miguel/cx/kics/assets/queries/terraform/alicloud/actiontrail_trail_oss_bucket_is_publicly_accessible",
				},
				ExtractionMap: map[string]model.ExtractedPathObject{
					"/tmp/kics-extract-872644142": {
						Path:      "github.com/DataDog/datadog-iac-scanner/pkg/model.ExtractedPathObject",
						LocalPath: true,
					},
					"/tmp/kics-extract-539696053": {
						Path:      "github.com/DataDog/datadog-iac-scanner/pkg/model.ExtractedPathObject",
						LocalPath: true,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extPath := provider.ExtractedPath{
				Path:          []string{},
				ExtractionMap: make(map[string]model.ExtractedPathObject),
			}
			v := combinePaths(tt.kuberneter, tt.regular, extPath, extPath)

			require.Equal(t, tt.expectedOutput, v)
		})
	}
}

func Test_GetLibraryPath(t *testing.T) {

	tests := []struct {
		name           string
		scanParameters Parameters
		expectedError  bool
	}{
		{
			name: "default without flag",
			scanParameters: Parameters{
				LibrariesPath:               "./assets/libraries",
				ChangedDefaultLibrariesPath: false,
			},
			expectedError: false,
		},
		{
			name: "default with flag",
			scanParameters: Parameters{
				LibrariesPath:               filepath.Join("..", "..", "assets", "libraries"),
				ChangedDefaultLibrariesPath: true,
			},
			expectedError: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{}

			c.ScanParams = &tt.scanParameters
			_, v := c.getLibraryPath(ctx)

			if tt.expectedError {
				require.Error(t, v)
			} else {
				require.NoError(t, v)
			}

		})
	}
}

func Test_PreparePaths(t *testing.T) {

	tests := []struct {
		name            string
		scanParameters  Parameters
		expectedError   bool
		queriesQuantity int
	}{
		{
			name: "default without flag",
			scanParameters: Parameters{
				LibrariesPath:               "./assets/libraries",
				ChangedDefaultLibrariesPath: false,
				QueriesPath: []string{
					filepath.Join("..", "..", "assets", "queries", "terraform", "aws"),
					filepath.Join("..", "..", "assets", "queries", "terraform", "azure"),
				},
				ChangedDefaultQueryPath: true,
			},
			expectedError:   false,
			queriesQuantity: 2,
		},
		{
			name: "default with flag",
			scanParameters: Parameters{
				LibrariesPath:               filepath.Join("..", "..", "assets", "libraries"),
				ChangedDefaultLibrariesPath: true,
				QueriesPath: []string{
					filepath.Join("..", "..", "assets", "queries", "terraform", "aws"),
					filepath.Join("..", "..", "assets", "queries", "terraform", "azure"),
				},
				ChangedDefaultQueryPath: true,
			},
			queriesQuantity: 2,
			expectedError:   false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{}
			c.ScanParams = &tt.scanParameters
			_, _, v := c.preparePaths(ctx)

			require.Equal(t, tt.queriesQuantity, len(c.ScanParams.QueriesPath))
			if tt.expectedError {
				require.Error(t, v)
			} else {
				require.NoError(t, v)
			}

		})
	}
}

func Test_AnalyzePaths(t *testing.T) {
	tests := []struct {
		name           string
		analyzer       analyzer.Analyzer
		expectedError  bool
		expectedOutput model.AnalyzedPaths
	}{
		{
			name: "test",
			analyzer: analyzer.Analyzer{
				Paths: []string{
					filepath.Join("..", "..", "assets", "queries", "terraform", "alicloud", "action_trail_logging_all_regions_disabled"),
					filepath.Join("..", "..", "assets", "queries", "terraform", "alicloud", "actiontrail_trail_oss_bucket_is_publicly_accessible"),
				},
				Types:             []string{""},
				ExcludeTypes:      []string{""},
				Exc:               []string{},
				GitIgnoreFileName: ".gitignore",
				ExcludeGitIgnore:  false,
				MaxFileSize:       -1,
			},
			expectedError: false,
			expectedOutput: model.AnalyzedPaths{
				Types: []string{"terraform"},
				Exc: []string{
					filepath.Join("..", "..", "assets", "queries", "terraform", "alicloud", "action_trail_logging_all_regions_disabled", "test", "positive_expected_result.json"),
					filepath.Join("..", "..", "assets", "queries", "terraform", "alicloud", "action_trail_logging_all_regions_disabled", "metadata.json"),
					filepath.Join("..", "..", "assets", "queries", "terraform", "alicloud", "actiontrail_trail_oss_bucket_is_publicly_accessible", "metadata.json"),
					filepath.Join("..", "..", "assets", "queries", "terraform", "alicloud", "actiontrail_trail_oss_bucket_is_publicly_accessible", "test", "positive_expected_result.json"),
				},
			},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			anPaths, err := analyzePaths(ctx, &tt.analyzer)
			require.ElementsMatch(t, tt.expectedOutput.Types, anPaths.Types)
			require.ElementsMatch(t, tt.expectedOutput.Exc, anPaths.Exc)
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
