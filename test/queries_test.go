package test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/mock"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

func BenchmarkQueries(b *testing.B) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: io.Discard})

	queries := loadQueries(b)
	for _, entry := range queries {
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			benchmarkPositiveAndNegativeQueries(b, entry)
		}
	}
}

func TestQueries(t *testing.T) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: io.Discard})

	if testing.Short() {
		t.Skip("skipping queries test in short mode.")
	}

	queries := loadQueries(t)
	for _, entry := range queries {
		testPositiveAndNegativeQueries(t, entry)
	}
}

// func testRemediationQuery(t testing.TB, entry queryEntry, vulnerabilities []model.Vulnerability) {
// 	summary := &remediation.Summary{
// 		SelectedRemediationNumber:   0,
// 		ActualRemediationDoneNumber: 0,
// 	}

// 	// get remediationSets from query vulns
// 	remediationSets := summary.GetRemediationSetsFromVulns(vulnerabilities, []string{"all"})

// 	if len(remediationSets) > 0 {
// 		// verify if the remediation vulns actually remediates the results
// 		data, err := os.ReadFile(filepath.FromSlash("../internal/console/assets/scan-flags.json"))
// 		require.NoError(t, err)

// 		mockCmd := &cobra.Command{
// 			Use:   "mock",
// 			Short: "Mock cmd",
// 			RunE: func(cmd *cobra.Command, args []string) error {
// 				return nil
// 			},
// 		}

// 		flags.InitJSONFlags(
// 			mockCmd,
// 			string(data),
// 			true,
// 			source.ListSupportedPlatforms(),
// 			source.ListSupportedCloudProviders(),
// 		)

// 		temporaryRemediationSets := make(map[string]interface{})

// 		for k := range remediationSets {
// 			tmpFilePath := filepath.Join(os.TempDir(), "temporary-remediation-"+utils.NextRandom()+filepath.Ext(k))
// 			tmpFile := remediation.CreateTempFile(k, tmpFilePath)

// 			temporaryRemediationSets[tmpFile] = remediationSets[k]
// 		}

// 		for filePath := range temporaryRemediationSets {
// 			fix := temporaryRemediationSets[filePath].(remediation.Set)

// 			err = summary.RemediateFile(filePath, fix, false, 15)
// 			os.Remove(filePath)
// 			if err != nil {
// 				require.NoError(t, err)
// 			}
// 		}

// 		require.Equal(t, summary.SelectedRemediationNumber, summary.ActualRemediationDoneNumber,
// 			"'SelectedRemediationNumber' is different from 'ActualRemediationDoneNumber'")

// 	}
// }

func TestUniqueQueryIDs(t *testing.T) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: io.Discard})
	queries := loadQueries(t)

	queriesIdentifiers := make(map[string]string)

	ctx := context.Background()
	for _, entry := range queries {
		queryPath := strings.TrimPrefix(entry.dir, filepath.FromSlash("../assets/"))
		metadata, err := source.ReadMetadata(ctx, queryPath)
		require.NoError(t, err)
		uuid := metadata["id"].(string)
		duplicateDir, ok := queriesIdentifiers[uuid]
		require.False(t, ok, "\nnon unique queryID found uuid: %s\nqueryDir: %s\nduplicateDir: %s",
			uuid, entry.dir, duplicateDir)
		queriesIdentifiers[uuid] = entry.dir

		if override, ok := metadata["override"].(map[string]interface{}); ok {
			for _, v := range override {
				if convertedValue, converted := v.(map[string]interface{}); converted {
					if id, ok := convertedValue["id"].(string); ok {
						duplicateDir, ok = queriesIdentifiers[id]
						require.False(t, ok, "\nnon unique queryID found on overriding uuid: %s\nqueryDir: %s\nduplicateDir: %s",
							id, entry.dir, duplicateDir)
						queriesIdentifiers[id] = entry.dir
					}
				}
			}
		}
	}
}

func testPositiveAndNegativeQueries(t *testing.T, entry queryEntry) {
	name := strings.TrimPrefix(entry.dir, filepath.FromSlash(BaseTestsScanPath))
	t.Run(name+"_positive", func(t *testing.T) {
		testQuery(t, entry, entry.PositiveFiles(t), getExpectedVulnerabilities(t, entry))
	})
	t.Run(name+"_negative", func(t *testing.T) {
		testQuery(t, entry, entry.NegativeFiles(t), []model.Vulnerability{})
	})
}

func benchmarkPositiveAndNegativeQueries(b *testing.B, entry queryEntry) {
	name := strings.TrimPrefix(entry.dir, filepath.FromSlash(BaseTestsScanPath))
	b.Run(name+"_positive", func(b *testing.B) {
		testQuery(b, entry, entry.PositiveFiles(b), getExpectedVulnerabilities(b, entry))
	})
	b.Run(name+"_negative", func(b *testing.B) {
		testQuery(b, entry, entry.NegativeFiles(b), []model.Vulnerability{})
	})
}

func getExpectedVulnerabilities(tb testing.TB, entry queryEntry) []model.Vulnerability {
	content, err := os.ReadFile(entry.ExpectedPositiveResultFile())
	require.NoError(tb, err, "can't read expected result file %s", entry.ExpectedPositiveResultFile())

	var expectedVulnerabilities []model.Vulnerability
	err = json.Unmarshal(content, &expectedVulnerabilities)
	require.NoError(tb, err, "can't unmarshal expected result file %s", entry.ExpectedPositiveResultFile())

	return expectedVulnerabilities
}

func testQuery(tb testing.TB, entry queryEntry, filesPath []string, expectedVulnerabilities []model.Vulnerability) {
	ctrl := gomock.NewController(tb)
	defer ctrl.Finish()

	ctx := context.Background()

	queriesSource := mock.NewMockQueriesSource(ctrl)
	queriesSource.EXPECT().GetQueries(gomock.Any(), getQueryFilter()).
		DoAndReturn(func(ctx context.Context, querySelection interface{}) ([]model.QueryMetadata, error) {
			queryPath := strings.TrimPrefix(entry.dir, filepath.FromSlash("../assets/"))
			q, err := source.ReadQuery(ctx, queryPath)
			require.NoError(tb, err)

			return []model.QueryMetadata{q}, nil
		})

	queriesSource.EXPECT().GetQueryLibrary(gomock.Any(), "common").
		DoAndReturn(func(ctx context.Context, platform string) (source.RegoLibraries, error) {
			q, err := readLibrary(platform)
			require.NoError(tb, err)
			return q, nil
		})

	queriesSource.EXPECT().GetQueryLibrary(gomock.Any(), entry.platform).
		DoAndReturn(func(ctx context.Context, platform string) (source.RegoLibraries, error) {
			q, err := readLibrary(platform)
			require.NoError(tb, err)
			return q, nil
		})

	inspector, err := engine.NewInspector(ctx,
		queriesSource,
		engine.DefaultVulnerabilityBuilder,
		&tracker.CITracker{},
		&source.QueryInspectorParameters{
			IncludeQueries: source.IncludeQueries{ByIDs: []string{}},
			ExcludeQueries: source.ExcludeQueries{ByIDs: []string{}, ByCategories: []string{}},
			InputDataPath:  "",
			FlagEvaluator:  nil,
		},
		map[string]bool{}, 60, false, true, 1, false,
		featureflags.NewLocalEvaluator(),
	)

	require.Nil(tb, err)
	require.NotNil(tb, inspector)

	platforms := MapToStringSlice(constants.AvailablePlatforms)

	vulnerabilities, err := inspector.Inspect(
		ctx,
		scanID,
		getFileMetadatas(tb, filesPath),
		[]string{BaseTestsScanPath},
		platforms,
	)

	require.Nil(tb, err)
	validateQueryResultFields(tb, vulnerabilities)
	requireEqualVulnerabilities(tb, expectedVulnerabilities, vulnerabilities, entry.dir)

	// if entry.platform == "terraform" {
	// 	testRemediationQuery(tb, entry, vulnerabilities)
	// }
}

func vulnerabilityCompare(vulnerabilitySlice []model.Vulnerability, i, j int) bool {
	if vulnerabilitySlice[i].FileName != "" {
		compareFile := strings.Compare(filepath.Base(vulnerabilitySlice[i].FileName), filepath.Base(vulnerabilitySlice[j].FileName))
		if compareFile == 0 {
			return vulnerabilitySlice[i].Line < vulnerabilitySlice[j].Line
		} else if compareFile < 0 {
			return true
		}
		return false
	}
	return vulnerabilitySlice[i].Line < vulnerabilitySlice[j].Line
}

func validateQueryResultFields(tb testing.TB, vulnerabilities []model.Vulnerability) {
	for idx := range vulnerabilities {
		issueType := string(vulnerabilities[idx].IssueType)
		_, ok := issueTypes[issueType]
		require.True(tb, ok, "Results 'issueType' is not valid :: %v", issueType)
		if vulnerabilities[idx].Severity == model.SeverityTrace {
			require.Equal(tb, "Bill Of Materials", vulnerabilities[idx].Category, "TRACE results should have category 'Bill Of Materials'")
			require.Equal(tb, model.IssueType("BillOfMaterials"), vulnerabilities[idx].IssueType, "TRACE results should have issueType 'BillOfMaterials'")
			require.NotEmpty(tb, vulnerabilities[idx].Value, "TRACE results should not have empty value")

			bomResult := make(map[string]string)
			json.Unmarshal([]byte(*vulnerabilities[idx].Value), &bomResult)
			bomOutputRequiredFields := map[string]bool{
				"acl": false,
				// "is_default_password":    false,
				"policy":                 false,
				"resource_type":          true,
				"resource_name":          true,
				"resource_engine":        false,
				"resource_accessibility": true,
				"resource_vendor":        true,
				"resource_category":      true,
				// "user_name":              false,
				"resource_encryption": true,
			}
			for key := range bomOutputRequiredFields {
				_, ok := bomResult[key]
				if bomOutputRequiredFields[key] {
					require.True(tb, ok, "BoM results should have the required value fields: %s", key)
				}
			}

			for key := range bomResult {
				_, ok := bomOutputRequiredFields[key]
				require.True(tb, ok, "BoM results should only have the allowed value fields, unknown field: %s", key)
			}
		}
	}
}

func diffActualExpectedVulnerabilities(actual, expected []model.Vulnerability) []string {
	m := make(map[string]bool)
	diff := make([]string, 0)
	for i := range expected {
		m[expected[i].QueryName+":"+expected[i].FileName+":"+strconv.Itoa(expected[i].Line)] = true
	}
	for i := range actual {
		if _, ok := m[actual[i].QueryName+":"+filepath.Base(actual[i].FileName)+":"+strconv.Itoa(actual[i].Line)]; !ok {
			diff = append(diff, actual[i].FileName+":"+strconv.Itoa(actual[i].Line))
		}
	}

	return diff
}

func requireEqualVulnerabilities(tb testing.TB, expected, actual []model.Vulnerability, dir string) {
	sort.Slice(expected, func(i, j int) bool {
		return vulnerabilityCompare(expected, i, j)
	})
	sort.Slice(actual, func(i, j int) bool {
		return vulnerabilityCompare(actual, i, j)
	})

	require.Len(tb, actual, len(expected),
		"Count of actual issues and expected vulnerabilities doesn't match\n -- \n%+v",
		strings.Join(diffActualExpectedVulnerabilities(actual, expected), ",\n"))

	for i := range expected {
		if i > len(actual)-1 {
			tb.Fatalf("Not enough results detected, expected %d, found %d ",
				len(expected),
				len(actual))
		}

		expectedItem := expected[i]
		actualItem := actual[i]
		if expectedItem.FileName != "" {
			require.Equal(tb, expectedItem.FileName, filepath.Base(actualItem.FileName), "Incorrect file name for query %s", dir)
		}
		require.Equal(tb, expectedItem.Line, actualItem.Line, "Incorrect detected line for query %s \n%v\n---\n%v",
			dir, filterFileNameAndLine(expected), filterFileNameAndLine(actual))
		require.Equal(tb, expectedItem.Severity, actualItem.Severity, "Invalid severity for query %s", dir)
		require.Equal(tb, expectedItem.QueryName, actualItem.QueryName, "Invalid query name for query %s :: %s", dir, actualItem.FileName)
		if expectedItem.Value != nil {
			require.NotNil(tb, actualItem.Value)
			require.Equal(tb, *expectedItem.Value, *actualItem.Value)
		}
	}
}

type ResultItem struct {
	File string
	Line int
}

func filterFileNameAndLine(vulnerabilitySlice []model.Vulnerability) []ResultItem {
	result := []ResultItem{}
	for i := 0; i < len(vulnerabilitySlice); i++ {
		result = append(result, ResultItem{
			File: vulnerabilitySlice[i].FileName,
			Line: vulnerabilitySlice[i].Line,
		})
	}
	return result
}
