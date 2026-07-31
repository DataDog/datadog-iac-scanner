package scan

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/analyzer"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, shouldScanTfPlans bool) *Client {
	t.Helper()

	params := &Parameters{
		PreviewLines:      3,
		RepoPath:          t.TempDir(),
		Path:              []string{t.TempDir()},
		ShouldScanTfPlans: shouldScanTfPlans,
	}

	tr, err := tracker.NewTracker(params.PreviewLines)
	require.NoError(t, err)

	return &Client{
		ScanParams:    params,
		Tracker:       tr,
		Storage:       storage.NewMemoryStorage(),
		FlagEvaluator: featureflags.NewLocalEvaluator(),
	}
}

// TestJSONParserRegistration verifies that the JSON parser is registered for
// JSON-capable platforms like cloudformation regardless of ShouldScanTfPlans,
// but only registered for terraform when ShouldScanTfPlans is true, since
// that's the only reason the JSON parser handles terraform.
func TestJSONParserRegistration(t *testing.T) {
	tests := []struct {
		name              string
		platforms         []string
		shouldScanTfPlans bool
		expectJSONParser  bool
	}{
		{"cloudformation, flag off", []string{"cloudformation"}, false, true},
		{"cloudformation, flag on", []string{"cloudformation"}, true, true},
		{"terraform, flag off", []string{"terraform"}, false, false},
		{"terraform, flag on", []string{"terraform"}, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			client := newTestClient(t, tt.shouldScanTfPlans)

			services, err := client.createService(
				ctx, nil, []string{client.ScanParams.Path[0]}, nil,
				client.Tracker, client.Storage, tt.platforms, []string{""},
				client.FlagEvaluator, nil,
			)

			require.NoError(t, err)
			assert.Equal(t, tt.expectJSONParser, countParsersOfType(services, model.KindJSON) > 0)
		})
	}
}

// TestAnalyzerJSONInventoryGate verifies analyzer inventory rules for JSON files.
func TestAnalyzerJSONInventoryGate(t *testing.T) {
	fixturesDir := filepath.FromSlash("../../test/fixtures/tfplan_flag_test")
	tfPlan := filepath.Join(fixturesDir, "tfplan.json")
	cfJSON := filepath.Join(fixturesDir, "cloudformation.json")

	tests := []struct {
		name        string
		paths       []string
		platforms   []string
		scanTfPlans bool
		wantInInv   []string
		wantExc     []string
	}{
		{
			name:        "cloudformation json in inventory when flag off",
			paths:       []string{cfJSON},
			platforms:   []string{"cloudformation"},
			scanTfPlans: false,
			wantInInv:   []string{cfJSON},
		},
		{
			name:        "tfplan excluded when flag off and terraform only",
			paths:       []string{tfPlan},
			platforms:   []string{"terraform"},
			scanTfPlans: false,
			wantExc:     []string{tfPlan},
		},
		{
			name:        "tfplan in inventory when flag on",
			paths:       []string{tfPlan},
			platforms:   []string{"terraform"},
			scanTfPlans: true,
			wantInInv:   []string{tfPlan},
		},
		{
			name:        "both json files in inventory when flag on",
			paths:       []string{fixturesDir},
			platforms:   []string{"terraform", "cloudformation"},
			scanTfPlans: true,
			wantInInv:   []string{tfPlan, cfJSON},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := analyzer.Analyze(ctx, &analyzer.Analyzer{
				RepoPath:    filepath.Dir(fixturesDir),
				Paths:       tt.paths,
				Types:       tt.platforms,
				MaxFileSize: -1,
				ScanTfPlans: tt.scanTfPlans,
			})
			require.NoError(t, err)

			inventory := make(map[string]struct{}, len(got.Inventory))
			for _, p := range got.Inventory {
				inventory[filepath.ToSlash(p)] = struct{}{}
			}
			excluded := make(map[string]struct{}, len(got.Exc))
			for _, p := range got.Exc {
				excluded[filepath.ToSlash(p)] = struct{}{}
			}

			for _, want := range tt.wantInInv {
				_, ok := inventory[filepath.ToSlash(want)]
				assert.True(t, ok, "expected %s in inventory", want)
			}
			for _, want := range tt.wantExc {
				_, ok := excluded[filepath.ToSlash(want)]
				assert.True(t, ok, "expected %s excluded", want)
			}
		})
	}
}

// Helper function to count parsers of a specific type
func countParsersOfType(services []*runner.Service, parserType model.FileKind) int {
	count := 0
	for _, service := range services {
		if service.Parser != nil && service.Parser.Parsers != nil {
			if service.Parser.Parsers.GetKind() == parserType {
				count++
			}
		}
	}
	return count
}

// TestJSONParserNotDoubleRegistered ensures JSON parser isn't registered multiple times
func TestJSONParserNotDoubleRegistered(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t, true)

	for range 3 {
		services, err := client.createService(
			ctx, nil, []string{client.ScanParams.Path[0]}, nil,
			client.Tracker, client.Storage, []string{"terraform"}, []string{""},
			client.FlagEvaluator, nil,
		)

		require.NoError(t, err)
		require.NotNil(t, services)
		assert.LessOrEqual(t, countParsersOfType(services, model.KindJSON), 1,
			"Should have at most one JSON parser per service creation")
	}
}
