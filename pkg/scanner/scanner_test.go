package scanner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver"
	"github.com/DataDog/datadog-iac-scanner/pkg/runner"
	"github.com/stretchr/testify/require"

	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/default"
)

// TestScanner_StartScan checks StartScan returns nil on an uncancelled ctx when rules are served by the backend.
func TestScanner_StartScan(t *testing.T) {
	services, store, err := createServices([]string{""}, []string{""})
	require.NoError(t, err)
	require.NoError(t, StartScan(context.Background(), "console", services))
	require.NotEmpty(t, &store)
}

func createServices(types, cloudProviders []string) (serviceSlice, *storage.MemoryStorage, error) {
	ctx := context.Background()
	filesSource, err := provider.NewFileSystemSourceProvider(ctx, []string{filepath.FromSlash("../../test")}, []string{}, []string{})
	if err != nil {
		return nil, nil, err
	}

	t, err := tracker.NewTracker(1)
	if err != nil {
		return nil, nil, err
	}
	querySource := source.NewFilesystemSource(ctx, []string{}, types, cloudProviders, filepath.FromSlash("../../assets/libraries"), true)

	inspector, err := engine.NewInspector(context.Background(),
		querySource, engine.DefaultVulnerabilityBuilder,
		t, &source.QueryInspectorParameters{}, nil, ".", 60, true, true, 1,
		featureflags.NewLocalEvaluator(),
	)
	if err != nil {
		return nil, nil, err
	}

	combinedParser, err := parser.NewBuilder(ctx).
		Add(&jsonParser.Parser{}).
		Add(&yamlParser.Parser{}).
		Add(terraformParser.NewDefault()).
		Build(types, cloudProviders)
	if err != nil {
		return nil, nil, err
	}

	combinedResolver, err := resolver.NewBuilder().
		Build(ctx)
	if err != nil {
		return nil, nil, err
	}

	store := storage.NewMemoryStorage()

	services := make([]*runner.Service, 0, len(combinedParser))

	for _, parser := range combinedParser {
		services = append(services, &runner.Service{
			SourceProvider: filesSource,
			Storage:        store,
			Parser:         parser,
			Inspector:      inspector,
			Tracker:        t,
			Resolver:       combinedResolver,
			MaxFileSize:    100,
		})
	}
	return services, store, nil
}
