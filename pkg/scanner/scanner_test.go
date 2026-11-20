package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver"
	"github.com/DataDog/datadog-iac-scanner/pkg/runner"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"

	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/default"
)

// emptyQuerySource serves no queries and returns a minimal common library stub.
type emptyQuerySource struct{ queries []model.QueryMetadata }

func (e *emptyQuerySource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return e.queries, nil
}

func (e *emptyQuerySource) GetQueryLibrary(_ context.Context, _ string) (source.RegoLibraries, error) {
	return source.RegoLibraries{LibraryCode: "package generic.common\n", LibraryInputData: "{}"}, nil
}

// TestScanner_StartScan checks StartScan returns nil on an uncancelled ctx when rules are served by the backend.
func TestScanner_StartScan(t *testing.T) {
	services, store, err := createServices([]string{""}, []string{""})
	require.NoError(t, err)
	failures, err := StartScan(context.Background(), "console", services)
	require.NoError(t, err)
	require.Equal(t, 0, failures.Len())
	require.NotEmpty(t, &store)
}

// A config or platform filter can leave no service. That is an empty scan, which
// must not fail as if the services used mixed source providers.
func TestPrepareAndScanWithoutServices(t *testing.T) {
	failures, err := PrepareAndScan(context.Background(), "server", false, 5, nil)
	require.NoError(t, err)
	require.Equal(t, 0, failures.Len())
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
	querySource := &emptyQuerySource{}

	inspector, err := engine.NewInspector(context.Background(),
		querySource, engine.DefaultVulnerabilityBuilder,
		t, &source.QueryInspectorParameters{}, nil, ".", true, true, 1,
		featureflags.NewLocalEvaluator(),
		vfs.DiskFS{},
		false,
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

type outcomeSink struct {
	runner.Storage
	save func(context.Context) error
}

func (s outcomeSink) SaveVulnerabilities(ctx context.Context, _ []model.Vulnerability) error {
	return s.save(ctx)
}

func TestScannerEvaluationOutcomeLifecycle(t *testing.T) {
	for _, test := range []struct {
		name                                  string
		semantic, fatal, parentCancel, joined bool
	}{
		{name: "semantic failure waits for independent completion", semantic: true},
		{name: "fatal sink cancels and joins peer", fatal: true},
		{name: "semantic and sink failures remain distinct", semantic: true, fatal: true},
		{name: "joined sink and cancellation remains fatal", fatal: true, joined: true},
		{name: "parent cancellation retains authority", parentCancel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			root := t.TempDir()
			tf := `resource "aws_s3_bucket" "same" {acl="private"}`
			require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(tf), 0600))
			if test.semantic {
				require.NoError(t, os.WriteFile(filepath.Join(root, "invalid_override.tf"), []byte(`locals {`), 0600))
			}
			services, store, err := createServices([]string{"terraform", "kubernetes"}, []string{""})
			require.NoError(t, err)
			fsp, err := provider.NewFileSystemSourceProvider(ctx, []string{root}, nil, nil)
			require.NoError(t, err)
			tr, err := tracker.NewTracker(1)
			require.NoError(t, err)
			q := model.QueryMetadata{Query: "outcome", InputData: "{}", Platform: "terraform", Metadata: map[string]interface{}{"id": "outcome", "platform": "Terraform"}, Content: `package datadog
import rego.v1
DatadogPolicy contains result if {some doc in input.document;some name;doc.resource.aws_s3_bucket[name].acl=="public";result:={"documentId":doc.id,"resourceType":"aws_s3_bucket","resourceName":name,"searchKey":"acl"}}`}
			inspector, err := engine.NewInspector(ctx, &emptyQuerySource{queries: []model.QueryMetadata{q}}, engine.DefaultVulnerabilityBuilder, tr, &source.QueryInspectorParameters{}, nil, root, false, false, 1, featureflags.NewLocalEvaluator(), vfs.DiskFS{}, false)
			require.NoError(t, err)
			configured, peerStarted, peerFinished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			sinkErr := errors.New("owned sink failure")
			for _, service := range services {
				service.SourceProvider = fsp
				service.Inspector = inspector
				service.Tracker = tr
				switch service.Parser.Parsers.GetKind() {
				case model.KindTerraform:
					service.Storage = outcomeSink{Storage: store, save: func(context.Context) error { close(configured); return nil }}
				case model.KindJSON:
					service.Storage = outcomeSink{Storage: store, save: func(ctx context.Context) error {
						if test.semantic {
							select {
							case <-configured:
							case <-ctx.Done():
								return ctx.Err()
							}
						}
						if test.fatal || test.parentCancel {
							select {
							case <-peerStarted:
							case <-ctx.Done():
								return ctx.Err()
							}
						}
						if test.parentCancel {
							cancel()
							return ctx.Err()
						}
						if test.fatal {
							if test.joined {
								return errors.Join(sinkErr, context.Canceled)
							}
							return sinkErr
						}
						return nil
					}}
				default:
					service.Storage = outcomeSink{Storage: store, save: func(ctx context.Context) error {
						close(peerStarted)
						defer close(peerFinished)
						if test.fatal || test.parentCancel {
							<-ctx.Done()
							return ctx.Err()
						}
						return nil
					}}
				}
			}
			require.NoError(t, runner.PrepareDiskSources(ctx, fsp, services, "lifecycle", false, 5))
			failures, err := StartScan(ctx, "lifecycle", services)
			select {
			case <-peerFinished:
			default:
				t.Fatal("returned before independent worker exited")
			}
			if test.semantic {
				require.Equal(t, 1, failures.Len())
			} else {
				require.Zero(t, failures.Len())
			}
			switch {
			case test.parentCancel:
				require.ErrorIs(t, err, context.Canceled)
			case test.fatal:
				require.ErrorIs(t, err, sinkErr)
				require.NoError(t, ctx.Err())
				if !test.joined {
					require.NotErrorIs(t, err, context.Canceled)
				}
			default:
				require.NoError(t, err)
				require.NoError(t, ctx.Err())
			}
		})
	}
}
