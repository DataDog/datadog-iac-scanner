/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/default"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver"
	"github.com/stretchr/testify/require"
)

// TestService tests the functions [GetVulnerabilities(), StartScan()] and all the methods called by them
func TestService(t *testing.T) { //nolint
	mockParser, mockFilesSource, mockResolver := createParserSourceProvider("../../test/fixtures/test_helm")
	type fields struct {
		SourceProvider provider.SourceProvider
		Storage        Storage
		Parser         []*parser.Parser
		Inspector      *engine.Inspector
		Tracker        Tracker
		Resolver       *resolver.Resolver
	}
	type args struct {
		ctx     context.Context
		scanID  string
		scanIDs []string
	}
	type want struct {
		vulnerabilities []model.Vulnerability
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    want
		wantErr bool
	}{
		{
			name: "service",
			fields: fields{
				Inspector: &engine.Inspector{
					QueryLoader: &engine.QueryLoader{
						QueriesMetadata: make([]model.QueryMetadata, 0),
					},
				},
				Parser:         mockParser,
				Tracker:        &tracker.CITracker{},
				Storage:        storage.NewMemoryStorage(),
				SourceProvider: mockFilesSource,
				Resolver:       mockResolver,
			},
			args: args{
				ctx:     context.Background(),
				scanID:  "scanID",
				scanIDs: []string{"scanID"},
			},
			wantErr: false,
			want: want{
				vulnerabilities: []model.Vulnerability{},
			},
		},
	}
	for _, tt := range tests {
		s := make([]*Service, 0, len(tt.fields.Parser))
		for _, parser := range tt.fields.Parser {
			s = append(s, &Service{
				SourceProvider: tt.fields.SourceProvider,
				Storage:        tt.fields.Storage,
				Parser:         parser,
				Inspector:      tt.fields.Inspector,
				Tracker:        tt.fields.Tracker,
				Resolver:       tt.fields.Resolver,
			})
		}
		t.Run(fmt.Sprintf("%s", tt.name+"_get_vulnerabilities"), func(t *testing.T) {
			for _, serv := range s {
				got, err := serv.GetVulnerabilities(tt.args.ctx, tt.args.scanID)
				if (err != nil) != tt.wantErr {
					t.Errorf("Service.GetVulnerabilities() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want.vulnerabilities) {
					t.Errorf("Service.GetVulnerabilities() = %v, want %v", got, tt.want)
				}
			}
		})
		t.Run(fmt.Sprintf("%s", tt.name+"_start_scan"), func(t *testing.T) {
			var wg sync.WaitGroup
			errCh := make(chan error)
			wgDone := make(chan bool)
			for _, serv := range s {
				wg.Add(1)
				serv.StartScan(tt.args.ctx, tt.args.scanID, errCh, &wg)
			}
			go func() {
				defer close(wgDone)
				wg.Wait()
			}()
			select {
			case <-wgDone:
				break
			case err := <-errCh:
				close(errCh)
				if (err != nil) != tt.wantErr {
					t.Errorf("Service.StartScan() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func createParserSourceProvider(path string) ([]*parser.Parser,
	*provider.FileSystemSourceProvider, *resolver.Resolver) {
	ctx := context.Background()
	mockParser, _ := parser.NewBuilder(ctx).
		Add(&jsonParser.Parser{}).
		Add(&yamlParser.Parser{}).
		Add(terraformParser.NewDefault()).
		Build([]string{""}, []string{""})

	mockFilesSource, _ := provider.NewFileSystemSourceProvider(ctx, []string{path}, []string{}, []string{})

	mockResolver, _ := resolver.NewBuilder().Build(ctx)

	return mockParser, mockFilesSource, mockResolver
}

// recordingStorage keeps what the scan saved, so a test can read the
// findings back the way storage would.
type recordingStorage struct {
	saved []model.Vulnerability
}

func (s *recordingStorage) SaveFile(_ context.Context, _ *model.FileMetadata) error {
	return nil
}

func (s *recordingStorage) SaveVulnerabilities(_ context.Context, vulnerabilities []model.Vulnerability) error {
	s.saved = append(s.saved, vulnerabilities...)
	return nil
}

func (s *recordingStorage) GetVulnerabilities(_ context.Context, _ string) ([]model.Vulnerability, error) {
	return s.saved, nil
}

// A file fetched into a checkout directory orders by where that directory
// came from — the checkout directory itself is per-scan, so two scans of the
// same repository must still list the same findings in the same order. The
// reported file name is never rewritten: reports read that file from disk and
// the served findings echo it back byte for byte.
func TestStartScan_OrdersFindingsByCanonicalPaths(t *testing.T) {
	ctx := context.Background()
	// Map keys and detected paths use the platform's own separators, as the
	// scan produces them on every OS.
	checkout := func(name string) string { return filepath.FromSlash("/checkout/" + name) }
	extractionMap := map[string]model.ExtractedPathObject{
		checkout("first"):  {Path: "github.com/org/first-module", LocalPath: false},
		checkout("second"): {Path: "github.com/org/second-module", LocalPath: false},
	}
	findings := []model.Vulnerability{
		{FileName: checkout("second") + filepath.FromSlash("/main.tf"), QueryID: "q", Line: 4, ResourceName: "second"},
		{FileName: checkout("first") + filepath.FromSlash("/main.tf"), QueryID: "q", Line: 2, ResourceName: "first"},
	}

	service := &Service{PathExtractionMap: extractionMap}
	service.canonicalizeFindingNames(findings)
	for i := range findings {
		require.Equal(t, filepath.FromSlash("github.com/org/"+findings[i].ResourceName+"-module/main.tf"), findings[i].OrderPath)
		require.Equal(t, checkout(findings[i].ResourceName)+filepath.FromSlash("/main.tf"), findings[i].FileName,
			"the reported file name stays the detected path")
	}

	// The same scan whose checkout directories were named differently, as
	// they are on every run, must report the same findings in the same order.
	otherRun := []model.Vulnerability{
		{FileName: checkout("x7f3a") + filepath.FromSlash("/main.tf"), QueryID: "q", Line: 4, ResourceName: "second"},
		{FileName: checkout("91bc0") + filepath.FromSlash("/main.tf"), QueryID: "q", Line: 2, ResourceName: "first"},
	}
	otherExtraction := map[string]model.ExtractedPathObject{
		checkout("x7f3a"): {Path: "github.com/org/second-module", LocalPath: false},
		checkout("91bc0"): {Path: "github.com/org/first-module", LocalPath: false},
	}
	otherService := &Service{PathExtractionMap: otherExtraction}
	otherService.canonicalizeFindingNames(otherRun)

	first := storageOrder(t, findings)
	second := storageOrder(t, otherRun)
	// The reported file names differ between the runs — they carry each
	// scan's own checkout directories — but the order and the ordering paths
	// must not.
	require.Equal(t,
		[]string{first[0].ResourceName, first[1].ResourceName},
		[]string{second[0].ResourceName, second[1].ResourceName})
	require.Equal(t, first[0].OrderPath, second[0].OrderPath)
	require.Equal(t, first[1].OrderPath, second[1].OrderPath)

	// Every reported field the scan publishes is identical across the runs:
	// the summary resolves each detected name to the same canonical report
	// path, so the findings the reports carry — names, lines, fingerprints —
	// match field for field. (The summary's file-path bookkeeping maps the
	// canonical names back to each scan's own detected paths, which are
	// legitimately per-scan; the reports read those files from disk.)
	firstSummary := model.CreateSummary(ctx, model.Counters{}, first, "scan", extractionMap, "", model.SCIInfo{})
	secondSummary := model.CreateSummary(ctx, model.Counters{}, second, "scan", otherExtraction, "", model.SCIInfo{})
	require.Equal(t, firstSummary.Queries, secondSummary.Queries)
	// The file-path bookkeeping keys on the canonical report path, identical
	// across the runs; the values are each scan's own detected paths.
	require.Equal(t,
		[]string{
			filepath.FromSlash("github.com/org/first-module/main.tf"),
			filepath.FromSlash("github.com/org/second-module/main.tf"),
		},
		[]string{first[0].OrderPath, first[1].OrderPath})
	require.Contains(t, firstSummary.FilePaths, filepath.FromSlash("github.com/org/first-module/main.tf"))
	require.Contains(t, firstSummary.FilePaths, filepath.FromSlash("github.com/org/second-module/main.tf"))
	require.Contains(t, secondSummary.FilePaths, filepath.FromSlash("github.com/org/first-module/main.tf"))
	require.Contains(t, secondSummary.FilePaths, filepath.FromSlash("github.com/org/second-module/main.tf"))
}

// A finding outside every checkout directory orders by its detected name,
// which round-trips byte for byte: no separator is ever rewritten.
func TestStartScan_KeepsUnmappedFindingNamesByteForByte(t *testing.T) {
	service := &Service{PathExtractionMap: map[string]model.ExtractedPathObject{
		"/somewhere/else": {Path: "github.com/org/other", LocalPath: false},
	}}
	findings := []model.Vulnerability{{FileName: "modules/x/main.tf", QueryID: "q", Line: 1}}
	service.canonicalizeFindingNames(findings)
	require.Empty(t, findings[0].OrderPath)
	require.Equal(t, "modules/x/main.tf", findings[0].FileName)

	// Without a map at all — the served content-push scan — nothing changes.
	bare := &Service{}
	pushed := []model.Vulnerability{{FileName: "src/a/b/c.yaml", QueryID: "q", Line: 1}}
	bare.canonicalizeFindingNames(pushed)
	require.Empty(t, pushed[0].OrderPath)
	require.Equal(t, "src/a/b/c.yaml", pushed[0].FileName)
}

// storageOrder stores the findings and returns what storage reports for
// them, so the test compares what storage itself makes of each run.
func storageOrder(t *testing.T, findings []model.Vulnerability) []model.Vulnerability {
	t.Helper()
	mem := storage.NewMemoryStorage()
	require.NoError(t, mem.SaveVulnerabilities(context.Background(), findings))
	saved, err := mem.GetVulnerabilities(context.Background(), "")
	require.NoError(t, err)
	return saved
}
