/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"context"
	"fmt"
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

func TestConsolidateTerraformFilesMovesPlansOntoHCLService(t *testing.T) {
	tf := &Service{Parser: &parser.Parser{Parsers: terraformParser.NewDefault()}}
	jsonSvc := &Service{Parser: &parser.Parser{Parsers: &jsonParser.Parser{}}}
	tf.appendFiles(model.FileMetadatas{
		{ID: "hcl", Kind: model.KindTerraform, FilePath: "envs/a/main.tf"},
	})
	jsonSvc.appendFiles(model.FileMetadatas{
		{ID: "plan", Kind: model.KindTerraformPlan, FilePath: "envs/a/tfplan.json"},
		{ID: "cfn", Kind: model.KindJSON, FilePath: "template.json"},
	})

	ConsolidateTerraformFiles([]*Service{tf, jsonSvc})

	require.Equal(t, 2, tf.FileCount(), "plan joins the HCL service for one Inspect")
	require.Equal(t, 1, jsonSvc.FileCount(), "non-plan JSON stays on the JSON service")
	ids := map[string]bool{}
	for _, f := range tf.files {
		ids[f.ID] = true
	}
	require.True(t, ids["hcl"] && ids["plan"])
	require.Equal(t, "cfn", jsonSvc.files[0].ID)
}

func TestConsolidateTerraformFilesNoopWithoutTerraformService(t *testing.T) {
	jsonSvc := &Service{Parser: &parser.Parser{Parsers: &jsonParser.Parser{}}}
	jsonSvc.appendFiles(model.FileMetadatas{
		{ID: "plan", Kind: model.KindTerraformPlan, FilePath: "tfplan.json"},
	})
	ConsolidateTerraformFiles([]*Service{jsonSvc})
	require.Equal(t, 1, jsonSvc.FileCount(), "plans stay put when there is no HCL service")
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
