/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package kics

import (
	"context"
	"fmt"
	"os"
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
	kustomizeResolver "github.com/DataDog/datadog-iac-scanner/pkg/resolver/kustomize"
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
		resolverDiagnostics := NewResolverDiagnosticsState()
		for _, parser := range tt.fields.Parser {
			s = append(s, &Service{
				SourceProvider: tt.fields.SourceProvider,
				Storage:        tt.fields.Storage,
				Parser:         parser,
				Inspector:      tt.fields.Inspector,
				Tracker:        tt.fields.Tracker,
				Resolver:       tt.fields.Resolver,
				ResolverDiagnostics: resolverDiagnostics,
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

func TestSaveResolverDiagnostics_DedupesAcrossServicesInSameScan(t *testing.T) {
	store := storage.NewMemoryStorage()
	state := NewResolverDiagnosticsState()
	scanID := "scanID"
	diag := model.ResolverDiagnostic{
		FilePath: "/tmp/overlay/kustomization.yaml",
		Message:  "render failed",
		QueryID:  "kustomize-render-failed",
		Line:     0,
	}

	serviceA := &Service{
		Storage:             store,
		ResolverDiagnostics: state,
	}
	serviceB := &Service{
		Storage:             store,
		ResolverDiagnostics: state,
	}

	require.NoError(t, serviceA.saveResolverDiagnostics(context.Background(), scanID, []model.ResolverDiagnostic{diag}))
	require.NoError(t, serviceB.saveResolverDiagnostics(context.Background(), scanID, []model.ResolverDiagnostic{diag}))

	vulns, err := store.GetVulnerabilities(context.Background(), scanID)
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	require.Equal(t, "", vulns[0].Platform)
	require.Equal(t, 1, vulns[0].Line)
}

// Regression: a single unparseable rendered doc (e.g. Kustomize generator
// output with a virtual filename) must not drop resFiles.Excluded; otherwise
// the walker re-scans patches / base files as raw YAML and produces duplicate
// or partial-document findings.
func TestResolverSink_PropagatesExcludedOnParseFailure(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- pod.yaml
configMapGenerator:
- name: app-config
  literals:
    - KEY=value
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "pod.yaml"), []byte(`apiVersion: v1
kind: Pod
metadata:
  name: demo
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.21
      envFrom:
        - configMapRef:
            name: app-config
`), 0o600))

	resolverWithKustomize, err := resolver.NewBuilder().
		Add(ctx, kustomizeResolver.NewResolver(kustomizeResolver.Options{RepoRoot: root})).
		Build(ctx)
	require.NoError(t, err)

	kicsParser, err := parser.NewBuilder(ctx).
		Add(&yamlParser.Parser{}).
		Build([]string{"Kubernetes"}, []string{""})
	require.NoError(t, err)

	tr, err := tracker.NewTracker(1)
	require.NoError(t, err)

	service := &Service{
		Storage:             storage.NewMemoryStorage(),
		ResolverDiagnostics: NewResolverDiagnosticsState(),
		Parser:              kicsParser[0],
		Resolver:            resolverWithKustomize,
		Tracker:             tr,
	}

	excluded, err := service.resolverSink(ctx, root, "scanID", false, 0)
	require.NoError(t, err)

	// Generator emits a virtual generated-ConfigMap-*.yaml (no file on disk)
	// which fails Parser.Parse; excludes must still surface the real sources.
	require.Contains(t, excluded, filepath.Join(root, "kustomization.yaml"))
	require.Contains(t, excluded, filepath.Join(root, "pod.yaml"))
}

func TestSaveResolverDiagnostics_UsesServicePlatform(t *testing.T) {
	store := storage.NewMemoryStorage()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
`), 0o600))
	resolverWithKustomize, err := resolver.NewBuilder().
		Add(context.Background(), kustomizeResolver.NewResolver(kustomizeResolver.Options{RepoRoot: root})).
		Build(context.Background())
	require.NoError(t, err)
	service := &Service{
		Storage:             store,
		ResolverDiagnostics: NewResolverDiagnosticsState(),
		Parser:              &parser.Parser{Platform: []string{"Knative", "Kubernetes"}},
		Resolver:            resolverWithKustomize,
	}

	require.NoError(t, service.saveResolverDiagnostics(context.Background(), "scanID", []model.ResolverDiagnostic{{
		FilePath: filepath.Join(root, "kustomization.yaml"),
		Message:  "render failed",
		QueryID:  "kustomize-render-failed",
	}}))

	vulns, err := store.GetVulnerabilities(context.Background(), "scanID")
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	require.Equal(t, "Kubernetes", vulns[0].Platform)
}
