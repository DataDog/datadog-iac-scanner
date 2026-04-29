/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package provider

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/kustomize"
	"github.com/DataDog/datadog-iac-scanner/test"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

// TestNewFileSystemSourceProvider tests the functions [NewFileSystemSourceProvider()] and all the methods called by them
func TestNewFileSystemSourceProvider(t *testing.T) {
	type args struct {
		paths    []string
		excludes []string
	}
	tests := []struct {
		name    string
		args    args
		want    *FileSystemSourceProvider
		wantErr bool
	}{
		{
			name: "new_filesystem_source_provider",
			args: args{
				paths: []string{"./test"},
				excludes: []string{
					".tf",
				},
			},
			want: &FileSystemSourceProvider{
				paths:    []string{filepath.FromSlash("./test")},
				excludes: make(map[string][]os.FileInfo, 1),
			},
			wantErr: false,
		},
		{
			name: "new_filesystem_source_provider",
			args: args{
				paths: []string{"./test", "./test2"},
				excludes: []string{
					".tf",
				},
			},
			want: &FileSystemSourceProvider{
				paths:    []string{filepath.FromSlash("./test"), filepath.FromSlash("./test2")},
				excludes: make(map[string][]os.FileInfo, 1),
			},
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewFileSystemSourceProvider(ctx, tt.args.paths, tt.args.excludes, []string{})
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFileSystemSourceProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewFileSystemSourceProvider() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFileSystemSourceProvider_GetSources tests the functions [GetSources()] and all the methods called by them
func TestFileSystemSourceProvider_GetSources(t *testing.T) { //nolint
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Fatal(err)
	}
	type fields struct {
		paths    []string
		excludes map[string][]os.FileInfo
	}
	type args struct {
		queryName    string
		extensions   model.Extensions
		sink         Sink
		resolverSink ResolverSink
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "new_filesystem_source_provider_error",
			fields: fields{
				paths:    []string{"./no-path"},
				excludes: map[string][]os.FileInfo{},
			},
			args: args{
				queryName:    "alb_protocol_is_http",
				extensions:   nil,
				sink:         mockSink,
				resolverSink: mockResolverSink,
			},
			wantErr: true,
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &FileSystemSourceProvider{
				paths:    tt.fields.paths,
				excludes: tt.fields.excludes,
			}
			if err := s.GetSources(ctx, tt.args.extensions, tt.args.sink, tt.args.resolverSink); (err != nil) != tt.wantErr {
				t.Errorf("FileSystemSourceProvider.GetSources() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err := s.GetParallelSources(ctx, tt.args.extensions, tt.args.sink, tt.args.resolverSink); (err != nil) != tt.wantErr {
				t.Errorf("FileSystemSourceProvider.GetSources() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFileSystemSourceProvider_GetBasePath(t *testing.T) {
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Errorf("failed to change dir: %s", err)
	}
	fsystem, err := initFs([]string{filepath.FromSlash("test")}, []string{})
	if err != nil {
		t.Errorf("failed to initialize a new File System Source Provider")
	}
	fsystem2, err := initFs([]string{filepath.FromSlash("test"), filepath.FromSlash("test2")}, []string{})
	if err != nil {
		t.Errorf("failed to initialize a new File System Source Provider")
	}
	type fields struct {
		fs *FileSystemSourceProvider
	}
	tests := []struct {
		name   string
		fields fields
		want   []string
	}{
		{
			name: "test_get_base_path",
			fields: fields{
				fs: fsystem,
			},
			want: []string{"test"},
		},
		{
			name: "test_get_base_path_multiples",
			fields: fields{
				fs: fsystem2,
			},
			want: []string{"test", "test2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fields.fs.GetBasePaths()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetBasePath() = %v, want = %v", got, tt.want)
			}
		})
	}
}

// TestFileSystemSourceProvider_checkConditions tests the functions [checkConditions()] and all the methods called by them
func TestFileSystemSourceProvider_checkConditions(t *testing.T) {
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Errorf("failed to change dir: %s", err)
	}
	infoHelm, errHelm := os.Stat(filepath.FromSlash("test/fixtures/test_helm"))
	checkStatErr(t, errHelm)
	infoHelmTerra, errHelmTerra := os.Stat(filepath.FromSlash("test/fixtures/terra/test_helm"))
	checkStatErr(t, errHelmTerra)
	infoTerraCache, errTerraCache := os.Stat(filepath.FromSlash("test/fixtures/test_terra_cache"))
	checkStatErr(t, errTerraCache)

	type fields struct {
		paths    []string
		excludes map[string][]os.FileInfo
	}
	type args struct {
		info       os.FileInfo
		extensions model.Extensions
		path       string
	}
	type want struct {
		got bool
		err error
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   want
	}{
		{
			name: "check_conditions_chart",
			fields: fields{
				paths:    []string{filepath.FromSlash("test/fixtures/test_helm")},
				excludes: nil,
			},
			args: args{
				info:       infoHelm,
				extensions: model.Extensions{},
				path:       filepath.FromSlash("test/fixtures/test_helm"),
			},
			want: want{
				got: false,
				err: nil,
			},
		},
		{
			name: "check_conditions_chart, with terra on path not skip",
			fields: fields{
				paths:    []string{filepath.FromSlash("test/fixtures/terra/test_helm")},
				excludes: nil,
			},
			args: args{
				info:       infoHelmTerra,
				extensions: model.Extensions{},
				path:       filepath.FromSlash("test/fixtures/terra/test_helm"),
			},
			want: want{
				got: false,
				err: nil,
			},
		},
		{
			name: "check_condition_ignore_terra_cache for .terra",
			fields: fields{
				paths:    []string{filepath.FromSlash(".terra")},
				excludes: nil,
			},
			args: args{
				info:       infoTerraCache,
				extensions: model.Extensions{},
				path:       filepath.FromSlash(".terra"),
			},
			want: want{
				got: true,
				err: filepath.SkipDir,
			},
		},
		{
			name: "check_condition_ignore_terragrunt_cache for .terragrunt-cache",
			fields: fields{
				paths:    []string{filepath.FromSlash(".terragrunt-cache")},
				excludes: nil,
			},
			args: args{
				info:       infoTerraCache,
				extensions: model.Extensions{},
				path:       filepath.FromSlash(".terragrunt-cache"),
			},
			want: want{
				got: true,
				err: filepath.SkipDir,
			},
		},
		{
			name: "check_condition_ignore_terra_cache for terra, exclude by missing chart.yaml",
			fields: fields{
				paths:    []string{filepath.FromSlash("terra")},
				excludes: nil,
			},
			args: args{
				info:       infoTerraCache,
				extensions: model.Extensions{},
				path:       filepath.FromSlash("terra"),
			},
			want: want{
				got: true,
				err: nil,
			},
		},
		{
			name: "check_condition_ignore_terra_cache for .terraform",
			fields: fields{
				paths:    []string{filepath.FromSlash(".terraform")},
				excludes: nil,
			},
			args: args{
				info:       infoTerraCache,
				extensions: model.Extensions{},
				path:       filepath.FromSlash(".terraform"),
			},
			want: want{
				got: true,
				err: filepath.SkipDir,
			},
		},
		{
			name: "check_condition_ignore_terra_cache for .terraform, exclude by missing chart.yaml",
			fields: fields{
				paths:    []string{filepath.FromSlash("terraform")},
				excludes: nil,
			},
			args: args{
				info:       infoTerraCache,
				extensions: model.Extensions{},
				path:       filepath.FromSlash("terraform"),
			},
			want: want{
				got: true,
				err: nil,
			},
		},
		{
			name: "check_condition_ignore_terra_cache for .terra/lalala",
			fields: fields{
				paths:    []string{filepath.FromSlash(".terra/lalala")},
				excludes: nil,
			},
			args: args{
				info:       infoTerraCache,
				extensions: model.Extensions{},
				path:       filepath.FromSlash(".terra/lalala"),
			},
			want: want{
				got: true,
				err: filepath.SkipDir,
			},
		},
		{
			name: "check_condition_ignore_terragrunt_cache for .terragrunt-cache/lalala",
			fields: fields{
				paths:    []string{filepath.FromSlash(".terragrunt-cache/lalala")},
				excludes: nil,
			},
			args: args{
				info:       infoTerraCache,
				extensions: model.Extensions{},
				path:       filepath.FromSlash(".terragrunt-cache/lalala"),
			},
			want: want{
				got: true,
				err: filepath.SkipDir,
			},
		},
		{
			name: "check_condition_ignore_terra_cache for .terraform/lalala",
			fields: fields{
				paths:    []string{filepath.FromSlash(".terraform/lalala")},
				excludes: nil,
			},
			args: args{
				info:       infoTerraCache,
				extensions: model.Extensions{},
				path:       filepath.FromSlash(".terraform/lalala"),
			},
			want: want{
				got: true,
				err: filepath.SkipDir,
			},
		},
		{
			name: "check_condition_ignore_terra_cache for /.terra",
			fields: fields{
				paths:    []string{filepath.FromSlash("/.terra")},
				excludes: nil,
			},
			args: args{
				info:       infoTerraCache,
				extensions: model.Extensions{},
				path:       filepath.FromSlash("/.terra"),
			},
			want: want{
				got: true,
				err: filepath.SkipDir,
			},
		},
		{
			name: "check_condition_ignore_terra_cache for /.terraform",
			fields: fields{
				paths:    []string{filepath.FromSlash("/.terraform")},
				excludes: nil,
			},
			args: args{
				info:       infoTerraCache,
				extensions: model.Extensions{},
				path:       filepath.FromSlash("/.terraform"),
			},
			want: want{
				got: true,
				err: filepath.SkipDir,
			},
		},
		{
			name: "check_condition_ignore_terragrunt_cache for /.terragrunt-cache",
			fields: fields{
				paths:    []string{filepath.FromSlash("/.terragrunt-cache")},
				excludes: nil,
			},
			args: args{
				info:       infoTerraCache,
				extensions: model.Extensions{},
				path:       filepath.FromSlash("/.terragrunt-cache"),
			},
			want: want{
				got: true,
				err: filepath.SkipDir,
			},
		},
		{
			name: "check_condition_ignore_terra_cache for /.terra/lalala",
			fields: fields{
				paths:    []string{filepath.FromSlash("/.terra/lalala")},
				excludes: nil,
			},
			args: args{
				info:       infoTerraCache,
				extensions: model.Extensions{},
				path:       filepath.FromSlash("/.terra/lalala"),
			},
			want: want{
				got: true,
				err: filepath.SkipDir,
			},
		},
		{
			name: "check_condition_ignore_terragrunt_cache for /.terragrunt-cache/lalala",
			fields: fields{
				paths:    []string{filepath.FromSlash("/.terragrunt-cache/lalala")},
				excludes: nil,
			},
			args: args{
				info:       infoTerraCache,
				extensions: model.Extensions{},
				path:       filepath.FromSlash("/.terragrunt-cache/lalala"),
			},
			want: want{
				got: true,
				err: filepath.SkipDir,
			},
		},
		{
			name: "check_condition_ignore_terra_cache for /.terraform/lalala",
			fields: fields{
				paths:    []string{filepath.FromSlash("/.terraform/lalala")},
				excludes: nil,
			},
			args: args{
				info:       infoTerraCache,
				extensions: model.Extensions{},
				path:       filepath.FromSlash("/.terraform/lalala"),
			},
			want: want{
				got: true,
				err: filepath.SkipDir,
			},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &FileSystemSourceProvider{
				paths:    tt.fields.paths,
				excludes: tt.fields.excludes,
			}
			if got, err := s.checkConditions(ctx, tt.args.info, tt.args.extensions, tt.args.path, nil); got != tt.want.got || err != tt.want.err {
				t.Errorf("FileSystemSourceProvider.checkConditions() = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestFileSystemSourceProvider_AddExcluded tests the functions [AddExcluded()] and all the methods called by them
func TestFileSystemSourceProvider_AddExcluded(t *testing.T) {
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Errorf("failed to change dir: %s", err)
	}
	fsystem, err := initFs([]string{filepath.FromSlash("test")}, []string{})
	if err != nil {
		t.Errorf("failed to initialize a new File System Source Provider")
	}
	type fields struct {
		fs *FileSystemSourceProvider
	}
	type args struct {
		excludePaths []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "test_too_many_levels_of_symbolic_links",
			fields: fields{
				fs: fsystem,
			},
			args: args{
				excludePaths: []string{
					"test/fixtures/link_test/eloop_link",
				},
			},
			want:    []string{},
			wantErr: false,
		},
		{
			name: "test_add_excluded",
			fields: fields{
				fs: fsystem,
			},
			args: args{
				excludePaths: []string{
					"test/fixtures/config_test",
				},
			},
			want: []string{
				"config_test",
			},
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fields.fs.addExcluded(ctx, tt.args.excludePaths)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddExcluded() = %v, wantErr = %v", err, tt.wantErr)
			}
			got := getFSExcludes(tt.fields.fs)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AddExcluded() = %v, want = %v", got, tt.want)
			}
		})
	}
}

var mockSink = func(ctx context.Context, filename string, content io.ReadCloser) error {
	return nil
}

var mockErrSink = func(ctx context.Context, filename string, content io.ReadCloser) error {
	return errors.New("")
}

var mockResolverSink = func(ctx context.Context, filename string) ([]string, error) {
	return []string{}, nil
}

var mockErrResolverSink = func(ctx context.Context, filename string) ([]string, error) {
	return []string{}, errors.New("")
}

func checkStatErr(t *testing.T, err error) {
	if err != nil {
		t.Errorf("failed to get info: %s", err)
	}
}

// initFs creates a new instance of File System Source Provider
func initFs(paths, excluded []string) (*FileSystemSourceProvider, error) {
	ctx := context.Background()
	return NewFileSystemSourceProvider(ctx, paths, excluded, []string{})
}

func getFSExcludes(fsystem *FileSystemSourceProvider) []string {
	excluded := make([]string, 0)
	for key := range fsystem.excludes {
		excluded = append(excluded, key)
	}
	return excluded
}

func TestProvider_getExcludePaths(t *testing.T) {
	type args struct {
		pathExpressions string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "test_getExcludedPaths",
			args: args{
				pathExpressions: "*.sh",
			},
			want:    []string(nil),
			wantErr: false,
		},
		{
			name: "test_getExcludedPaths with double start",
			args: args{
				pathExpressions: filepath.Join("test", "fixtures", "analyzer_test", "**", "*.json"),
			},
			want: []string{
				filepath.Join("test", "fixtures", "analyzer_test", "azureResourceManager.json"),
				filepath.Join("test", "fixtures", "analyzer_test", "not_openapi.json"),
				filepath.Join("test", "fixtures", "analyzer_test", "openAPI.json"),
				filepath.Join("test", "fixtures", "analyzer_test", "openAPI_test", "openAPI.json"),
			},
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetExcludePaths(ctx, tt.args.pathExpressions)
			if (err != nil) != tt.wantErr {
				t.Errorf("getExcludePaths Error: %v, wantErr: %v", got, tt.wantErr)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIsUnderResolvedRoot(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		resolvedRoots []string
		want         bool
	}{
		{
			name:               "empty resolved list",
			path:               filepath.FromSlash("k8s/chart-a/templates"),
			resolvedRoots: nil,
			want:               false,
		},
		{
			name:               "subdirectory of resolved chart is skipped",
			path:               filepath.FromSlash("k8s/chart-a/templates"),
			resolvedRoots: []string{filepath.FromSlash("k8s/chart-a")},
			want:               true,
		},
		{
			name:               "sibling chart is not skipped",
			path:               filepath.FromSlash("k8s/chart-b"),
			resolvedRoots: []string{filepath.FromSlash("k8s/chart-a")},
			want:               false,
		},
		{
			name:               "chart root itself is not considered under itself",
			path:               filepath.FromSlash("k8s/chart-a"),
			resolvedRoots: []string{filepath.FromSlash("k8s/chart-a")},
			want:               false,
		},
		{
			name:               "path sharing a prefix but different directory is not skipped",
			path:               filepath.FromSlash("k8s/chart"),
			resolvedRoots: []string{filepath.FromSlash("k8s/chart-a")},
			want:               false,
		},
		{
			name: "subdirectory matched against multiple resolved charts",
			path: filepath.FromSlash("k8s/chart-b/templates"),
			resolvedRoots: []string{
				filepath.FromSlash("k8s/chart-a"),
				filepath.FromSlash("k8s/chart-b"),
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUnderResolvedRoot(tt.path, tt.resolvedRoots)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestGetSources_multipleHelmCharts(t *testing.T) {
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Fatalf("failed to change dir: %s", err)
	}

	ctx := context.Background()
	fs, err := NewFileSystemSourceProvider(ctx,
		[]string{filepath.FromSlash("test/fixtures/multi_helm")}, []string{}, []string{})
	require.NoError(t, err)

	resolvedDirs := make([]string, 0)
	countingResolverSink := func(_ context.Context, filename string) ([]string, error) {
		info, statErr := os.Stat(filename)
		if statErr == nil && info.IsDir() {
			if _, chartErr := os.Stat(filepath.Join(filename, "Chart.yaml")); chartErr == nil {
				resolvedDirs = append(resolvedDirs, filepath.Base(filename))
			}
		}
		return []string{}, nil
	}

	err = fs.GetSources(ctx, model.Extensions{".yaml": {}},
		mockSink, countingResolverSink)
	require.NoError(t, err)

	require.ElementsMatch(t, []string{"chart-a", "chart-b"}, resolvedDirs,
		"both sibling Helm charts must be sent to the resolver, not just the first one")
}

func TestGetSources_parentHelmChartSkipsRecursiveSubchartResolverWalks(t *testing.T) {
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Fatalf("failed to change dir: %s", err)
	}

	ctx := context.Background()
	root := filepath.FromSlash("test/fixtures/test_helm_subchart")
	fs, err := NewFileSystemSourceProvider(ctx, []string{root}, []string{}, []string{})
	require.NoError(t, err)

	var resolvedDirs []string
	countingResolverSink := func(_ context.Context, filename string) ([]string, error) {
		info, statErr := os.Stat(filename)
		if statErr == nil && info.IsDir() {
			if _, chartErr := os.Stat(filepath.Join(filename, "Chart.yaml")); chartErr == nil {
				resolvedDirs = append(resolvedDirs, filepath.Clean(filename))
				if filepath.Clean(filename) == filepath.Clean(root) {
					return []string{
						filepath.FromSlash("test/fixtures/test_helm_subchart/templates/serviceaccount.yaml"),
						filepath.FromSlash("test/fixtures/test_helm_subchart/charts/subchart/templates/service.yaml"),
					}, nil
				}
			}
		}
		return []string{}, nil
	}

	err = fs.GetSources(ctx, model.Extensions{".yaml": {}}, mockSink, countingResolverSink)
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Clean(root)}, resolvedDirs)
}

func TestGetSources_multipleKustomizationRoots(t *testing.T) {
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Fatalf("failed to change dir: %s", err)
	}

	ctx := context.Background()
	fs, err := NewFileSystemSourceProvider(ctx,
		[]string{filepath.FromSlash("test/fixtures/multi_kustomize")}, []string{}, []string{})
	require.NoError(t, err)

	resolvedDirs := make([]string, 0)
	countingResolverSink := func(_ context.Context, filename string) ([]string, error) {
		info, statErr := os.Stat(filename)
		if statErr == nil && info.IsDir() {
			if _, ok := kustomize.Detect(filename); ok {
				resolvedDirs = append(resolvedDirs, filepath.Base(filename))
			}
		}
		return []string{}, nil
	}

	err = fs.GetSources(ctx, model.Extensions{".yaml": {}},
		mockSink, countingResolverSink)
	require.NoError(t, err)

	require.ElementsMatch(t, []string{"k8s-a", "k8s-b"}, resolvedDirs,
		"both sibling kustomization roots must be sent to the resolver")
}

func TestGetSources_nestedIndependentKustomizationRoots(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	require.NoError(t, os.MkdirAll(nested, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(nested, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
`), 0o600))

	fs, err := NewFileSystemSourceProvider(ctx, []string{root}, []string{}, []string{})
	require.NoError(t, err)

	var resolvedDirs []string
	countingResolverSink := func(_ context.Context, filename string) ([]string, error) {
		info, statErr := os.Stat(filename)
		if statErr == nil && info.IsDir() {
			if _, ok := kustomize.Detect(filename); ok {
				resolvedDirs = append(resolvedDirs, filename)
				if filename == root {
					return []string{filepath.Join(root, "kustomization.yaml")}, nil
				}
			}
		}
		return []string{}, nil
	}

	err = fs.GetSources(ctx, model.Extensions{".yaml": {}}, mockSink, countingResolverSink)
	require.NoError(t, err)
	require.Contains(t, resolvedDirs, root)
	require.Contains(t, resolvedDirs, nested)
}

func TestGetSources_kustomizeDirsNotSkippedWhenResolverReturnsNoExclusions(t *testing.T) {
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Fatalf("failed to change dir: %s", err)
	}

	ctx := context.Background()
	fs, err := NewFileSystemSourceProvider(ctx,
		[]string{filepath.FromSlash("test/fixtures/multi_kustomize")}, []string{}, []string{})
	require.NoError(t, err)

	var seenYAML []string
	err = fs.GetSources(ctx, model.Extensions{".yaml": {}},
		func(_ context.Context, filename string, _ io.ReadCloser) error {
			seenYAML = append(seenYAML, filepath.Base(filename))
			return nil
		},
		func(_ context.Context, _ string) ([]string, error) {
			return []string{}, nil
		})
	require.NoError(t, err)
	require.Contains(t, seenYAML, "kustomization.yaml")
	require.Contains(t, seenYAML, "cm.yaml")
}

func TestGetSources_kustomizeDirsSkippedWhenResolverReturnsDiagnosticsAndExclusions(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- cm.yaml
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n"), 0o600))

	fs, err := NewFileSystemSourceProvider(ctx, []string{root}, []string{}, []string{})
	require.NoError(t, err)

	var seenYAML []string
	err = fs.GetSources(ctx, model.Extensions{".yaml": {}},
		func(_ context.Context, filename string, _ io.ReadCloser) error {
			seenYAML = append(seenYAML, filepath.Base(filename))
			return nil
		},
		func(_ context.Context, filename string) ([]string, error) {
			if filepath.Clean(filename) == filepath.Clean(root) {
				return []string{filepath.Join(root, "kustomization.yaml"), filepath.Join(root, "cm.yaml")}, nil
			}
			return []string{}, nil
		})
	require.NoError(t, err)
	require.NotContains(t, seenYAML, "kustomization.yaml")
	require.NotContains(t, seenYAML, "cm.yaml")
}

func TestGetSources_explicitKustomizationFileUsesResolverRoot(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	kust := filepath.Join(root, "kustomization.yaml")
	require.NoError(t, os.WriteFile(kust, []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- cm.yaml
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n"), 0o600))

	fs, err := NewFileSystemSourceProvider(ctx, []string{kust}, []string{}, []string{})
	require.NoError(t, err)

	var resolverRoots []string
	var seenYAML []string
	err = fs.GetSources(ctx, model.Extensions{".yaml": {}},
		func(_ context.Context, filename string, _ io.ReadCloser) error {
			seenYAML = append(seenYAML, filepath.Base(filename))
			return nil
		},
		func(_ context.Context, filename string) ([]string, error) {
			resolverRoots = append(resolverRoots, filepath.Clean(filename))
			return []string{kust, filepath.Join(root, "cm.yaml")}, nil
		})
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Clean(root)}, resolverRoots)
	require.Empty(t, seenYAML)
}

func TestGetSources_explicitKustomizationFileWithDiagnosticsOnlyStillSkipsRawParse(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	kust := filepath.Join(root, "kustomization.yaml")
	require.NoError(t, os.WriteFile(kust, []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- https://example.com/remote
`), 0o600))

	fs, err := NewFileSystemSourceProvider(ctx, []string{kust}, []string{}, []string{})
	require.NoError(t, err)

	var resolverRoots []string
	var seenYAML []string
	err = fs.GetSources(ctx, model.Extensions{".yaml": {}},
		func(_ context.Context, filename string, _ io.ReadCloser) error {
			seenYAML = append(seenYAML, filepath.Base(filename))
			return nil
		},
		func(_ context.Context, filename string) ([]string, error) {
			resolverRoots = append(resolverRoots, filepath.Clean(filename))
			return []string{}, nil
		})
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Clean(root)}, resolverRoots)
	require.Empty(t, seenYAML)
}

func TestGetSources_explicitKustomizationFilePropagatesResolverError(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	kust := filepath.Join(root, "kustomization.yaml")
	require.NoError(t, os.WriteFile(kust, []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
`), 0o600))

	fs, err := NewFileSystemSourceProvider(ctx, []string{kust}, []string{}, []string{})
	require.NoError(t, err)

	wantErr := errors.New("resolver failed")
	err = fs.GetSources(ctx, model.Extensions{".yaml": {}}, mockSink, func(_ context.Context, _ string) ([]string, error) {
		return nil, wantErr
	})
	require.ErrorIs(t, err, wantErr)

	err = fs.GetParallelSources(ctx, model.Extensions{".yaml": {}}, mockSink, func(_ context.Context, _ string) ([]string, error) {
		return nil, wantErr
	})
	require.ErrorIs(t, err, wantErr)
}

func TestGetSources_directoryKustomizeRootPropagatesResolverError(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
`), 0o600))

	fs, err := NewFileSystemSourceProvider(ctx, []string{root}, []string{}, []string{})
	require.NoError(t, err)

	wantErr := errors.New("resolver failed")
	err = fs.GetSources(ctx, model.Extensions{".yaml": {}}, mockSink, func(_ context.Context, _ string) ([]string, error) {
		return nil, wantErr
	})
	require.ErrorIs(t, err, wantErr)

	err = fs.GetParallelSources(ctx, model.Extensions{".yaml": {}}, mockSink, func(_ context.Context, _ string) ([]string, error) {
		return nil, wantErr
	})
	require.ErrorIs(t, err, wantErr)
}
