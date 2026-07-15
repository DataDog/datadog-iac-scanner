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
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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

func TestFileSystemSourceProvider_GetSourcesClosesSingleFile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "main.tf")
	require.NoError(t, os.WriteFile(path, []byte("resource \"test\" \"main\" {}"), 0o600))
	source, err := NewFileSystemSourceProvider(ctx, []string{path}, nil, nil)
	require.NoError(t, err)

	var openedFile *os.File
	err = source.GetSources(ctx, model.Extensions{".tf": {}},
		func(_ context.Context, _ string, content io.ReadCloser) error {
			openedFile = content.(*os.File)
			return nil
		},
		func(context.Context, string) ([]string, error) {
			return nil, nil
		},
	)
	require.NoError(t, err)
	require.NotNil(t, openedFile)
	require.Error(t, openedFile.Close())
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

func TestIsUnderResolvedChart(t *testing.T) {
	tests := []struct {
		name               string
		path               string
		resolvedChartPaths []string
		want               bool
	}{
		{
			name:               "empty resolved list",
			path:               filepath.FromSlash("k8s/chart-a/templates"),
			resolvedChartPaths: nil,
			want:               false,
		},
		{
			name:               "subdirectory of resolved chart is skipped",
			path:               filepath.FromSlash("k8s/chart-a/templates"),
			resolvedChartPaths: []string{filepath.FromSlash("k8s/chart-a")},
			want:               true,
		},
		{
			name:               "sibling chart is not skipped",
			path:               filepath.FromSlash("k8s/chart-b"),
			resolvedChartPaths: []string{filepath.FromSlash("k8s/chart-a")},
			want:               false,
		},
		{
			name:               "chart root itself is not considered under itself",
			path:               filepath.FromSlash("k8s/chart-a"),
			resolvedChartPaths: []string{filepath.FromSlash("k8s/chart-a")},
			want:               false,
		},
		{
			name:               "path sharing a prefix but different directory is not skipped",
			path:               filepath.FromSlash("k8s/chart"),
			resolvedChartPaths: []string{filepath.FromSlash("k8s/chart-a")},
			want:               false,
		},
		{
			name: "subdirectory matched against multiple resolved charts",
			path: filepath.FromSlash("k8s/chart-b/templates"),
			resolvedChartPaths: []string{
				filepath.FromSlash("k8s/chart-a"),
				filepath.FromSlash("k8s/chart-b"),
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUnderResolvedChart(tt.path, tt.resolvedChartPaths)
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

// TestGetSources_helmChartSkipsRawTemplates ensures that once a Helm chart is
// rendered by the resolver, its raw template files are not also scanned as plain YAML.
func TestGetSources_helmChartSkipsRawTemplates(t *testing.T) {
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Fatalf("failed to change dir: %s", err)
	}

	ctx := context.Background()
	const chartDir = "test/fixtures/test_helm"

	var mu sync.Mutex
	var sinkedFiles, resolvedDirs []string

	recordingSink := func(_ context.Context, filename string, _ io.ReadCloser) error {
		mu.Lock()
		sinkedFiles = append(sinkedFiles, filepath.ToSlash(filename))
		mu.Unlock()
		return nil
	}
	recordingResolverSink := func(_ context.Context, filename string) ([]string, error) {
		if _, chartErr := os.Stat(filepath.Join(filename, "Chart.yaml")); chartErr == nil {
			mu.Lock()
			resolvedDirs = append(resolvedDirs, filepath.ToSlash(filename))
			mu.Unlock()
		}
		return []string{}, nil
	}

	run := func(t *testing.T, scan func(*FileSystemSourceProvider) error) {
		t.Helper()
		mu.Lock()
		sinkedFiles, resolvedDirs = nil, nil
		mu.Unlock()

		fs, err := NewFileSystemSourceProvider(ctx, []string{filepath.FromSlash(chartDir)}, []string{}, []string{})
		require.NoError(t, err)
		require.NoError(t, scan(fs))

		require.Contains(t, resolvedDirs, chartDir, "the Helm chart directory must be sent to the resolver")
		for _, f := range sinkedFiles {
			require.NotContains(t, f, chartDir+"/",
				"raw files under a resolved Helm chart must not be scanned as plain YAML, got %q", f)
		}
	}

	t.Run("sequential", func(t *testing.T) {
		run(t, func(fs *FileSystemSourceProvider) error {
			return fs.GetSources(ctx, model.Extensions{".yaml": {}}, recordingSink, recordingResolverSink)
		})
	})
	t.Run("parallel", func(t *testing.T) {
		run(t, func(fs *FileSystemSourceProvider) error {
			return fs.GetParallelSources(ctx, model.Extensions{".yaml": {}}, recordingSink, recordingResolverSink)
		})
	})
}
