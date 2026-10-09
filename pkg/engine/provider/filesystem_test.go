/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package provider

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
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
			if got, _, err := s.checkConditions(ctx, tt.args.info, tt.args.extensions, tt.args.path, nil); got != tt.want.got || err != tt.want.err {
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
		{
			name: "malformed glob treated as literal path",
			args: args{
				pathExpressions: filepath.Join("terraform", "module[production.tf"),
			},
			want: []string{
				filepath.Join("terraform", "module[production.tf"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetExcludePaths(tt.args.pathExpressions)
			if (err != nil) != tt.wantErr {
				t.Errorf("getExcludePaths Error: %v, wantErr: %v", got, tt.wantErr)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIsNestedRenderedChart(t *testing.T) {
	tests := []struct {
		name          string
		root          string
		renderedRoots []string
		want          bool
	}{
		{name: "nothing rendered", root: "k8s/chart-a/charts/sub", want: false},
		{name: "subchart under charts/", root: "k8s/chart-a/charts/sub", renderedRoots: []string{"k8s/chart-a"}, want: true},
		{name: "deep subchart", root: "chart/charts/a/charts/b", renderedRoots: []string{"chart"}, want: true},
		{name: "sibling chart", root: "k8s/chart-b", renderedRoots: []string{"k8s/chart-a"}, want: false},
		{name: "chart root itself", root: "k8s/chart-a", renderedRoots: []string{"k8s/chart-a"}, want: false},
		{name: "shared name prefix", root: "k8s/chart-ab/charts/x", renderedRoots: []string{"k8s/chart-a"}, want: false},
		{name: "standalone chart under a root chart", root: "deploy/app", renderedRoots: []string{"."}, want: false},
		{name: "subchart of a root chart", root: "charts/sub", renderedRoots: []string{"."}, want: true},
		{name: "native separators", root: filepath.FromSlash("k8s/chart-a/charts/sub"),
			renderedRoots: []string{filepath.FromSlash("k8s/chart-a")}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, IsNestedRenderedChart(tt.root, tt.renderedRoots))
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

func TestIsHelmChartFile_normalizesSeparators(t *testing.T) {
	root := `D:/charts/app`
	require.True(t, IsHelmChartFile(`D:/charts/app/templates/svc.yaml`, []string{root}))
	if runtime.GOOS == "windows" {
		require.True(t, IsHelmChartFile(`D:\charts\app\templates\svc.yaml`, []string{root}))
	}
	require.False(t, IsHelmChartFile(`D:/charts/other/templates/svc.yaml`, []string{root}))
}

func TestIsHelmChartDir(t *testing.T) {
	require.True(t, isHelmChartDir("chart/templates", []string{"chart"}))
	require.True(t, isHelmChartDir("chart/charts/sub/templates", []string{"chart"}))
	require.True(t, isHelmChartDir(filepath.FromSlash("chart/crds"), []string{filepath.FromSlash("chart")}))
	require.True(t, isHelmChartDir("templates", []string{"."}))
	require.False(t, isHelmChartDir("chart", []string{"chart"}))
	require.False(t, isHelmChartDir("chart/infra", []string{"chart"}))
	require.False(t, isHelmChartDir("chartx/templates", []string{"chart"}))
}

func TestIsHelmChartFile(t *testing.T) {
	tests := []struct {
		path string
		root string
		want bool
	}{
		{"chart/Chart.yaml", "chart", true},
		{"chart/Chart.lock", "chart", true},
		{"chart/values.yaml", "chart", true},
		{"chart/values-prod.yml", "chart", true},
		{"chart/values.schema.json", "chart", true},
		{"chart/templates/deployment.yaml", "chart", true},
		{"chart/crds/crd.yaml", "chart", true},
		{"chart/charts/sub/templates/svc.yaml", "chart", true},
		{"chart/main.tf", "chart", false},
		{"chart/ci/test-values.yaml", "chart", false},
		{"chart/templates", "chart", false},
		{"chartx/templates/deployment.yaml", "chart", false},
		{"templates/deployment.yaml", ".", true},
		{"Chart.yaml", ".", true},
		{"infra/main.tf", ".", false},
		{".github/workflows/ci.yml", ".", false},
		{"deploy/app/templates/deployment.yaml", ".", false},
	}
	for _, tt := range tests {
		t.Run(tt.path+"@"+tt.root, func(t *testing.T) {
			require.Equal(t, tt.want, IsHelmChartFile(tt.path, []string{tt.root}))
		})
	}
}

func TestTerraformFilesIncludesTfJSON(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`module "a" {}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf.json"), []byte(`{"module":{}}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "data.json"), []byte(`{}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tofu"), []byte(`module "b" {}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tofu.json"), []byte(`{"module":{}}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "foo.tf"), []byte(`module "c" {}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "foo.tofu.json"), []byte(`{"module":{}}`), 0o600))

	provider, err := NewFileSystemSourceProvider(ctx, []string{dir}, nil, nil)
	require.NoError(t, err)

	files, err := provider.TerraformFiles(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{
		filepath.ToSlash(filepath.Join(dir, "foo.tf")),
		filepath.ToSlash(filepath.Join(dir, "foo.tofu.json")),
		filepath.ToSlash(filepath.Join(dir, "main.tf")),
		filepath.ToSlash(filepath.Join(dir, "main.tf.json")),
		filepath.ToSlash(filepath.Join(dir, "main.tofu")),
		filepath.ToSlash(filepath.Join(dir, "main.tofu.json")),
	}, files)
}

func TestWalkInventoryTofuShadowing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	tofu := filepath.Join(dir, "main.tofu")
	twin := filepath.Join(dir, "main.tf")
	tofuJSON := filepath.Join(dir, "main.tofu.json")
	twinJSON := filepath.Join(dir, "main.tf.json")
	require.NoError(t, os.WriteFile(tofu, []byte(`resource "aws_s3_bucket" "b" {}`), 0o600))
	require.NoError(t, os.WriteFile(twin, []byte(`resource "aws_s3_bucket" "shadowed" {}`), 0o600))
	require.NoError(t, os.WriteFile(tofuJSON, []byte(`{}`), 0o600))
	require.NoError(t, os.WriteFile(twinJSON, []byte(`{}`), 0o600))

	fs, err := NewFileSystemSourceProvider(ctx, []string{dir}, nil, nil)
	require.NoError(t, err)

	noChart := func(context.Context, string) bool { return false }
	extensions := model.Extensions{".tf": {}, ".tofu": {}, ".tf.json": {}, ".tofu.json": {}}
	files, err := fs.WalkInventory(ctx, extensions, utils.PoolOptions{}, noChart)
	require.NoError(t, err)

	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	require.ElementsMatch(t, []string{
		filepath.ToSlash(tofu),
		filepath.ToSlash(twin),
		filepath.ToSlash(tofuJSON),
		filepath.ToSlash(twinJSON),
	}, paths)
}

func TestWalkInventoryPrebuiltTofuShadowing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	tofu := filepath.Join(dir, "main.tofu")
	twin := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(tofu, []byte(`resource "aws_s3_bucket" "b" {}`), 0o600))
	require.NoError(t, os.WriteFile(twin, []byte(`resource "aws_s3_bucket" "shadowed" {}`), 0o600))

	fs, err := NewFileSystemSourceProvider(ctx, []string{dir}, nil, nil)
	require.NoError(t, err)
	fs.SetPrebuiltWalk([]string{
		filepath.ToSlash(twin),
		filepath.ToSlash(tofu),
	}, nil, nil)

	noChart := func(context.Context, string) bool { return false }
	extensions := model.Extensions{".tf": {}, ".tofu": {}}
	files, err := fs.WalkInventory(ctx, extensions, utils.PoolOptions{}, noChart)
	require.NoError(t, err)

	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	require.ElementsMatch(t, []string{filepath.ToSlash(twin), filepath.ToSlash(tofu)}, paths)
}

func TestGetSourcesTofuShadowing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	tofu := filepath.Join(dir, "main.tofu")
	twin := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(tofu, []byte(`resource "aws_s3_bucket" "b" {}`), 0o600))
	require.NoError(t, os.WriteFile(twin, []byte(`resource "aws_s3_bucket" "shadowed" {}`), 0o600))

	fs, err := NewFileSystemSourceProvider(ctx, []string{dir}, nil, nil)
	require.NoError(t, err)
	exts := model.Extensions{".tf": {}, ".tofu": {}}
	noop := func(context.Context, string) ([]string, error) { return nil, nil }

	collect := func(parallel bool) []string {
		var got []string
		var mu sync.Mutex
		sink := func(_ context.Context, filename string, content io.ReadCloser) error {
			_ = content.Close()
			mu.Lock()
			got = append(got, filepath.Base(filename))
			mu.Unlock()
			return nil
		}
		var runErr error
		if parallel {
			runErr = fs.GetParallelSources(ctx, exts, sink, noop)
		} else {
			runErr = fs.GetSources(ctx, exts, sink, noop)
		}
		require.NoError(t, runErr)
		return got
	}

	for _, parallel := range []bool{false, true} {
		got := collect(parallel)
		require.ElementsMatch(t, []string{"main.tf", "main.tofu"}, got, "parallel=%v", parallel)
	}
}

func TestGetSourcesTofuShadowingExplicitFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	tofu := filepath.Join(dir, "main.tofu")
	twin := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(tofu, []byte(`resource "aws_s3_bucket" "b" {}`), 0o600))
	require.NoError(t, os.WriteFile(twin, []byte(`resource "aws_s3_bucket" "shadowed" {}`), 0o600))

	fs, err := NewFileSystemSourceProvider(ctx, []string{twin, tofu}, nil, nil)
	require.NoError(t, err)
	exts := model.Extensions{".tf": {}, ".tofu": {}}
	noop := func(context.Context, string) ([]string, error) { return nil, nil }

	for _, parallel := range []bool{false, true} {
		var got []string
		var mu sync.Mutex
		sink := func(_ context.Context, filename string, content io.ReadCloser) error {
			_ = content.Close()
			mu.Lock()
			got = append(got, filepath.Base(filename))
			mu.Unlock()
			return nil
		}
		var runErr error
		if parallel {
			runErr = fs.GetParallelSources(ctx, exts, sink, noop)
		} else {
			runErr = fs.GetSources(ctx, exts, sink, noop)
		}
		require.NoError(t, runErr)
		require.ElementsMatch(t, []string{"main.tf", "main.tofu"}, got, "parallel=%v", parallel)
	}
}

// Path filters reach Helm charts too: an ignored or out-of-scope chart is not
// rendered, and only-paths naming a template inside a chart still renders it.
func TestWalkInventoryRendersOnlyChartsInScope(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	for _, chart := range []string{"app", "lib", "other"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, chart, "templates"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, chart, "Chart.yaml"), []byte("name: "+chart+"\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, chart, "templates", "cm.yaml"), []byte("kind: ConfigMap\n"), 0o600))
	}
	roots := []string{
		filepath.ToSlash(filepath.Join(dir, "app")),
		filepath.ToSlash(filepath.Join(dir, "lib")),
		filepath.ToSlash(filepath.Join(dir, "other")),
	}
	tests := []struct {
		name           string
		excludes, only []string
		want           []string
	}{
		{"no filters", nil, nil, []string{"app", "lib", "other"}},
		{"ignored chart", []string{filepath.Join(dir, "lib", "**")}, nil, []string{"app", "other"}},
		{"only one chart", nil, []string{filepath.Join(dir, "app")}, []string{"app"}},
		{"only one template", nil, []string{filepath.Join(dir, "other", "templates", "cm.yaml")}, []string{"other"}},
	}
	for _, prebuilt := range []bool{true, false} {
		for _, tt := range tests {
			t.Run(fmt.Sprintf("%s prebuilt=%v", tt.name, prebuilt), func(t *testing.T) {
				fs, err := NewFileSystemSourceProvider(ctx, []string{dir}, tt.excludes, tt.only)
				require.NoError(t, err)
				if prebuilt {
					fs.SetPrebuiltWalk([]string{roots[0] + "/templates/cm.yaml"}, roots, nil)
				}
				var mu sync.Mutex
				var rendered []string
				_, err = fs.WalkInventory(ctx, model.Extensions{".yaml": {}}, utils.PoolOptions{}, func(_ context.Context, root string) bool {
					mu.Lock()
					defer mu.Unlock()
					rendered = append(rendered, filepath.Base(root))
					return true
				})
				require.NoError(t, err)
				require.ElementsMatch(t, tt.want, rendered)
			})
		}
	}
}

// The analyzer lists the files under an ignored directory, which it matches by
// exact path only; the templates of a chart there are neither rendered nor
// scanned raw.
func TestBuildInventoryFromPrebuilt_IgnoredChartDirIsNotScannedRaw(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	var listed []string
	for _, chart := range []string{"app", "lib"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, chart, "templates"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, chart, "Chart.yaml"), []byte("name: "+chart+"\n"), 0o600))
		template := filepath.Join(dir, chart, "templates", "cm.yaml")
		require.NoError(t, os.WriteFile(template, []byte("kind: ConfigMap\n"), 0o600))
		listed = append(listed, filepath.ToSlash(template))
	}
	fs, err := NewFileSystemSourceProvider(ctx, []string{dir}, []string{filepath.Join(dir, "lib")}, nil)
	require.NoError(t, err)
	fs.SetPrebuiltWalk(listed, []string{filepath.ToSlash(filepath.Join(dir, "app")), filepath.ToSlash(filepath.Join(dir, "lib"))}, nil)
	files, err := fs.WalkInventory(ctx, model.Extensions{".yaml": {}}, utils.PoolOptions{},
		func(_ context.Context, root string) bool {
			require.Equal(t, "app", filepath.Base(root))
			return false
		})
	require.NoError(t, err)
	require.Equal(t, []InventoryFile{{Path: listed[0], Ext: ".yaml"}}, files,
		"app failed to render, so its raw template is scanned; lib's is not")
}

func TestExcludesFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	kept := filepath.Join(dir, "app", "cm.yaml")
	ignored := filepath.Join(dir, "lib", "cm.yaml")
	for _, f := range []string{kept, ignored} {
		require.NoError(t, os.MkdirAll(filepath.Dir(f), 0o755))
		require.NoError(t, os.WriteFile(f, []byte("kind: ConfigMap\n"), 0o600))
	}
	fs, err := NewFileSystemSourceProvider(ctx, []string{dir}, []string{ignored}, nil)
	require.NoError(t, err)
	require.False(t, fs.ExcludesFile(kept))
	require.True(t, fs.ExcludesFile(ignored))
	require.False(t, fs.ExcludesFile(filepath.Join(dir, "app", "charts", "pkg", "templates", "cm.yaml")),
		"a path that names no file is not matched by the filters")

	ignoredDir, err := NewFileSystemSourceProvider(ctx, []string{dir}, []string{filepath.Join(dir, "lib")}, nil)
	require.NoError(t, err)
	require.True(t, ignoredDir.ExcludesFile(ignored), "a file under an ignored directory is excluded")
	require.True(t, ignoredDir.ExcludesFile(filepath.Join(dir, "lib", "charts", "pkg", "templates", "cm.yaml")),
		"so is a file of an archive under it")
	require.False(t, ignoredDir.ExcludesFile(kept))
	inScope, outOfScope := ignoredDir.partitionChartRoots(
		[]string{toSlash(filepath.Join(dir, "app")), toSlash(filepath.Join(dir, "lib"))})
	require.Equal(t, []string{toSlash(filepath.Join(dir, "app"))}, inScope)
	require.Equal(t, []string{toSlash(filepath.Join(dir, "lib"))}, outOfScope)

	only, err := NewFileSystemSourceProvider(ctx, []string{dir}, nil, []string{filepath.Join(dir, "app")})
	require.NoError(t, err)
	require.False(t, only.ExcludesFile(kept))
	require.True(t, only.ExcludesFile(ignored))

	mem := NewMemorySourceProvider(nil, nil, []string{"lib/**"}, nil)
	require.True(t, mem.ExcludesFile("lib/cm.yaml"))
	require.False(t, mem.ExcludesFile("app/cm.yaml"))
}

func TestChartRootWaves(t *testing.T) {
	waves := chartRootWaves([]string{
		"a/charts/sub/charts/leaf", "b", "a/charts/sub", "a", "c\\charts\\x", "c", "b",
	})
	require.Equal(t, [][]string{
		{"a", "b", "c"},
		{"c/charts/x", "a/charts/sub"},
		{"a/charts/sub/charts/leaf"},
	}, waves)
	require.Equal(t, [][]string{{"."}, {"charts/sub", "deploy/app"}}, chartRootWaves([]string{"charts/sub", ".", "deploy/app"}))
	require.Equal(t, [][]string{{"/r/a", "/r/b"}, {"/r/a/charts/x"}},
		chartRootWaves([]string{"/r/a/charts/x", "/r/b", "/r/a"}))
	require.Empty(t, chartRootWaves(nil))
}

// Charts render concurrently, yet a subchart is still skipped exactly when an
// enclosing chart rendered it, and a failed parent leaves it to render alone.
func TestRenderChartsShallowFirst(t *testing.T) {
	failing := map[string]bool{"b": true}
	rendered := renderChartsShallowFirst(context.Background(),
		[]string{"a/charts/sub", "b/charts/sub", "a", "b", "c", "d/nested"}, utils.PoolOptions{CPUBound: true},
		func(_ context.Context, root string) bool { return !failing[root] })
	require.ElementsMatch(t, []string{"a", "c", "d/nested", "b/charts/sub"}, rendered)
}

// A single-worker pool renders one chart at a time, which is what turning the
// parallel-parsing flag off asks for.
func TestRenderChartsShallowFirstSequentialPool(t *testing.T) {
	var running, peak atomic.Int32
	rendered := renderChartsShallowFirst(context.Background(),
		[]string{"a", "b", "c", "d"}, utils.PoolOptions{Workers: 1},
		func(context.Context, string) bool {
			n := running.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			running.Add(-1)
			return true
		})
	require.ElementsMatch(t, []string{"a", "b", "c", "d"}, rendered)
	require.Equal(t, int32(1), peak.Load())
}

// A directory walk renders charts through the same recover as the pool: a
// chart whose render panics is left unrendered and its raw files are listed.
func TestWalkInventoryRecoversChartPanic(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	template := filepath.Join(dir, "chart", "templates", "cm.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(template), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "chart", "Chart.yaml"),
		[]byte("apiVersion: v2\nname: app\nversion: 1.0.0\n"), 0o600))
	require.NoError(t, os.WriteFile(template, []byte("apiVersion: v1\nkind: ConfigMap\n"), 0o600))

	fs, err := NewFileSystemSourceProvider(ctx, []string{dir}, nil, nil)
	require.NoError(t, err)
	charts := 0
	var files []InventoryFile
	require.NotPanics(t, func() {
		files, err = fs.WalkInventory(ctx, model.Extensions{".yaml": {}}, utils.PoolOptions{},
			func(context.Context, string) bool {
				charts++
				panic("boom")
			})
	})
	require.NoError(t, err)
	require.Equal(t, 1, charts)
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	require.Contains(t, paths, filepath.ToSlash(template))
}

// A chart whose render panics is left unrendered without taking down the
// others: renders run on pool goroutines, out of reach of the caller's recover.
func TestRenderChartsShallowFirstRecoversPanic(t *testing.T) {
	rendered := renderChartsShallowFirst(context.Background(),
		[]string{"a", "b", "c"}, utils.PoolOptions{CPUBound: true},
		func(_ context.Context, root string) bool {
			if root == "b" {
				panic("boom")
			}
			return true
		})
	require.ElementsMatch(t, []string{"a", "c"}, rendered)
}
