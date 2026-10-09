/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"context"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/resolver"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/helm"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

// panicOnReadDirFS fails while the chart's files are being loaded, after the
// chart has been recognised as one.
type panicOnReadDirFS struct{ vfs.FS }

func (panicOnReadDirFS) ReadDir(string) ([]fs.DirEntry, error) { panic("boom") }

type chartFailureRecorder struct {
	preparedSource
	failed []string
}

func (r *chartFailureRecorder) chartFailed(chartPath string) { r.failed = append(r.failed, chartPath) }

// A chart whose rendering panics goes through the same failure handling as a
// chart that fails to render: it is recorded failed and its raw files scanned.
// It runs the real Helm resolver, which recovers panics itself.
func TestResolveAndStoreChartHandlesResolvePanic(t *testing.T) {
	ctx := context.Background()
	memfs := vfs.NewMemFS(map[string][]byte{
		"chart/Chart.yaml":        []byte("apiVersion: v2\nname: app\nversion: 1.0.0\n"),
		"chart/templates/cm.yaml": []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n"),
	})
	res, err := resolver.NewBuilder().Add(ctx, helm.NewResolver(panicOnReadDirFS{memfs})).Build(ctx)
	require.NoError(t, err)
	service := &Service{Resolver: res}
	src := &chartFailureRecorder{}

	rendered := resolveAndStoreChart(ctx, src, []*Service{service}, "chart", "scan", false, 15, &unrenderedHelmCharts{})

	require.False(t, rendered)
	require.Equal(t, []string{"chart"}, src.failed)
	require.True(t, service.isUnderFailedHelmChart(filepath.Join("chart", "templates", "cm.yaml")))
}

// A panic while storing the files of a rendered chart leaves documents already
// stored, so the chart counts as rendered and its raw templates are not
// scanned on top of them.
func TestResolveAndStoreChartKeepsRenderedWhenStoringPanics(t *testing.T) {
	ctx := context.Background()
	memfs := vfs.NewMemFS(map[string][]byte{
		"chart/Chart.yaml":        []byte("apiVersion: v2\nname: app\nversion: 1.0.0\n"),
		"chart/templates/cm.yaml": []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n"),
	})
	res, err := resolver.NewBuilder().Add(ctx, helm.NewResolver(memfs)).Build(ctx)
	require.NoError(t, err)
	service := &Service{Resolver: res} // no parser: storing the files panics
	src := &chartFailureRecorder{}

	rendered := resolveAndStoreChart(ctx, src, []*Service{service}, "chart", "scan", false, 15, &unrenderedHelmCharts{})

	require.True(t, rendered)
	require.Empty(t, src.failed)
}
