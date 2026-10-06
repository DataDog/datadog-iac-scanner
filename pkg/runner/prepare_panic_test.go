/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver"
	"github.com/stretchr/testify/require"
)

type panickingHelmResolver struct{}

func (panickingHelmResolver) Resolve(context.Context, string) (model.ResolvedFiles, error) {
	panic("boom")
}

func (panickingHelmResolver) SupportedTypes() []model.FileKind {
	return []model.FileKind{model.KindHELM}
}

func (panickingHelmResolver) GetType(string) model.FileKind { return model.KindHELM }

type chartFailureRecorder struct {
	preparedSource
	failed []string
}

func (r *chartFailureRecorder) chartFailed(chartPath string) { r.failed = append(r.failed, chartPath) }

// A chart whose resolution panics goes through the same failure handling as a
// chart that fails to render: it is recorded failed and its raw files scanned.
func TestResolveAndStoreChartHandlesResolvePanic(t *testing.T) {
	ctx := context.Background()
	res, err := resolver.NewBuilder().Add(ctx, panickingHelmResolver{}).Build(ctx)
	require.NoError(t, err)
	service := &Service{Resolver: res}
	src := &chartFailureRecorder{}
	chart := t.TempDir()

	rendered := resolveAndStoreChart(ctx, src, []*Service{service}, chart, "scan", false, 15, &unrenderedHelmCharts{})

	require.False(t, rendered)
	require.Equal(t, []string{chart}, src.failed)
	require.True(t, service.isUnderFailedHelmChart(filepath.Join(chart, "templates", "cm.yaml")))
}
