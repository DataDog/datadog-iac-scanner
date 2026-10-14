/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/stretchr/testify/require"
)

// The disk filter, the in-memory filter and the rule filter apply one rule to a
// file known by several paths, so one table of cases runs through each of them.
// Patterns are absolute paths under a temporary root, and globs are expanded on
// disk for the disk filter, so the files they name exist.
func TestPathFiltersAgreeOnFilesKnownBySeveralPaths(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"app/charts/pkg-1.0.0.tgz", "app/Chart.yaml", "lib/Chart.yaml"} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
	}
	abs := func(rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }
	patterns := func(rels ...string) []string {
		if len(rels) == 0 {
			return nil
		}
		out := make([]string, 0, len(rels))
		for _, rel := range rels {
			out = append(out, abs(rel))
		}
		return out
	}
	// The rendered template names no file on disk, only the archive does.
	paths := []string{abs("app/charts/pkg/templates/pod.yaml"), abs("app/Chart.yaml")}
	archive := []string{abs("app/charts/pkg-1.0.0.tgz"), abs("app/Chart.yaml")}
	cases := []struct {
		name         string
		known        []string
		ignore, only []string
		want         bool
	}{
		{name: "no filters", want: false},
		{name: "ignore on the archive's directory", ignore: patterns("app/charts"), want: true},
		{name: "ignore on the archive's directory by glob", ignore: patterns("app/charts/**"), want: true},
		{name: "ignore on the declaration", ignore: patterns("app/Chart.yaml"), want: true},
		{name: "ignore on neither", ignore: patterns("lib"), want: false},
		{name: "ignore on neither by glob", ignore: patterns("lib/*.yaml"), want: false},
		{name: "ignore on a sibling sharing the prefix", ignore: patterns("app/char"), want: false},
		{name: "ignore on the archive file by glob", known: archive, ignore: patterns("app/charts/*.tgz"), want: true},
		{name: "ignore on the archive file by glob, not the rendered template", ignore: patterns("app/charts/*.tgz"), want: false},
		{name: "ignore on the rendered template by glob", ignore: patterns("app/charts/pkg/templates/*.yaml"), want: true},
		{name: "only on the declaration", only: patterns("app/Chart.yaml"), want: false},
		{name: "only on the archive's directory", only: patterns("app/charts"), want: false},
		{name: "only on the archive's directory by glob", only: patterns("app/charts/**"), want: false},
		{name: "only on the rendered template by glob", only: patterns("app/charts/pkg/templates/*.yaml"), want: false},
		{name: "only on neither", only: patterns("lib"), want: true},
		{name: "only on a sibling sharing the prefix", only: patterns("app/chart"), want: true},
		{name: "ignore wins over only", ignore: patterns("app/charts"), only: patterns("app/Chart.yaml"), want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			known := paths
			if tc.known != nil {
				known = tc.known
			}
			disk, err := provider.ExpandPathFilter(tc.ignore, tc.only)
			require.NoError(t, err)
			memory := provider.NewMemorySourceProvider(nil, nil, tc.ignore, tc.only)
			rule := &Inspector{}
			require.Equal(t, tc.want, disk.ExcludesAny(known...), "disk filter")
			require.Equal(t, tc.want, memory.ExcludesAny(known...), "in-memory filter")
			require.Equal(t, tc.want, rule.rulePathsExcluded(known, tc.ignore, tc.only), "rule filter")
		})
	}
}

// With no path to check, a file is excluded exactly when only-paths are set.
func TestPathFiltersWithoutPaths(t *testing.T) {
	only := []string{filepath.Join(t.TempDir(), "app")}
	require.True(t, provider.NewPathFilter(nil, only).ExcludesAny(), "disk filter")
	require.True(t, provider.NewMemorySourceProvider(nil, nil, nil, only).ExcludesAny(), "in-memory filter")
	require.True(t, (&Inspector{}).rulePathsExcluded(nil, nil, only), "rule filter")
	require.False(t, provider.NewPathFilter(nil, nil).ExcludesAny(), "disk filter without only-paths")
	require.False(t, provider.NewMemorySourceProvider(nil, nil, nil, nil).ExcludesAny(), "in-memory filter without only-paths")
	require.False(t, (&Inspector{}).rulePathsExcluded(nil, nil, nil), "rule filter without only-paths")
}
