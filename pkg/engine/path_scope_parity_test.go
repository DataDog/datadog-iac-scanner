/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/stretchr/testify/require"
)

// The disk filter, the in-memory filter and the rule filter apply one rule to a
// file known by several paths, so one table of cases runs through each of them.
func TestPathFiltersAgreeOnFilesKnownBySeveralPaths(t *testing.T) {
	root := t.TempDir()
	at := func(parts ...string) string { return filepath.Join(append([]string{root}, parts...)...) }
	paths := []string{at("app", "charts", "pkg", "templates", "pod.yaml"), at("app", "Chart.yaml")}
	declared := at("app", "Chart.yaml")
	cases := []struct {
		name         string
		ignore, only []string
		want         bool
	}{
		{name: "no filters", want: false},
		{name: "ignore on the archive's directory", ignore: []string{at("app", "charts")}, want: true},
		{name: "ignore on the declaration", ignore: []string{declared}, want: true},
		{name: "ignore on neither", ignore: []string{at("lib")}, want: false},
		{name: "ignore on a sibling sharing the prefix", ignore: []string{at("app", "char")}, want: false},
		{name: "only on the declaration", only: []string{declared}, want: false},
		{name: "only on the archive's directory", only: []string{at("app", "charts")}, want: false},
		{name: "only on neither", only: []string{at("lib")}, want: true},
		{name: "only on a sibling sharing the prefix", only: []string{at("app", "chart")}, want: true},
		{name: "ignore wins over only", ignore: []string{at("app", "charts")}, only: []string{declared}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			disk := provider.NewPathFilter(tc.ignore, tc.only)
			memory := provider.NewMemorySourceProvider(nil, nil, tc.ignore, tc.only)
			rule := &Inspector{}
			require.Equal(t, tc.want, disk.ExcludesAny(paths...), "disk filter")
			require.Equal(t, tc.want, memory.ExcludesAny(paths...), "in-memory filter")
			require.Equal(t, tc.want, rule.rulePathsExcluded(paths, tc.ignore, tc.only), "rule filter")
		})
	}
}
