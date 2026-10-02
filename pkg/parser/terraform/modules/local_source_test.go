/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfmodules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

func TestResolveLocalModuleDir(t *testing.T) {
	repo := t.TempDir()
	mkdir := func(rel string) string {
		p := filepath.Join(repo, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(p, 0o755))
		return p
	}
	svc := mkdir("domains/svc/config/tf")
	env := mkdir("domains/svc/config/tf/environments/us1.prod")
	mkdir("domains/svc/config/tf/workflows/create")
	mkdir("domains/svc/config/tf/environments/us1.prod/local")
	mkdir("domains/shared/modules/slo")
	// Build containers mount the repository at a path like /cnab/app/terraform;
	// derive an OS-absolute equivalent so the absolute-source branch runs on
	// every OS (on Windows a leading-slash path is not absolute).
	container := filepath.Join(t.TempDir(), "cnab", "app", "terraform")
	fsys := vfs.DiskFS{}

	tests := []struct {
		name      string
		callerDir string
		source    string
		want      string
	}{
		{"relative source that exists", svc, "./workflows/create", filepath.Join(svc, "workflows/create")},
		{"environment file keeps its own directory first", env, "./local", filepath.Join(env, "local")},
		{"environment file merged into its module", env, "./workflows/create", filepath.Join(svc, "workflows/create")},
		{"relative source missing everywhere", env, "./nope", filepath.Join(env, "nope")},
		{"not under environments", svc, "../nope", filepath.Join(filepath.Dir(svc), "nope")},
		{"absolute container path mapped to the repository", svc,
			filepath.Join(container, "domains/shared/modules/slo"), filepath.Join(repo, "domains/shared/modules/slo")},
		{"absolute path that exists", svc, filepath.Join(repo, "domains/shared"), filepath.Join(repo, "domains/shared")},
		{"absolute path with no repository suffix", svc,
			filepath.Join(container, "domains/missing/mod"), filepath.Join(container, "domains/missing/mod")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ResolveLocalModuleDir(fsys, tt.callerDir, filepath.FromSlash(tt.source)))
		})
	}
}
