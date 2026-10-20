/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

func TestExtensionFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{path: "/repo/main.tf", want: ".tf"},
		{path: "/repo/main.tf.json", want: ".tf.json"},
		{path: "/repo/main.tofu.json", want: ".tofu.json"},
		{path: "/repo/MAIN.TF.JSON", want: ".tf.json"},
		{path: "/repo/data.json", want: ".json"},
		{path: "/repo/Dockerfile", want: "Dockerfile"},
		{path: "/repo/vars.tfvars", want: ".tfvars"},
		{path: "/repo/terraform.tfvars", want: ".tfvars"},
		{path: "/repo/pnpm-lock.yaml", want: ".yaml"},
		{path: "/repo/Makefile", want: ""},
		{path: "/repo/bin/aws", want: ""},
	}
	for _, tt := range tests {
		if got := ExtensionFromPath(tt.path); got != tt.want {
			t.Errorf("ExtensionFromPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestDockerfileExtensions(t *testing.T) {
	for _, tt := range []struct{ path, want string }{
		{"Dockerfile", "Dockerfile"},
		{"dockerfile", "Dockerfile"},
		{"DOCKERFILE", "Dockerfile"},
		{"api.Dockerfile", ".dockerfile"},
		{"api.DOCKERFILE", ".dockerfile"},
		{"Dockerfile.prod", "possibleDockerfile"},
		{"dockerfile.dev", "possibleDockerfile"},
		{"Dockerfile.ubi8", "possibleDockerfile"},
		{"dockerfile.tf", ".tf"},
		{"dockerfile.tofu", ".tofu"},
		{"Dockerfile.tf.json", ".tf.json"},
		{"Dockerfile.tofu.json", ".tofu.json"},
		{"dockerfile.yaml", ".yaml"},
		{"dockerfile.yml", ".yml"},
		{"dockerfile.json", ".json"},
		{"dockerfile.go", ".go"},
		{"dockerfile.py", ".py"},
		{"dockerfile.ts", ".ts"},
		{"Dockerfile.bicep", ".bicep"},
		{"Dockerfile.sh", ".sh"},
		{"Dockerfile.dockerignore", ".dockerignore"},
		{"api.Dockerfile.dockerignore", ".dockerignore"},
		{"Dockerfile.bak", ".bak"},
		{"Dockerfile.orig", ".orig"},
		{"Dockerfile.save", ".save"},
		{"Dockerfile.swp", ".swp"},
		{"Dockerfile.tmp", ".tmp"},
		{"Dockerfile.rej", ".rej"},
		{"Dockerfile.patch", ".patch"},
		{"Dockerfile.diff", ".diff"},
		{"Dockerfile.gz", ".gz"},
		{"Dockerfile.tgz", ".tgz"},
		{"Dockerfile.tar", ".tar"},
		{"Dockerfile.zip", ".zip"},
		{"Dockerfile.xz", ".xz"},
		{"Dockerfile.bz2", ".bz2"},
		{"DOCKERFILE.BAK", ".BAK"},
		// Templates remain candidates: plain Dockerfile templates can be scanned
		// when their content passes the ordinary Dockerfile gate.
		{"Dockerfile.j2", "possibleDockerfile"},
		{"Dockerfile.tpl", "possibleDockerfile"},
		{"Dockerfile.template", "possibleDockerfile"},
		{"Dockerfile.erb", "possibleDockerfile"},
		{"Dockerfile.gotmpl", "possibleDockerfile"},
	} {
		t.Run(tt.path, func(t *testing.T) {
			require.Equal(t, tt.want, ExtensionFromPath(tt.path))
			fsys := vfs.NewMemFS(map[string][]byte{tt.path: []byte("FROM alpine\n")})
			ext, err := GetExtensionWithFS(t.Context(), fsys, tt.path)
			require.NoError(t, err)
			require.Equal(t, tt.want, ext)
			require.Empty(t, fsys.MissingFiles())
		})
	}
}

func TestGetExtension(t *testing.T) {
	tests := []struct {
		name     string
		want     string
		err      error
		filePath string
		toCreate bool
	}{
		{
			name:     "Get extension from a file with extension defined ('positive.tf')",
			want:     ".tf",
			filePath: "../../test/fixtures/all_auth_users_get_read_access/test/positive.tf",
			toCreate: false,
			err:      nil,
		},
		{
			name:     "Get error when analyze a folder",
			want:     "",
			filePath: "../../test/fixtures/for_test_folder",
			toCreate: true,
			err:      fmt.Errorf("the path %s is a directory", "../../test/fixtures/for_test_folder"),
		},
	}

	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.toCreate {
				err := os.Mkdir(test.filePath, 0755)

				if err != nil {
					require.Nil(t, err, "error creating folder")
				}
			}

			got, err := GetExtension(ctx, test.filePath)
			require.Equal(t, test.want, got)
			require.Equal(t, test.err, err)

			if test.toCreate {
				os.RemoveAll(test.filePath)
			}
		})
	}
}
