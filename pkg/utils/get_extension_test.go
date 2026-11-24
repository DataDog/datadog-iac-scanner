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

	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"
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
		{path: "/repo/dockerfile", want: "Dockerfile"},
		{path: "/repo/DOCKERFILE", want: "Dockerfile"},
		{path: "/repo/app.dockerfile", want: ".dockerfile"},
		{path: "/repo/app.Dockerfile", want: ".dockerfile"},
		{path: "/repo/app.DOCKERFILE", want: ".dockerfile"},
		{path: "/repo/.dockerfile", want: ".dockerfile"},
		{path: "/repo/Dockerfile.dockerfile", want: ".dockerfile"},
		{path: "/repo/Dockerfile.Dockerfile", want: ".dockerfile"},
		{path: "/repo/Dockerfile.prod", want: PossibleDockerfile},
		{path: "/repo/dockerfile.dev", want: PossibleDockerfile},
		{path: "/repo/DOCKERFILE.CI", want: PossibleDockerfile},
		{path: "/repo/Dockerfile.linux.amd64", want: PossibleDockerfile},
		{path: "/repo/Dockerfile.debian", want: PossibleDockerfile},
		{path: "/repo/Dockerfile.DEBIAN", want: PossibleDockerfile},
		{path: "/repo/Dockerfile.ubi8", want: PossibleDockerfile},
		{path: "/repo/Dockerfile.UBI8", want: PossibleDockerfile},
		{path: "/repo/Dockerfile.tar.gz", want: PossibleDockerfile},
		{path: "/repo/app.debian", want: ".debian"},
		{path: "/repo/app.ubi8", want: ".ubi8"},
		// Registered non-Dockerfile formats take precedence over Dockerfile.*
		{path: "/repo/Dockerfile.yaml", want: ".yaml"},
		{path: "/repo/Dockerfile.yml", want: ".yml"},
		{path: "/repo/Dockerfile.json", want: ".json"},
		{path: "/repo/Dockerfile.tf", want: ".tf"},
		{path: "/repo/Dockerfile.tofu", want: ".tofu"},
		{path: "/repo/Dockerfile.tf.json", want: ".tf.json"},
		{path: "/repo/Dockerfile.TF.JSON", want: ".tf.json"},
		{path: "/repo/Dockerfile.tofu.json", want: ".tofu.json"},
		{path: "/repo/Dockerfile.tfvars", want: ".tfvars"},
		{path: "/repo/Dockerfile.sh", want: ".sh"},
		{path: "/repo/Dockerfile.cfg", want: ".cfg"},
		{path: "/repo/Dockerfile.conf", want: ".conf"},
		{path: "/repo/Dockerfile.ini", want: ".ini"},
		{path: "/repo/Dockerfile.proto", want: ".proto"},
		{path: "/repo/Dockerfile.bicep", want: ".bicep"},
		// Uppercase registered non-Dockerfile extensions are not hijacked as Dockerfile.*
		{path: "/repo/Dockerfile.YAML", want: ".YAML"},
		{path: "/repo/Dockerfile.TF", want: ".TF"},
		{path: "/repo/Dockerfile.JSON", want: ".JSON"},
		// Non-matching names
		{path: "/repo/my-dockerfile", want: ""},
		{path: "/repo/Dockerfile_prod", want: ""},
		{path: "/repo/Dockerfile-dev", want: ""},
		{path: "/repo/possibleDockerfile", want: ""},
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

func TestGetExtensionWithFS_DockerfileVariants(t *testing.T) {
	ctx := context.Background()
	mem := vfs.NewMemFS(map[string][]byte{
		"dockerfile":         []byte("FROM alpine\n"),
		"app.DOCKERFILE":     []byte("FROM alpine\n"),
		"Dockerfile.prod":    []byte("FROM alpine\n"),
		"Dockerfile.yaml":    []byte("apiVersion: v1\n"),
		"Dockerfile.YAML":    []byte("apiVersion: v1\n"),
		"Dockerfile.TF.JSON": []byte("{}\n"),
	})

	cases := map[string]string{
		"dockerfile":         "Dockerfile",
		"app.DOCKERFILE":     ".dockerfile",
		"Dockerfile.prod":    PossibleDockerfile,
		"Dockerfile.yaml":    ".yaml",
		"Dockerfile.YAML":    ".YAML",
		"Dockerfile.TF.JSON": ".tf.json",
	}
	for path, want := range cases {
		got, err := GetExtensionWithFS(ctx, mem, path)
		require.NoError(t, err, path)
		require.Equal(t, want, got, path)
	}

	dir := t.TempDir()
	dockerDir := dir + "/Dockerfile"
	require.NoError(t, os.Mkdir(dockerDir, 0o755))
	_, err := GetExtension(ctx, dockerDir)
	require.Error(t, err)
}

func TestFileTypeRegistry(t *testing.T) {
	// Unambiguous types expose a fixed platform and do not need content checks.
	for token, want := range map[string]string{
		"Dockerfile":  platforms.Dockerfile,
		".dockerfile": platforms.Dockerfile,
		".tf":         platforms.Terraform,
		".tofu":       platforms.Terraform,
		".tf.json":    platforms.Terraform,
		".tofu.json":  platforms.Terraform,
		".tfvars":     platforms.Terraform,
		".proto":      platforms.GRPC,
		".bicep":      platforms.Bicep,
	} {
		require.False(t, NeedsContentCheck(token), token)
		require.Equal(t, want, PlatformForFileType(token), token)
	}

	// Content-checked types must not claim a fixed platform from filename alone.
	for _, token := range []string{PossibleDockerfile, ".debian", ".ubi8", ".yaml", ".yml", ".json", ".sh", ".cfg", ".conf", ".ini"} {
		require.True(t, NeedsContentCheck(token), token)
		require.Empty(t, PlatformForFileType(token), token)
	}

	var dockerGlob *FilePattern
	for _, fp := range FilePatterns() {
		if fp.Token == PossibleDockerfile {
			fpCopy := fp
			dockerGlob = &fpCopy
			break
		}
	}
	require.NotNil(t, dockerGlob)
	require.Equal(t, "Dockerfile.*", dockerGlob.Pattern)
	require.False(t, dockerGlob.CaseSensitive)
	require.Contains(t, dockerGlob.ExcludedSuffixes, ".yaml")
	require.Contains(t, dockerGlob.ExcludedSuffixes, ".tf.json")
	require.NotContains(t, dockerGlob.ExcludedSuffixes, ".dockerfile")
	require.NotContains(t, dockerGlob.ExcludedSuffixes, ".debian")
	require.NotContains(t, dockerGlob.ExcludedSuffixes, ".ubi8")
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
