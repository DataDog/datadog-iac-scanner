/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestIsTestFixturePath(t *testing.T) {
	tests := map[string]bool{
		"/repo/pkg/testdata/a.yaml":   true,
		"/repo/tests/fixtures/a.yaml": true,
		"repo/__fixtures__/a.tf":      true,
		"/repo/prod/main.tf":          false,
		"/repo/testdata-gen/main.tf":  false,
		"/repo/config/fixtures.yaml":  false,
	}
	for path, want := range tests {
		if got := IsTestFixturePath(path); got != want {
			t.Errorf("IsTestFixturePath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsTestFixturePath_OnlyInsideTheRepository(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "fixtures", "infra")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if IsTestFixturePath(filepath.Join(repo, "prod", "main.tf")) {
		t.Error("a checkout under a fixtures directory is not a fixture")
	}
	if !IsTestFixturePath(filepath.Join(repo, "testdata", "main.tf")) {
		t.Error("a fixture directory inside the checkout is a fixture")
	}
}

func TestWarnUnlessFixture(t *testing.T) {
	tests := []struct {
		path      string
		minLevel  zerolog.Level
		wantLevel string
	}{
		{"stack/main.tf", zerolog.DebugLevel, "warn"},
		{"testdata/main.tf", zerolog.DebugLevel, "debug"},
		{"testdata/main.tf", zerolog.WarnLevel, ""},
		{"stack/main.tf", zerolog.WarnLevel, "warn"},
	}
	for _, tt := range tests {
		t.Run(tt.path+"/"+tt.minLevel.String(), func(t *testing.T) {
			var logs bytes.Buffer
			ctx := zerolog.New(&logs).Level(tt.minLevel).WithContext(t.Context())
			WarnUnlessFixture(ctx, tt.path).Err(errors.New("invalid content")).Msg("skipping file")

			if tt.wantLevel == "" {
				require.Empty(t, logs.String())
				return
			}
			var event map[string]string
			require.NoError(t, json.Unmarshal(logs.Bytes(), &event))
			require.Equal(t, tt.wantLevel, event["level"])
			require.Equal(t, "skipping file", event["message"])
			require.Equal(t, "invalid content", event["error"])
		})
	}
}
