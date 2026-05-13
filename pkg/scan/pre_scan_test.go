/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRemoteConfigClient struct {
	remote []byte
	err    error
}

func (f fakeRemoteConfigClient) GetDefaultRuleset(_ context.Context) (*datadog.Ruleset, error) {
	panic("unimplemented")
}

func (f fakeRemoteConfigClient) GetRemoteConfig(_ context.Context, _ string, localConfig []byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.remote != nil {
		return f.remote, nil
	}
	return localConfig, nil
}

func TestBestEffortDatadog_Success(t *testing.T) {
	client := fakeRemoteConfigClient{remote: []byte("remote-config")}

	opt := bestEffortDatadog(client, "https://example.com/repo.git")
	out, err := opt(t.Context(), []byte("local-config"))

	assert.NoError(t, err)
	assert.Equal(t, "remote-config", string(out))
}

func TestBestEffortDatadog_ErrorFallsBackToLocal(t *testing.T) {
	client := fakeRemoteConfigClient{err: errors.New("network down")}

	opt := bestEffortDatadog(client, "https://example.com/repo.git")
	out, err := opt(t.Context(), []byte("local-config"))

	assert.NoError(t, err, "remote-config errors must not fail the scan")
	assert.Equal(t, "local-config", string(out))
}

func TestConfigurationOptions_NoGitRemoteReturnsNil(t *testing.T) {
	opts := configurationOptions(t.TempDir())
	assert.Nil(t, opts)
}

func TestConfigurationOptions_GitRemoteReturnsDatadogOption(t *testing.T) {
	const remoteURL = "https://example.com/test-repo.git"
	repoDir := initRepoWithOrigin(t, remoteURL)

	t.Run("repository root", func(t *testing.T) {
		assert.Equal(t, remoteURL, lookupRepositoryURL(repoDir))

		opts := configurationOptions(repoDir)
		require.Len(t, opts, 1, "expected a single WithDatadog-backed option")
		assert.NotNil(t, opts[0])
	})

	t.Run("nested subdirectory walks up to repo root", func(t *testing.T) {
		nested := filepath.Join(repoDir, "a", "b", "c")
		require.NoError(t, os.MkdirAll(nested, 0o755))

		assert.Equal(t, remoteURL, lookupRepositoryURL(nested))

		opts := configurationOptions(nested)
		require.Len(t, opts, 1)
		assert.NotNil(t, opts[0])
	})
}

// initRepoWithOrigin creates a temporary git repository configured with a single
// `origin` remote pointing at remoteURL, and returns its path.
func initRepoWithOrigin(t *testing.T, remoteURL string) string {
	t.Helper()

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{remoteURL},
	})
	require.NoError(t, err)

	return dir
}
