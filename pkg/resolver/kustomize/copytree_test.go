package kustomize

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCopyRepoRelativeFilesNoSymlinks_skipsSymlinks(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(secret, []byte("secret"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "ok.txt"), []byte("ok"), 0o600))
	require.NoError(t, os.Symlink(secret, filepath.Join(src, "leak")))

	require.NoError(t, CopyRepoRelativeFilesNoSymlinks(dst, src, []string{"ok.txt", "leak"}))

	got, err := os.ReadFile(filepath.Join(dst, "ok.txt"))
	require.NoError(t, err)
	require.Equal(t, "ok", string(got))
	_, err = os.Stat(filepath.Join(dst, "leak"))
	require.Error(t, err)
	require.True(t, errors.Is(err, os.ErrNotExist), "symlink must not be copied")
}
