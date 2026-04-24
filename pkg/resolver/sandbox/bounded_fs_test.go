package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBoundedFS_RejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.yaml")
	require.NoError(t, os.WriteFile(outside, []byte("secret"), 0o600))
	link := filepath.Join(root, "escape.yaml")
	require.NoError(t, os.Symlink(outside, link))

	fs, err := NewBoundedFS(root)
	require.NoError(t, err)
	_, err = fs.ReadFile(link)
	require.Error(t, err, "read through symlink to outside root should be rejected")
}

func TestBoundedFS_RejectsTraversal(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "safe")
	require.NoError(t, os.MkdirAll(sub, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "a.yaml"), []byte("k: v\n"), 0o600))

	fs, err := NewBoundedFS(root)
	require.NoError(t, err)
	_, err = fs.ReadFile(filepath.Join(sub, "a.yaml"))
	require.NoError(t, err)

	outside := filepath.Join(root, "..", "outside")
	_, err = fs.ReadFile(outside)
	require.Error(t, err)
}

func TestBoundedFS_RejectsWriteThroughSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	outsideRoot := t.TempDir()
	linkDir := filepath.Join(root, "linked")
	require.NoError(t, os.Symlink(outsideRoot, linkDir))

	fs, err := NewBoundedFS(root)
	require.NoError(t, err)

	target := filepath.Join(linkDir, "escape.yaml")
	err = fs.WriteFile(target, []byte("secret"))
	require.Error(t, err, "write through symlinked parent should be rejected")

	_, statErr := os.Stat(filepath.Join(outsideRoot, "escape.yaml"))
	require.Error(t, statErr)
	require.True(t, os.IsNotExist(statErr))
}
