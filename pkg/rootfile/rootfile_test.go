package rootfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadFile_roundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a", "b.txt")
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
	require.NoError(t, os.WriteFile(p, []byte("hello"), 0o600))

	got, err := ReadFile(p)
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))

	fi, err := Lstat(p)
	require.NoError(t, err)
	require.False(t, fi.IsDir())
}
