/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package vfs

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// overlayCase builds a base holding a/main.tf, a/other.tf and a/sub/x.tf,
// with an overlay replacing a/main.tf and adding a/gen.tf, v/only.tf and a/sub/y.tf.
type overlayCase struct {
	name string
	root string
	base FS
}

func overlayCases(t *testing.T) []overlayCase {
	t.Helper()
	disk := t.TempDir()
	for p, c := range map[string]string{"a/main.tf": "base", "a/other.tf": "other", "a/sub/x.tf": "x"} {
		full := filepath.Join(disk, p)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(c), 0o600))
	}
	mem := string(filepath.Separator) + "ws"
	return []overlayCase{
		{"disk", disk, DiskFS{}},
		{"mem", mem, NewMemFS(map[string][]byte{
			filepath.Join(mem, "a/main.tf"):  []byte("base"),
			filepath.Join(mem, "a/other.tf"): []byte("other"),
			filepath.Join(mem, "a/sub/x.tf"): []byte("x"),
		})},
	}
}

func (c overlayCase) overlay() *Overlay {
	return NewOverlay(c.base, map[string][]byte{
		filepath.Join(c.root, "a/main.tf"):         []byte("shadow"),
		filepath.Join(c.root, "a/gen.tf"):          []byte("gen"),
		filepath.Join(c.root, "v/only.tf"):         []byte("only"),
		filepath.Join(c.root, "a/sub/../sub/y.tf"): []byte("y"),
	})
}

func names(entries []fs.DirEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestOverlay_ReadFile(t *testing.T) {
	for _, c := range overlayCases(t) {
		t.Run(c.name, func(t *testing.T) {
			o := c.overlay()
			got, err := o.ReadFile(filepath.Join(c.root, "a/main.tf"))
			require.NoError(t, err)
			require.Equal(t, "shadow", string(got))
			got, err = o.ReadFile(filepath.Join(c.root, "a/gen.tf"))
			require.NoError(t, err)
			require.Equal(t, "gen", string(got))
			got, err = o.ReadFile(filepath.Join(c.root, "a/other.tf"))
			require.NoError(t, err)
			require.Equal(t, "other", string(got))
			got, err = o.ReadFile(filepath.Join(c.root, "a/sub/y.tf"))
			require.NoError(t, err)
			require.Equal(t, "y", string(got))

			// A caller cannot mutate the overlay through the returned slice.
			got, _ = o.ReadFile(filepath.Join(c.root, "a/gen.tf"))
			got[0] = 'X'
			again, _ := o.ReadFile(filepath.Join(c.root, "a/gen.tf"))
			require.Equal(t, "gen", string(again))

			_, err = o.ReadFile(filepath.Join(c.root, "a/missing.tf"))
			require.ErrorIs(t, err, fs.ErrNotExist)
		})
	}
}

func TestOverlay_Stat(t *testing.T) {
	for _, c := range overlayCases(t) {
		t.Run(c.name, func(t *testing.T) {
			o := c.overlay()
			info, err := o.Stat(filepath.Join(c.root, "a/main.tf"))
			require.NoError(t, err)
			require.True(t, info.Mode().IsRegular())
			require.Zero(t, info.Mode().Perm()&0o222, "overlay files are read-only")
			require.Equal(t, int64(len("shadow")), info.Size())
			require.Equal(t, "main.tf", info.Name())

			info, err = o.Stat(filepath.Join(c.root, "a/other.tf"))
			require.NoError(t, err)
			require.Equal(t, int64(len("other")), info.Size())

			info, err = o.Stat(filepath.Join(c.root, "v/only.tf"))
			require.NoError(t, err)
			require.Equal(t, int64(len("only")), info.Size())

			// Virtual-only directory.
			info, err = o.Stat(filepath.Join(c.root, "v"))
			require.NoError(t, err)
			require.True(t, info.IsDir())
			require.Equal(t, "v", info.Name())

			_, err = o.Stat(filepath.Join(c.root, "nope"))
			require.ErrorIs(t, err, fs.ErrNotExist)
			_, err = o.Stat(filepath.Join(c.root, "v/nope.tf"))
			require.ErrorIs(t, err, fs.ErrNotExist)
		})
	}
}

func TestOverlay_ReadDir(t *testing.T) {
	for _, c := range overlayCases(t) {
		t.Run(c.name, func(t *testing.T) {
			o := c.overlay()
			entries, err := o.ReadDir(filepath.Join(c.root, "a"))
			require.NoError(t, err)
			require.Equal(t, []string{"gen.tf", "main.tf", "other.tf", "sub"}, names(entries))
			for _, e := range entries {
				switch e.Name() {
				case "main.tf":
					info, err := e.Info()
					require.NoError(t, err)
					require.Equal(t, int64(len("shadow")), info.Size(), "overlay replaces the base entry")
				case "sub":
					require.True(t, e.IsDir())
				}
			}

			entries, err = o.ReadDir(filepath.Join(c.root, "a/sub"))
			require.NoError(t, err)
			require.Equal(t, []string{"x.tf", "y.tf"}, names(entries))

			// Virtual-only directory.
			entries, err = o.ReadDir(filepath.Join(c.root, "v"))
			require.NoError(t, err)
			require.Equal(t, []string{"only.tf"}, names(entries))

			_, err = o.ReadDir(filepath.Join(c.root, "nope"))
			require.ErrorIs(t, err, fs.ErrNotExist)
		})
	}
}

func TestOverlay_ReadDirOverlayDirKeepsBaseDir(t *testing.T) {
	for _, c := range overlayCases(t) {
		t.Run(c.name, func(t *testing.T) {
			o := NewOverlay(c.base, map[string][]byte{filepath.Join(c.root, "a/sub/y.tf"): []byte("y")})
			entries, err := o.ReadDir(filepath.Join(c.root, "a"))
			require.NoError(t, err)
			require.Equal(t, []string{"main.tf", "other.tf", "sub"}, names(entries))
		})
	}
}

func TestOverlay_Glob(t *testing.T) {
	for _, c := range overlayCases(t) {
		t.Run(c.name, func(t *testing.T) {
			o := c.overlay()
			got, err := o.Glob(filepath.Join(c.root, "a", "*.tf"))
			require.NoError(t, err)
			require.Equal(t, []string{
				filepath.Join(c.root, "a/gen.tf"),
				filepath.Join(c.root, "a/main.tf"),
				filepath.Join(c.root, "a/other.tf"),
			}, got, "union, sorted, without duplicates")

			got, err = o.Glob(filepath.Join(c.root, "v", "*.tf"))
			require.NoError(t, err)
			require.Equal(t, []string{filepath.Join(c.root, "v/only.tf")}, got)

			got, err = o.Glob(filepath.Join(c.root, "a", "*.json"))
			require.NoError(t, err)
			require.Empty(t, got)

			_, err = o.Glob(filepath.Join(c.root, "a", "[*.tf"))
			require.Error(t, err)
		})
	}
}

func TestOverlay_Abs(t *testing.T) {
	m := NewMemFS(nil)
	o := NewOverlay(m, nil)
	want, _ := m.Abs("x/../y")
	got, err := o.Abs("x/../y")
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestOverlay_NilBaseIsDisk(t *testing.T) {
	o := NewOverlay(nil, nil)
	require.True(t, IsDisk(o))
}

func TestOverlay_MemFSMissesNotRecordedByOverlayReads(t *testing.T) {
	m := NewMemFS(map[string][]byte{"/ws/a.tf": []byte("a")})
	o := NewOverlay(m, map[string][]byte{"/ws/gen.tf": []byte("g")})
	_, err := o.ReadFile("/ws/gen.tf")
	require.NoError(t, err)
	_, err = o.Stat("/ws/gen.tf")
	require.NoError(t, err)
	require.Empty(t, m.MissingFiles())
	_, err = o.ReadFile("/ws/other.tf")
	require.Error(t, err)
	require.Equal(t, []string{"/ws/other.tf"}, m.MissingFiles(), "base misses still escalate")
}

type wrapperFS struct{ FS }

func (n wrapperFS) Unwrap() FS { return n.FS }

func TestUnwrapAndIsDisk(t *testing.T) {
	mem := NewMemFS(nil)
	require.Same(t, mem, Unwrap(mem))
	require.Same(t, mem, Unwrap(NewOverlay(NewOverlay(mem, nil), nil)))
	require.Equal(t, DiskFS{}, Unwrap(wrapperFS{DiskFS{}}))

	require.True(t, IsDisk(DiskFS{}))
	require.True(t, IsDisk(NewOverlay(DiskFS{}, nil)))
	require.True(t, IsDisk(NewOverlay(NewOverlay(&DiskFS{}, nil), nil)))
	require.False(t, IsDisk(mem))
	require.False(t, IsDisk(NewOverlay(mem, nil)))
}

func TestOverlay_MissingRecorderThroughUnwrap(t *testing.T) {
	mem := NewMemFS(nil)
	_, ok := Unwrap(NewOverlay(mem, nil)).(MissingRecorder)
	require.True(t, ok)
	_, ok = Unwrap(NewOverlay(DiskFS{}, nil)).(MissingRecorder)
	require.False(t, ok)
}
