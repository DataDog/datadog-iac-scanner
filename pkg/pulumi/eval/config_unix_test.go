//go:build !windows

/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSourceIndexSkipsSymlinks(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero")
	}
	dir, outside := t.TempDir(), t.TempDir()
	writeFiles(t, dir, map[string]string{"__main__.py": `cfg.require_int("count")`})
	big := filepath.Join(outside, "big.py")
	require.NoError(t, os.WriteFile(big, make([]byte, maxIndexedBytes+1), 0o600))
	for name, target := range map[string]string{"zero.py": "/dev/zero", "big.py": big} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Skipf("symbolic links are not supported: %v", err)
		}
	}

	done := make(chan *sourceIndex, 1)
	go func() { done <- newSourceIndex(dir) }()
	var idx *sourceIndex
	select {
	case idx = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("newSourceIndex did not return")
	}
	assert.Equal(t, []string{filepath.Join(dir, "__main__.py")}, indexedPaths(idx), "symbolic links are not indexed")

	_, ok := readIndexedFile("/dev/zero")
	assert.False(t, ok, "reads are bounded")
}

func indexedPaths(idx *sourceIndex) []string {
	out := make([]string, 0, len(idx.files))
	for k := range idx.files {
		out = append(out, k)
	}
	return out
}
