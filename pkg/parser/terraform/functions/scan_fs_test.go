/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/zclconf/go-cty/cty"
)

func TestScanFSKeepsConfinementAcrossCalls(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "note.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape.txt")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "note.txt"), filepath.Join(root, "inside.txt")); err != nil {
		t.Skipf("symlink: %v", err)
	}

	scanFS := NewScanFS(vfs.DiskFS{})
	for call := range 3 {
		// Each module evaluation builds its own functions over the scan's FS.
		funcs := EvalFuncs(root, scanFS)
		if _, err := funcs["file"].Call([]cty.Value{cty.StringVal("escape.txt")}); err == nil {
			t.Fatalf("call %d: a symlink out of the module must stay rejected once resolved", call)
		}
		if _, err := funcs["fileexists"].Call([]cty.Value{cty.StringVal("escape.txt")}); err == nil {
			t.Fatalf("call %d: fileexists must reject the escaping symlink", call)
		}
		for _, name := range []string{"note.txt", "inside.txt"} {
			got, err := funcs["file"].Call([]cty.Value{cty.StringVal(name)})
			if err != nil || !got.RawEquals(cty.StringVal("hello")) {
				t.Fatalf("call %d: file(%s) = %#v, %v", call, name, got, err)
			}
		}
		exists, err := funcs["fileexists"].Call([]cty.Value{cty.StringVal("missing.txt")})
		if err != nil || !exists.RawEquals(cty.False) {
			t.Fatalf("call %d: fileexists(missing.txt) = %#v, %v", call, exists, err)
		}
	}

	scanFS.mu.Lock()
	defer scanFS.mu.Unlock()
	if len(scanFS.resolved) == 0 {
		t.Fatal("resolutions are remembered for later calls")
	}
}

func TestScanFSOverMemFSSkipsSymlinkChecks(t *testing.T) {
	t.Parallel()

	funcs := EvalFuncs("mod", NewScanFS(vfs.NewMemFS(map[string][]byte{"mod/note.txt": []byte("hello")})))
	got, err := funcs["file"].Call([]cty.Value{cty.StringVal("note.txt")})
	if err != nil || !got.RawEquals(cty.StringVal("hello")) {
		t.Fatalf("file over MemFS = %#v, %v", got, err)
	}
}
