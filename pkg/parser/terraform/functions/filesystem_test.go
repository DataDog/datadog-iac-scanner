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

func TestFileFunctionsConfined(t *testing.T) {
	t.Parallel()

	root := "mod"
	fsys := vfs.NewMemFS(map[string][]byte{
		"mod/note.txt":   []byte("hello"),
		"mod/sub/a.txt":  []byte("inner"),
		"mod/tmpl.tftpl": []byte("hi ${name}"),
		"outside/secret": []byte("nope"),
		"mod/bin.dat":    {0xff, 0xfe},
	})
	funcs := EvalFuncs(root, fsys)

	got, err := funcs["file"].Call([]cty.Value{cty.StringVal("note.txt")})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("hello")) {
		t.Fatalf("file = %#v", got)
	}

	got, err = funcs["fileexists"].Call([]cty.Value{cty.StringVal("note.txt")})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.True) {
		t.Fatalf("fileexists = %#v", got)
	}

	got, err = funcs["fileexists"].Call([]cty.Value{cty.StringVal("missing.txt")})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.False) {
		t.Fatalf("fileexists missing = %#v", got)
	}

	if _, err = funcs["file"].Call([]cty.Value{cty.StringVal("../outside/secret")}); err == nil {
		t.Fatal("file escape: expected error")
	}
	if _, err = funcs["fileexists"].Call([]cty.Value{cty.StringVal("../outside/secret")}); err == nil {
		t.Fatal("fileexists escape: expected error")
	}

	if _, err = funcs["file"].Call([]cty.Value{cty.StringVal("bin.dat")}); err == nil {
		t.Fatal("file non-utf8: expected error")
	}
	got, err = funcs["filebase64"].Call([]cty.Value{cty.StringVal("bin.dat")})
	if err != nil {
		t.Fatal(err)
	}
	if got.AsString() == "" {
		t.Fatal("filebase64 empty")
	}

	got, err = funcs["fileset"].Call([]cty.Value{cty.StringVal("."), cty.StringVal("*.txt")})
	if err != nil {
		t.Fatal(err)
	}
	if !setHas(got, "note.txt") {
		t.Fatalf("fileset *.txt = %#v", got)
	}
	if setHas(got, "sub/a.txt") {
		t.Fatalf("fileset *.txt should not include nested: %#v", got)
	}

	got, err = funcs["fileset"].Call([]cty.Value{cty.StringVal("."), cty.StringVal("**/*.txt")})
	if err != nil {
		t.Fatal(err)
	}
	if !setHas(got, "note.txt") || !setHas(got, "sub/a.txt") {
		t.Fatalf("fileset **/*.txt = %#v", got)
	}

	got, err = funcs["filemd5"].Call([]cty.Value{cty.StringVal("note.txt")})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("5d41402abc4b2a76b9719d911017c592")) {
		t.Fatalf("filemd5 = %#v", got)
	}

	got, err = funcs["templatefile"].Call([]cty.Value{
		cty.StringVal("tmpl.tftpl"),
		cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal("world")}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("hi world")) {
		t.Fatalf("templatefile = %#v", got)
	}
}

func TestConfinePath(t *testing.T) {
	t.Parallel()

	got, err := confinePath("mod", "note.txt")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.ToSlash(got) != "mod/note.txt" {
		t.Fatalf("confinePath = %q", got)
	}
	if _, err = confinePath("mod", "../outside"); err == nil {
		t.Fatal("expected escape error")
	}
	if _, err = confinePath("mod", filepath.Join(os.TempDir(), "passwd")); err == nil {
		t.Fatal("expected absolute escape error")
	}
}

func TestEvalFuncsWithoutFS(t *testing.T) {
	t.Parallel()

	if _, ok := EvalFuncs("", nil)["file"]; ok {
		t.Fatal("static map should not include file")
	}
	if _, ok := EvalFuncs("", nil)["templatestring"]; !ok {
		t.Fatal("static map should include templatestring")
	}
}

func setHas(v cty.Value, s string) bool {
	for it := v.ElementIterator(); it.Next(); {
		_, ev := it.Element()
		if ev.AsString() == s {
			return true
		}
	}
	return false
}
