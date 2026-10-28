/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
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

func largeJSON(entries int) string {
	var b strings.Builder
	b.WriteString(`{"entries":{`)
	for i := 0; i < entries; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"k%d":{"name":"n%d","tags":{"a":"%d"}}`, i, i, i)
	}
	b.WriteString("}}")
	return b.String()
}

// A large document is decoded once per scan: later calls, including their type
// inference, share the first result, and a small one is not remembered.
func TestScanFSDecodesLargeDocumentsOnce(t *testing.T) {
	scan := NewScanFS(vfs.DiskFS{})
	funcs := EvalFuncsWithRoot(t.TempDir(), "", scan)
	doc := largeJSON(300)
	if len(doc) < minMemoizedDecode {
		t.Fatalf("fixture is %d bytes, want at least %d", len(doc), minMemoizedDecode)
	}
	want, err := stdlib.JSONDecodeFunc.Call([]cty.Value{cty.StringVal(doc)})
	if err != nil {
		t.Fatal(err)
	}
	for call := 0; call < 3; call++ {
		got, err := funcs["jsondecode"].Call([]cty.Value{cty.StringVal(doc)})
		if err != nil {
			t.Fatalf("call %d: %v", call, err)
		}
		if !got.RawEquals(want) {
			t.Fatalf("call %d: decoded value differs from the unmemoized one", call)
		}
	}
	if n := len(scan.decodes.results); n != 1 {
		t.Fatalf("memo holds %d results after repeated calls on one document, want 1", n)
	}
	if _, err := funcs["jsondecode"].Call([]cty.Value{cty.StringVal(`{"a":1}`)}); err != nil {
		t.Fatal(err)
	}
	if n := len(scan.decodes.results); n != 1 {
		t.Fatalf("a small document was remembered: %d results", n)
	}
}

func TestScanFSDecodeMemoKeepsErrorsMarksAndFunctionsApart(t *testing.T) {
	scan := NewScanFS(vfs.DiskFS{})
	funcs := EvalFuncsWithRoot(t.TempDir(), "", scan)
	doc := largeJSON(300)
	broken := doc[:len(doc)-5]
	for call := 0; call < 2; call++ {
		if _, err := funcs["jsondecode"].Call([]cty.Value{cty.StringVal(broken)}); err == nil {
			t.Fatalf("call %d: a malformed document must keep failing", call)
		}
	}

	marked := cty.StringVal(doc).Mark("sensitive")
	for call := 0; call < 2; call++ {
		got, err := funcs["jsondecode"].Call([]cty.Value{marked})
		if err != nil {
			t.Fatal(err)
		}
		if !got.HasMark("sensitive") {
			t.Fatalf("call %d: the mark of the input must reach the result", call)
		}
	}
	plain, err := funcs["jsondecode"].Call([]cty.Value{cty.StringVal(doc)})
	if err != nil {
		t.Fatal(err)
	}
	if plain.ContainsMarked() {
		t.Fatal("a marked call must not mark the memoized value for other calls")
	}

	yamlDoc := strings.Repeat("key: value\n", 600)
	if _, err := funcs["yamldecode"].Call([]cty.Value{cty.StringVal(yamlDoc)}); err != nil {
		t.Fatal(err)
	}
	if _, err := funcs["jsondecode"].Call([]cty.Value{cty.StringVal(yamlDoc)}); err == nil {
		t.Fatal("a document remembered by yamldecode must not answer jsondecode")
	}
}

func TestDecodeMemoStopsRememberingPastItsBudget(t *testing.T) {
	var m decodeMemo
	value := cty.StringVal("v")
	per := minMemoizedDecode
	for i := 0; i < decodeMemoBudget/(per*decodeBytesPerInputByte)+10; i++ {
		m.remember(decodeKey{fn: "jsondecode", n: per, a: uint64(i)}, decoded{value: value})
	}
	if m.bytes > decodeMemoBudget {
		t.Fatalf("memo holds an estimated %d bytes, over its %d budget", m.bytes, decodeMemoBudget)
	}
	if _, ok := m.lookup(decodeKey{fn: "jsondecode", n: per, a: 0}); !ok {
		t.Fatal("the first results must stay remembered")
	}
}

// A call parses its input once for the type and once for the value. A small
// input, and one the memo does not keep, must not add another pass.
func TestMemoizeDecodeParsesUncachedInputsOnce(t *testing.T) {
	var typeN, implN int
	original := function.New(&function.Spec{
		Params: []function.Parameter{{Name: "str", Type: cty.String}},
		Type: func(args []cty.Value) (cty.Type, error) {
			typeN++
			if args[0].AsString() == "bad" {
				return cty.NilType, fmt.Errorf("bad")
			}
			return cty.String, nil
		},
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			implN++
			return cty.StringVal("ok"), nil
		},
	})
	check := func(t *testing.T, m *decodeMemo, input string, wantType, wantImpl int, wantErr bool) {
		t.Helper()
		typeN, implN = 0, 0
		_, err := m.memoizeDecode("f", original).Call([]cty.Value{cty.StringVal(input)})
		if wantErr {
			if err == nil {
				t.Fatal("expected an error")
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if typeN != wantType || implN != wantImpl {
			t.Fatalf("type calls = %d, value calls = %d, want %d and %d", typeN, implN, wantType, wantImpl)
		}
	}

	var fresh decodeMemo
	check(t, &fresh, "small", 1, 1, false)
	check(t, &fresh, "bad", 1, 0, true)

	kept := strings.Repeat("a", minMemoizedDecode)
	check(t, &fresh, kept, 1, 1, false)
	check(t, &fresh, kept, 0, 0, false)

	var full decodeMemo
	full.bytes = decodeMemoBudget
	check(t, &full, kept+"b", 1, 1, false)
	if _, ok := full.lookup(decodeKeyOf("f", kept+"b")); ok {
		t.Fatal("a result past the budget was remembered")
	}
}

func TestMemoizeDecodeKeepsUnknownPrefixType(t *testing.T) {
	scan := NewScanFS(vfs.DiskFS{})
	fn := EvalFuncsWithRoot(t.TempDir(), "", scan)["jsondecode"]
	unknown := cty.UnknownVal(cty.String).Refine().NotNull().StringPrefixFull(`"`).NewValue()
	ty, err := fn.ReturnTypeForValues([]cty.Value{unknown})
	if err != nil {
		t.Fatal(err)
	}
	if !ty.Equals(cty.String) {
		t.Fatalf("return type = %s, want string", ty.FriendlyName())
	}
	got, err := fn.Call([]cty.Value{unknown})
	if err != nil {
		t.Fatal(err)
	}
	if got.IsKnown() || !got.Type().Equals(cty.String) {
		t.Fatalf("result = %#v, want an unknown string", got)
	}
}

func TestMemoizeDecodeSharesOneInFlightDecode(t *testing.T) {
	scan := NewScanFS(vfs.DiskFS{})
	fn := EvalFuncsWithRoot(t.TempDir(), "", scan)["jsondecode"]
	doc := largeJSON(300)
	want, err := stdlib.JSONDecodeFunc.Call([]cty.Value{cty.StringVal(doc)})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errc := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := fn.Call([]cty.Value{cty.StringVal(doc)})
			if err != nil {
				errc <- err
				return
			}
			if !got.RawEquals(want) {
				errc <- fmt.Errorf("decoded value differs")
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Error(err)
	}
	if n := len(scan.decodes.results); n != 1 {
		t.Fatalf("memo holds %d results, want 1", n)
	}
}
