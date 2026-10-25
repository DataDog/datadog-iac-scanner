/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"fmt"
	"math"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	ctyyaml "github.com/zclconf/go-cty-yaml"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// scanFuncs returns the functions of a module at a fresh directory over a new
// ScanFS, and that ScanFS's memo.
func scanFuncs(t testing.TB) (map[string]function.Function, *scanMemo) {
	t.Helper()
	fsys := NewScanFS(vfs.DiskFS{})
	return EvalFuncs(t.TempDir(), fsys), fsys.memo
}

// countingJSONDecode is jsondecode counting how often it parses its input.
func countingJSONDecode(parses *atomic.Int32) function.Function {
	return function.New(&function.Spec{
		Params: stdlib.JSONDecodeFunc.Params(),
		Type: func(args []cty.Value) (cty.Type, error) {
			parses.Add(1)
			return stdlib.JSONDecodeFunc.ReturnTypeForValues(args)
		},
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			return unmarshalJSON(args[0].AsString(), retType)
		},
	})
}

func TestMemoizeDecode_KeepsAValueOnlyWhenAskedAgain(t *testing.T) {
	memo := newScanMemo()
	keptDecodes := memo.decodes.keptResults
	var parses atomic.Int32
	fn := memoizeDecode(memo, "jsondecode", countingJSONDecode(&parses), unmarshalJSON)
	input := cty.StringVal(largeJSON(200))
	if len(input.AsString()) < minMemoizedSize {
		t.Fatalf("fixture is %d bytes", len(input.AsString()))
	}

	first, err := fn.Call([]cty.Value{input})
	if err != nil {
		t.Fatal(err)
	}
	if kept := keptDecodes(); kept != 0 {
		t.Fatalf("a value used once was kept: %d entries", kept)
	}

	second, err := fn.Call([]cty.Value{input})
	if err != nil {
		t.Fatal(err)
	}
	if kept := keptDecodes(); kept != 1 {
		t.Fatalf("a value used twice was not kept: %d entries", kept)
	}
	third, err := fn.Call([]cty.Value{input})
	if err != nil {
		t.Fatal(err)
	}
	if parses.Load() != 2 {
		t.Fatalf("parsed %d times, want 2", parses.Load())
	}
	if !first.RawEquals(second) || !first.RawEquals(third) {
		t.Fatal("decodes differ")
	}

	small := cty.StringVal(largeJSON(20))
	if len(small.AsString()) >= minMemoizedSize {
		t.Fatalf("small fixture is %d bytes", len(small.AsString()))
	}
	for range 2 {
		if _, err := fn.Call([]cty.Value{small}); err != nil {
			t.Fatal(err)
		}
	}
	if kept := keptDecodes(); kept != 1 {
		t.Fatalf("a small input was kept: %d entries", kept)
	}
}

// Each ScanFS is one scan: another scan decodes again, and keeps nothing of
// an earlier one alive.
func TestMemoizeDecode_ScansDoNotShare(t *testing.T) {
	input := cty.StringVal(largeJSON(2000))
	first, firstMemo := scanFuncs(t)
	second, secondMemo := scanFuncs(t)
	for range 2 {
		callFunc(t, first["jsondecode"], input)
	}
	callFunc(t, second["jsondecode"], input)
	if firstMemo.decodes.keptResults() != 1 || secondMemo.decodes.keptResults() != 0 {
		t.Fatalf("kept %d and %d decodes, want 1 and 0",
			firstMemo.decodes.keptResults(), secondMemo.decodes.keptResults())
	}
}

func TestMemoizeDecode_AgreesWithStdlib(t *testing.T) {
	funcs, _ := scanFuncs(t)

	large := largeJSON(2000)
	inputs := []string{
		`{"a":1}`,
		`[1,2,3]`,
		`null`,
		``,
		`{"a":`,
		large,
		large[:len(large)-1],
		"\x00" + large,
	}
	for _, src := range inputs {
		args := []cty.Value{cty.StringVal(src)}
		want, wantErr := stdlib.JSONDecodeFunc.Call(args)
		for call := range 3 {
			got, gotErr := funcs["jsondecode"].Call(args)
			if (wantErr == nil) != (gotErr == nil) || (wantErr != nil && wantErr.Error() != gotErr.Error()) {
				t.Fatalf("json %q call %d: got (%v, %v), want (%v, %v)", src[:min(20, len(src))], call, got, gotErr, want, wantErr)
			}
			if wantErr == nil && !want.RawEquals(got) {
				t.Fatalf("json %q call %d differs", src[:min(20, len(src))], call)
			}
		}
	}

	yamlSrc := "k: \"" + strings.Repeat("a", minMemoizedSize) + "\"\n"
	for _, src := range []string{yamlSrc, yamlSrc + "---\nk: 1\n"} {
		args := []cty.Value{cty.StringVal(src)}
		want, wantErr := ctyyaml.YAMLDecodeFunc.Call(args)
		for call := range 3 {
			got, gotErr := funcs["yamldecode"].Call(args)
			if (wantErr == nil) != (gotErr == nil) || (wantErr != nil && wantErr.Error() != gotErr.Error()) {
				t.Fatalf("yaml call %d: got err %v, want %v", call, gotErr, wantErr)
			}
			if wantErr == nil && !want.RawEquals(got) {
				t.Fatal("yaml decode differs")
			}
		}
	}
}

// A large input's decode error is returned by Impl rather than Type. Callers
// evaluating an expression must see the same diagnostic either way.
func TestMemoizeDecode_LargeDecodeErrorSurfacesAsBefore(t *testing.T) {
	funcs, memo := scanFuncs(t)

	invalid := largeJSON(2000)
	invalid = invalid[:len(invalid)-1] + ","
	expr, diags := hclsyntax.ParseExpression([]byte(`jsondecode(v)`), "test.tf", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	evaluate := func(fn function.Function) (cty.Value, hcl.Diagnostics) {
		return expr.Value(&hcl.EvalContext{
			Variables: map[string]cty.Value{"v": cty.StringVal(invalid)},
			Functions: map[string]function.Function{"jsondecode": fn},
		})
	}
	wantVal, wantDiags := evaluate(stdlib.JSONDecodeFunc)
	if !wantDiags.HasErrors() {
		t.Fatal("fixture decodes")
	}
	for call := range 3 {
		gotVal, gotDiags := evaluate(funcs["jsondecode"])
		if len(gotDiags) != len(wantDiags) {
			t.Fatalf("call %d: %d diagnostics, want %d", call, len(gotDiags), len(wantDiags))
		}
		for i := range wantDiags {
			if gotDiags[i].Summary != wantDiags[i].Summary || gotDiags[i].Detail != wantDiags[i].Detail ||
				*gotDiags[i].Subject != *wantDiags[i].Subject {
				t.Fatalf("call %d: diagnostic %q / %q, want %q / %q",
					call, gotDiags[i].Summary, gotDiags[i].Detail, wantDiags[i].Summary, wantDiags[i].Detail)
			}
		}
		if !gotVal.RawEquals(wantVal) {
			t.Fatalf("call %d: value %#v, want %#v", call, gotVal, wantVal)
		}
	}
	if kept := memo.decodes.keptResults(); kept != 1 {
		t.Fatalf("a repeated decode error was not kept: %d entries", kept)
	}
}

func TestMemoizeDecode_KeepsJSONAndYAMLApart(t *testing.T) {
	funcs, _ := scanFuncs(t)

	// Valid YAML, not valid JSON. A shared key would return the other's result.
	for _, fill := range []string{"b", "c"} {
		args := []cty.Value{cty.StringVal("k: \"" + strings.Repeat(fill, minMemoizedSize) + "\"\n")}
		first, second := "jsondecode", "yamldecode"
		if fill == "c" {
			first, second = second, first
		}
		for range 2 {
			_, _ = funcs[first].Call(args)
		}
		for range 2 {
			_, _ = funcs[second].Call(args)
		}
		if _, err := funcs["jsondecode"].Call(args); err == nil {
			t.Fatal("jsondecode accepted YAML")
		}
		got, err := funcs["yamldecode"].Call(args)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Type().IsObjectType() {
			t.Fatalf("yamldecode type %s", got.Type().FriendlyName())
		}
	}
}

func TestMemoizeDecode_MarksStayOnTheCall(t *testing.T) {
	funcs, _ := scanFuncs(t)
	src := largeJSON(2000)
	fn := funcs["jsondecode"]
	plain, err := fn.Call([]cty.Value{cty.StringVal(src)})
	if err != nil {
		t.Fatal(err)
	}
	if plain.IsMarked() {
		t.Fatal("unmarked input returned a marked value")
	}

	marked, err := fn.Call([]cty.Value{cty.StringVal(src).Mark("sensitive")})
	if err != nil {
		t.Fatal(err)
	}
	if !marked.HasMark("sensitive") {
		t.Fatal("mark was dropped")
	}
	again, err := fn.Call([]cty.Value{cty.StringVal(src)})
	if err != nil {
		t.Fatal(err)
	}
	if again.IsMarked() {
		t.Fatal("mark leaked into a later unmarked call")
	}
	if !plain.RawEquals(again) {
		t.Fatal("unmarked value changed after a marked call")
	}

	small, err := fn.Call([]cty.Value{cty.StringVal(`{"a":1}`).Mark("sensitive")})
	if err != nil {
		t.Fatal(err)
	}
	if !small.HasMark("sensitive") {
		t.Fatal("small marked input lost its mark")
	}
}

func TestMemoizeDecode_UnknownIsNotRemembered(t *testing.T) {
	funcs, memo := scanFuncs(t)
	for range 2 {
		got, err := funcs["jsondecode"].Call([]cty.Value{cty.UnknownVal(cty.String)})
		if err != nil {
			t.Fatal(err)
		}
		if got.IsKnown() {
			t.Fatal("unknown input became known")
		}
	}
	if kept := memo.decodes.keptResults(); kept != 0 {
		t.Fatalf("remembered %d values", kept)
	}
}

// jsondecode(file(...)) passes the same string, held by the kept file result,
// on every call; the decode finds its key without hashing that string again.
func TestMemoizeDecode_AKeptFileIsNotHashedAgain(t *testing.T) {
	root := t.TempDir()
	content := largeJSON(2000)
	writeFile(t, filepath.Join(root, "config.json"), content)
	fsys := NewScanFS(vfs.DiskFS{})
	funcs := EvalFuncs(root, fsys)
	decodeFile := func() cty.Value {
		return callFunc(t, funcs["jsondecode"], callFunc(t, funcs["file"], cty.StringVal("config.json")))
	}
	want := callFunc(t, stdlib.JSONDecodeFunc, cty.StringVal(content))
	for call := range 4 {
		if got := decodeFile(); !got.RawEquals(want) {
			t.Fatalf("call %d decoded another value", call)
		}
	}
	keys := fsys.memo.keys
	keys.mu.Lock()
	identities := len(keys.keys)
	keys.mu.Unlock()
	if identities != 1 {
		t.Fatalf("%d decode keys known by identity, want 1", identities)
	}
}

// Three configurations of a few megabytes, each over the budget once decoded
// and read by every instance of a loop, are each decoded a fixed number of
// times however many instances read them.
func TestMemoizeDecode_LargeSharedConfigsAreDecodedAFixedNumberOfTimes(t *testing.T) {
	prev := debug.SetMemoryLimit(math.MaxInt64)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })
	root := t.TempDir()
	configs := []string{largeJSON(88000), largeJSON(92000), largeJSON(96000)}
	for i, content := range configs {
		if len(content) < 3<<20-200<<10 {
			t.Fatalf("config %d is %d bytes", i, len(content))
		}
		writeFile(t, filepath.Join(root, fmt.Sprintf("config%d.json", i)), content)
	}

	var mu sync.Mutex
	decodes := map[int]int{}
	counting := function.New(&function.Spec{
		Params: stdlib.JSONDecodeFunc.Params(),
		Type: func(args []cty.Value) (cty.Type, error) {
			mu.Lock()
			decodes[len(args[0].AsString())]++
			mu.Unlock()
			return stdlib.JSONDecodeFunc.ReturnTypeForValues(args)
		},
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			return unmarshalJSON(args[0].AsString(), retType)
		},
	})
	fsys := NewScanFS(vfs.DiskFS{})
	fsys.memo.decodeFuncs[fnJSONDecode] = memoizeDecode(fsys.memo, fnJSONDecode, counting, unmarshalJSON)
	funcs := EvalFuncs(root, fsys)

	first, _ := estimateDecode(decodeKey{}, valueResult{value: callFunc(t, stdlib.JSONDecodeFunc, cty.StringVal(configs[0]))})
	if first <= fsys.memo.decodes.budget {
		t.Fatalf("a decoded config is estimated at %d bytes, within the %d budget", first, fsys.memo.decodes.budget)
	}
	const instances = 50
	for range instances {
		for i := range configs {
			path := cty.StringVal(fmt.Sprintf("config%d.json", i))
			callFunc(t, funcs[fnJSONDecode], callFunc(t, funcs["file"], path))
		}
	}
	for i, content := range configs {
		if decodes[len(content)] != 2 {
			t.Errorf("config %d decoded %d times for %d instances, want 2", i, decodes[len(content)], instances)
		}
	}
}

func BenchmarkJSONDecodeOfAKeptFile(b *testing.B) {
	root := b.TempDir()
	writeFile(b, filepath.Join(root, "config.json"), largeJSON(20000))
	funcs := EvalFuncs(root, NewScanFS(vfs.DiskFS{}))
	decodeFile := func() {
		callFunc(b, funcs["jsondecode"], callFunc(b, funcs["file"], cty.StringVal("config.json")))
	}
	for range 3 {
		decodeFile()
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		decodeFile()
	}
}

func BenchmarkJSONDecodeLargeHit(b *testing.B) {
	funcs, _ := scanFuncs(b)
	input := cty.StringVal(largeJSON(20000))
	fn := funcs["jsondecode"]
	for range 2 {
		if _, err := fn.Call([]cty.Value{input}); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := fn.Call([]cty.Value{input}); err != nil {
			b.Fatal(err)
		}
	}
}
