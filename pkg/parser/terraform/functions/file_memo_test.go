/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

func TestFileMemo_SharesOneReadAcrossModuleEvaluations(t *testing.T) {
	root := t.TempDir()
	content := largeJSON(2000)
	writeFile(t, filepath.Join(root, "mod", "config.json"), content)
	fsys := NewScanFS(vfs.DiskFS{})

	var got []cty.Value
	for range 3 {
		// Each module instance builds its own functions over the scan's FS.
		funcs := EvalFuncsWithRoot(filepath.Join(root, "mod"), root, fsys)
		got = append(got, callFunc(t, funcs["file"], cty.StringVal("config.json")))
	}
	for i, v := range got {
		if v.AsString() != content {
			t.Fatalf("call %d returned other content", i)
		}
	}
	if unsafe.StringData(got[1].AsString()) != unsafe.StringData(got[2].AsString()) {
		t.Fatal("a file read again was not shared")
	}
	if kept := fsys.memo.files.keptResults(); kept != 1 {
		t.Fatalf("kept %d file results, want 1", kept)
	}
}

func TestFileMemo_SmallFilesAreReadAgain(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "hello")
	fsys := NewScanFS(vfs.DiskFS{})
	funcs := EvalFuncs(root, fsys)
	for range 3 {
		callFunc(t, funcs["file"], cty.StringVal("a.txt"))
	}
	if kept := fsys.memo.files.keptResults(); kept != 0 {
		t.Fatalf("kept %d results of a small file", kept)
	}
}

// A ScanFS is one scan, during which files do not change; the next scan reads
// a file again.
func TestFileMemo_ANewScanReadsAReplacedFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.txt")
	first, second := strings.Repeat("1", minMemoizedSize), strings.Repeat("2", minMemoizedSize)
	writeFile(t, path, first)
	read := func(fsys *ScanFS) string {
		return callFunc(t, EvalFuncs(root, fsys)["file"], cty.StringVal("a.txt")).AsString()
	}
	scan := NewScanFS(vfs.DiskFS{})
	for range 2 {
		read(scan)
	}
	writeFile(t, path, second)
	if read(scan) != first {
		t.Fatal("a scan read a file again after keeping it")
	}
	if read(NewScanFS(vfs.DiskFS{})) != second {
		t.Fatal("a new scan returned what an earlier scan read")
	}
}

func TestFileMemo_KeepsModuleFilesApart(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"a", "b"} {
		writeFile(t, filepath.Join(root, dir, "config.json"), dir+strings.Repeat(" ", minMemoizedSize))
	}
	fsys := NewScanFS(vfs.DiskFS{})
	for range 3 {
		for _, dir := range []string{"a", "b"} {
			funcs := EvalFuncsWithRoot(filepath.Join(root, dir), root, fsys)
			if got := callFunc(t, funcs["file"], cty.StringVal("config.json")).AsString(); !strings.HasPrefix(got, dir+" ") {
				t.Fatalf("module %s read %q", dir, got[:2])
			}
		}
	}
}

func TestFileMemo_LinksToOneFileShareItsResult(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "config.json"), largeJSON(2000))
	if err := os.Symlink("config.json", filepath.Join(root, "link.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	fsys := NewScanFS(vfs.DiskFS{})
	funcs := EvalFuncs(root, fsys)
	for _, name := range []string{"config.json", "link.json", "config.json", "link.json"} {
		callFunc(t, funcs["file"], cty.StringVal(name))
	}
	if kept := fsys.memo.files.keptResults(); kept != 1 {
		t.Fatalf("kept %d results for one file and a link to it, want 1", kept)
	}
}

// Every file function keeps its own result of a file: file, filebase64 and a
// hash of the same path must not answer for one another.
func TestFileMemo_AgreesWithAFreshRead(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "text.txt"), largeJSON(2000))
	writeFile(t, filepath.Join(root, "bin.dat"), "\xff\xfe"+strings.Repeat("x", minMemoizedSize))
	writeFile(t, filepath.Join(root, "t.tftpl"), "hi ${name}, %{ for p in ports }${p} %{ endfor }"+strings.Repeat(" ", minMemoizedSize))
	writeFile(t, filepath.Join(root, "lit.tftpl"), "no variables"+strings.Repeat(" ", minMemoizedSize))
	writeFile(t, filepath.Join(root, "bad.tftpl"), "hi ${"+strings.Repeat(" ", minMemoizedSize))
	type call struct {
		fn   string
		args []cty.Value
	}
	vars := func(name string) cty.Value {
		return cty.ObjectVal(map[string]cty.Value{
			"name":  cty.StringVal(name),
			"ports": cty.TupleVal([]cty.Value{cty.NumberIntVal(1), cty.NumberIntVal(2)}),
		})
	}
	var calls []call
	for _, path := range []string{"text.txt", "./text.txt", "bin.dat", "./bin.dat", "missing.txt", "../escape"} {
		for _, fn := range []string{"file", "filebase64", "filemd5", "filesha1", "filesha256", "filesha512", "filebase64sha256", "filebase64sha512"} {
			calls = append(calls, call{fn, []cty.Value{cty.StringVal(path)}})
		}
	}
	for _, path := range []string{"t.tftpl", "lit.tftpl", "bad.tftpl", "bin.dat", "missing.tftpl"} {
		calls = append(calls, call{"templatefile", []cty.Value{cty.StringVal(path), vars("a")}})
		calls = append(calls, call{"templatefile", []cty.Value{cty.StringVal(path), vars("b")}})
		calls = append(calls, call{"templatefile", []cty.Value{cty.StringVal(path), cty.StringVal("not an object")}})
	}

	type result struct {
		value cty.Value
		err   string
	}
	run := func(funcs map[string]function.Function) []result {
		out := make([]result, len(calls))
		for i, c := range calls {
			v, err := funcs[c.fn].Call(c.args)
			out[i].value = v
			if err != nil {
				out[i].err = err.Error()
			}
		}
		return out
	}

	want := run(EvalFuncs(root, vfs.DiskFS{}))
	fsys := NewScanFS(vfs.DiskFS{})
	for round := range 3 {
		got := run(EvalFuncs(root, fsys))
		for i, c := range calls {
			if got[i].err != want[i].err || (want[i].err == "" && !got[i].value.RawEquals(want[i].value)) {
				t.Fatalf("round %d: %s(%#v) = (%#v, %q), want (%#v, %q)",
					round, c.fn, c.args[0], got[i].value, got[i].err, want[i].value, want[i].err)
			}
		}
	}
	if fsys.memo.files.keptResults() == 0 {
		t.Fatal("nothing was kept")
	}
}

// A pushed file is read once, and a file that was not pushed is still
// reported missing.
func TestFileMemo_MemFS(t *testing.T) {
	content := largeJSON(2000)
	mem := vfs.NewMemFS(map[string][]byte{"mod/config.json": []byte(content)})
	fsys := NewScanFS(mem)
	funcs := EvalFuncs("mod", fsys)
	for range 3 {
		if got := callFunc(t, funcs["file"], cty.StringVal("config.json")); got.AsString() != content {
			t.Fatal("file over MemFS returned other content")
		}
		if _, err := funcs["file"].Call([]cty.Value{cty.StringVal("absent.json")}); err == nil {
			t.Fatal("a file that was not pushed was read")
		}
	}
	if kept := fsys.memo.files.keptResults(); kept != 2 {
		t.Fatalf("kept %d results over MemFS, want the content and the miss", kept)
	}
	if missing := mem.MissingFiles(); len(missing) != 1 || missing[0] != "mod/absent.json" {
		t.Fatalf("missing files %v", missing)
	}
}

func largeJSON(entries int) string {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < entries; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"k%05d":{"n":%d,"s":"abcdefghij"}`, i, i)
	}
	b.WriteByte('}')
	return b.String()
}

func writeFile(t testing.TB, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func callFunc(t testing.TB, fn function.Function, args ...cty.Value) cty.Value {
	t.Helper()
	got, err := fn.Call(args)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (m *resultMemo[K, R]) keptResults() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

func (m *resultMemo[K, R]) stored(key K) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.entries[key]
	return ok
}

// sizedMemo keeps ints, each estimated at its own value, with an allowance
// of four times its budget for larger results.
func sizedMemo(budget int) *resultMemo[string, int] {
	return sizedMemoSharing(budget, &allowance{size: 4 * budget})
}

func sizedMemoSharing(budget int, large *allowance) *resultMemo[string, int] {
	return newResultMemo(budget, large, func(_ string, size int) (int, bool) { return size, size > 0 })
}

func computeTwice(m *resultMemo[string, int], key string, size int) int {
	calls := 0
	for range 2 {
		m.lookupOrCompute(key, func() int {
			calls++
			return size
		})
	}
	return calls
}

func TestResultMemo_KeepsAResultOnlyWhenAskedAgain(t *testing.T) {
	m := sizedMemo(100)
	calls := 0
	compute := func() int {
		calls++
		return 10
	}
	m.lookupOrCompute("a", compute)
	if m.stored("a") {
		t.Fatal("a result used once was kept")
	}
	for range 3 {
		m.lookupOrCompute("a", compute)
	}
	if calls != 2 || !m.stored("a") {
		t.Fatalf("computed %d times, kept=%v; want 2 and kept", calls, m.stored("a"))
	}
	if computeTwice(m, "small", 0); m.stored("small") {
		t.Fatal("a result not worth keeping was kept")
	}
}

func TestResultMemo_KeepsLargeResultsUpToTheAllowance(t *testing.T) {
	m := sizedMemo(100)
	estimates := 0
	estimate := m.estimate
	m.estimate = func(k string, size int) (int, bool) {
		estimates++
		return estimate(k, size)
	}
	for i := range 3 {
		computeTwice(m, fmt.Sprint("fits", i), 30)
	}
	// Each over what is left of the budget, together within the allowance.
	for i, size := range []int{150, 200} {
		if computeTwice(m, fmt.Sprint("large", i), size); !m.stored(fmt.Sprint("large", i)) {
			t.Fatalf("large result %d was not kept", i)
		}
	}
	computeTwice(m, "past the cap", 100)
	if m.stored("past the cap") {
		t.Fatal("a result past both the budget and the allowance was kept")
	}
	measured := estimates
	if got := computeTwice(m, "past the cap", 100); got != 2 || estimates != measured {
		t.Fatalf("a rejected result was computed %d times and measured %d more times; want 2 and 0",
			got, estimates-measured)
	}
	for i := range 3 {
		if !m.stored(fmt.Sprint("fits", i)) {
			t.Fatalf("result %d within the budget was given up", i)
		}
	}
	if m.size > m.budget || m.large.used > m.large.size {
		t.Fatalf("kept %d bytes within the %d budget and %d within the %d allowance", m.size, m.budget, m.large.used, m.large.size)
	}
}

// The memos of one ScanFS draw their large results from one allowance, so
// together they keep no more than it.
func TestResultMemo_MemosShareOneAllowance(t *testing.T) {
	large := &allowance{size: 300}
	one, other := sizedMemoSharing(100, large), sizedMemoSharing(100, large)
	if computeTwice(one, "first", 200); !one.stored("first") {
		t.Fatal("a large result within the allowance was not kept")
	}
	if computeTwice(other, "second", 200); other.stored("second") {
		t.Fatal("a large result was kept past what the other memo left of the shared allowance")
	}
	if computeTwice(other, "smaller", 100); !other.stored("smaller") {
		t.Fatal("a result within its memo's own budget was not kept")
	}
}

func TestResultMemo_ConcurrentCallersComputeOnce(t *testing.T) {
	m := sizedMemo(100)
	var calls atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := m.lookupOrCompute("k", func() int {
				calls.Add(1)
				<-release
				return 7
			})
			if got != 7 {
				t.Errorf("got %d", got)
			}
			if !m.stored("k") {
				t.Error("a caller returned before the result was kept")
			}
		}()
	}
	for {
		m.mu.Lock()
		p := m.pending["k"]
		waiting := p != nil && p.waiters == 7
		m.mu.Unlock()
		if waiting {
			break
		}
		runtime.Gosched()
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("computed %d times", calls.Load())
	}
	if !m.stored("k") {
		t.Fatal("a result waited on by other callers was not kept")
	}
}

// A computation that panics leaves its waiters to compute on their own.
func TestResultMemo_WaitersOfAPanickedComputationComputeAgain(t *testing.T) {
	m := sizedMemo(100)
	started, release := make(chan struct{}), make(chan struct{})
	go func() {
		defer func() { _ = recover() }()
		m.lookupOrCompute("k", func() int {
			close(started)
			<-release
			panic("compute failed")
		})
	}()
	<-started
	done := make(chan int)
	go func() { done <- m.lookupOrCompute("k", func() int { return 3 }) }()
	for {
		m.mu.Lock()
		waiting := m.pending["k"] != nil && m.pending["k"].waiters == 1
		m.mu.Unlock()
		if waiting {
			break
		}
		runtime.Gosched()
	}
	close(release)
	if got := <-done; got != 3 {
		t.Fatalf("waiter got %d", got)
	}
}

func TestResultMemo_SeenKeysAreBounded(t *testing.T) {
	m := sizedMemo(1 << 30)
	for i := range maxSeen + 10 {
		m.lookupOrCompute(fmt.Sprint(i), func() int { return 1 })
	}
	if len(m.seen) != 10 {
		t.Fatalf("remembered %d keys, want the 10 since the record started over", len(m.seen))
	}
	if m.lookupOrCompute("0", func() int { return 1 }); m.stored("0") {
		t.Fatal("a key forgotten when the record started over was kept on its next call")
	}
	if computeTwice(m, "unseen", 1); !m.stored("unseen") {
		t.Fatal("a key asked for twice after the record started over was not kept")
	}
}

func TestScanBudget_ScalesWithTheMemoryLimit(t *testing.T) {
	prev := debug.SetMemoryLimit(math.MaxInt64)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })
	for _, tc := range []struct {
		limit int64
		want  int
	}{
		{math.MaxInt64, defaultScanBudget},
		{512 << 20, minScanBudget},
		{4 << 30, 1 << 30},
		{64 << 30, maxScanBudget},
	} {
		debug.SetMemoryLimit(tc.limit)
		if got := scanBudget(); got != tc.want {
			t.Errorf("memory limit %d: budget %d, want %d", tc.limit, got, tc.want)
		}
	}
}
