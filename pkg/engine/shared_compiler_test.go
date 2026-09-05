/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// TestSafeCapabilities_BlocksUnsafeBuiltins is the security guard for the
// WithUnsafeBuiltins -> WithCapabilities migration: a rule referencing an unsafe
// builtin (http.send / opa.runtime) must still fail to compile under the shared
// compiler's capabilities, exactly as it did under WithUnsafeBuiltins.
func TestSafeCapabilities_BlocksUnsafeBuiltins(t *testing.T) {
	for name := range unsafeRegoFunctions {
		t.Run(name, func(t *testing.T) {
			src := "package datadog\nDatadogPolicy contains result if { result := " + name + "({}) }\n"
			mod, err := ast.ParseModuleWithOpts("rule", src, ast.ParserOptions{RegoVersion: ast.RegoV1})
			require.NoError(t, err)

			c := ast.NewCompiler().WithCapabilities(safeCapabilities())
			c.Compile(map[string]*ast.Module{"rule": mod})
			require.True(t, c.Failed(), "compile must reject the unsafe builtin %q", name)
		})
	}
}

// TestSafeCapabilities_AllowsNormalBuiltins guards the other direction: ordinary
// builtins the rules rely on (e.g. sprintf) stay available.
func TestSafeCapabilities_AllowsNormalBuiltins(t *testing.T) {
	src := "package datadog\nDatadogPolicy contains result if { result := sprintf(\"%d\", [1]) }\n"
	mod, err := ast.ParseModuleWithOpts("rule", src, ast.ParserOptions{RegoVersion: ast.RegoV1})
	require.NoError(t, err)

	c := ast.NewCompiler().WithCapabilities(safeCapabilities())
	c.Compile(map[string]*ast.Module{"rule": mod})
	require.False(t, c.Failed(), "compile must allow safe builtins: %v", c.Errors)
}

// secondRule is a second self-contained rule, distinct from aclRule, so the
// shared-compiler path must keep multiple rules independently addressable
// (the whole point of the per-rule package rename).
const secondRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	bucket := input.document[i].resource.aws_s3_bucket[name]
	not bucket.versioning

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
	}
}
`

// TestInspect_SharedCompiler runs multiple rules through the shared compiler
// and asserts the expected findings are produced.
func TestInspect_SharedCompiler(t *testing.T) {
	root := t.TempDir()
	stackDir := filepath.Join(root, "stack")
	require.NoError(t, os.MkdirAll(stackDir, 0o755))
	mainPath := filepath.Join(stackDir, "main.tf")
	require.NoError(t, os.WriteFile(mainPath, []byte(`
resource "aws_s3_bucket" "public" {
  acl = "public-read"
}

resource "aws_s3_bucket" "plain" {
  bucket = "x"
}
`), 0o644))

	queries := []model.QueryMetadata{
		{Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1},
		{Query: "versioning_rule", Content: secondRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "versioning-rule"}, Aggregation: 1},
	}

	files := parseTerraform(t, mainPath)
	ins := newTestInspector(t, inspectorOpts{
		queries:  queries,
		repoPath: root,
		vb:       DefaultVulnerabilityBuilder,
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries(), "no query should fail")
	require.NotEmpty(t, vulns, "the crafted file should trigger findings")
}

// customInputRule fires only when its result references data read from the
// query's own InputData (data.expected_acl). If shared mode were to run it
// against the per-platform base store (which lacks this rule's InputData), the
// reference would be undefined and the rule would NOT fire — exactly the
// false-negative the custom-input guard prevents.
const customInputRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.acl == data.expected_acl

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
	}
}
`

// TestInspect_SharedCompiler_CustomInputData is the regression guard for the
// review finding: a rule whose Rego reads its custom InputData must produce
// findings in shared mode. Shared mode must fall back to the per-query store
// for such rules instead of running them against the input-data-less base store.
func TestInspect_SharedCompiler_CustomInputData(t *testing.T) {
	root := t.TempDir()
	mainPath := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(mainPath, []byte(`
resource "aws_s3_bucket" "b" {
  acl = "public-read"
}
`), 0o644))

	// The rule fires only if data.expected_acl == "public-read", which lives in
	// the rule's InputData (not in any library or base store).
	queries := []model.QueryMetadata{
		{Query: "custom_input_rule", Content: customInputRule, InputData: `{"expected_acl":"public-read"}`,
			Platform: "terraform", Metadata: map[string]interface{}{"id": "custom-input-rule"}, Aggregation: 1},
	}

	files := parseTerraform(t, mainPath)
	ins := newTestInspector(t, inspectorOpts{
		queries:  queries,
		repoPath: root,
		vb:       DefaultVulnerabilityBuilder,
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries(), "no query should fail")
	require.NotEmpty(t, vulns, "the rule should fire when its custom InputData is present")
}

// TestLoadSharedQueries_ExcludesCustomInput pins the guard directly: a rule with
// custom InputData must NOT be prepared by the shared compiler (it would use the
// input-data-less base store); it must be absent from the returned map so the
// worker falls back to the isolated LoadQuery. A static-input rule alongside it
// must still be served from the shared compiler.
func TestLoadSharedQueries_ExcludesCustomInput(t *testing.T) {
	platform := "terraform"
	static := staticQuery(platform, "static_rule", "DatadogPolicy contains result if { result := \"x\" }\n")
	custom := staticQuery(platform, "custom_rule", "DatadogPolicy contains result if { result := \"y\" }\n")
	custom.InputData = `{"expected_acl":"public-read"}`

	loader := newCacheTestLoader(t, platform, []model.QueryMetadata{static, custom})
	stores, _ := baseStoresFor(platform, "{}")

	shared := loader.loadSharedQueries(context.Background(), []model.QueryMetadata{static, custom}, stores)

	if _, ok := shared[0]; !ok {
		t.Errorf("static-input rule (index 0) should be served from the shared compiler")
	}
	if _, ok := shared[1]; ok {
		t.Errorf("custom-input rule (index 1) must be excluded from shared compilation so it falls back to isolated LoadQuery")
	}
}

func clearSharedPreparedQueryCache() {
	sharedPreparedQueryCache.Lock()
	sharedPreparedQueryCache.key = 0
	sharedPreparedQueryCache.queries = nil
	sharedPreparedQueryCache.Unlock()
}

type observedDoneContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *observedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func TestLoadSharedQueriesCache_ReusesAndInvalidates(t *testing.T) {
	clearSharedPreparedQueryCache()

	platform := "terraform"
	query := staticQuery(platform, "static_rule", "DatadogPolicy contains result if { result := \"x\" }\n")
	loader := newCacheTestLoader(t, platform, []model.QueryMetadata{query})
	stores, hashes := baseStoresFor(platform, "{}")

	first, hit, err := loader.loadSharedQueriesCached(t.Context(), []model.QueryMetadata{query}, stores, hashes)
	require.NoError(t, err)
	require.False(t, hit)
	require.Contains(t, first, 0)
	second, hit, err := loader.loadSharedQueriesCached(t.Context(), []model.QueryMetadata{query}, stores, hashes)
	require.NoError(t, err)
	require.True(t, hit)
	require.Same(t, first[0], second[0])

	changedStores, changedHashes := baseStoresFor(platform, `{"library_version":2}`)
	third, hit, err := loader.loadSharedQueriesCached(
		t.Context(), []model.QueryMetadata{query}, changedStores, changedHashes)
	require.NoError(t, err)
	require.False(t, hit)
	require.Contains(t, third, 0)
	require.NotSame(t, first[0], third[0])
	fourth, hit, err := loader.loadSharedQueriesCached(
		t.Context(), []model.QueryMetadata{query}, changedStores, changedHashes)
	require.NoError(t, err)
	require.True(t, hit)
	require.Same(t, third[0], fourth[0])
}

func TestLoadSharedQueriesCache_ConcurrentReuse(t *testing.T) {
	clearSharedPreparedQueryCache()

	platform := "terraform"
	query := staticQuery(platform, "static_rule", "DatadogPolicy contains result if { result := \"x\" }\n")
	loader := newCacheTestLoader(t, platform, []model.QueryMetadata{query})
	stores, hashes := baseStoresFor(platform, "{}")

	const workers = 8
	start := make(chan struct{})
	type workerResult struct {
		prepared *rego.PreparedEvalQuery
		err      error
	}
	results := make(chan workerResult, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			prepared, _, err := loader.loadSharedQueriesCached(
				t.Context(), []model.QueryMetadata{query}, stores, hashes)
			results <- workerResult{prepared: prepared[0], err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var first *rego.PreparedEvalQuery
	for result := range results {
		require.NoError(t, result.err)
		require.NotNil(t, result.prepared)
		if first == nil {
			first = result.prepared
			continue
		}
		require.Same(t, first, result.prepared)
	}
}

func TestLoadSharedQueriesCache_CanceledWaiterReturns(t *testing.T) {
	clearSharedPreparedQueryCache()

	platform := "terraform"
	query := staticQuery(platform, "static_rule", "DatadogPolicy contains result if { result := \"x\" }\n")
	loader := newCacheTestLoader(t, platform, []model.QueryMetadata{query})
	stores, hashes := baseStoresFor(platform, "{}")
	key := sharedCacheKey([]model.QueryMetadata{query}, loader.platformKeyBases, hashes)

	started := make(chan struct{})
	release := make(chan struct{})
	flightDone := make(chan struct{})
	go func() {
		defer close(flightDone)
		_, _, _ = sharedPreparedQueryCache.flight.Do(strconv.FormatUint(key, 16), func() (any, error) {
			close(started)
			<-release
			return sharedQueryCacheResult{queries: map[int]*rego.PreparedEvalQuery{}}, nil
		})
	}()
	<-started

	baseCtx, cancel := context.WithCancel(t.Context())
	ctx := &observedDoneContext{Context: baseCtx, observed: make(chan struct{})}
	returned := make(chan error, 1)
	go func() {
		_, _, err := loader.loadSharedQueriesCached(ctx, []model.QueryMetadata{query}, stores, hashes)
		returned <- err
	}()
	<-ctx.observed
	cancel()

	var waiterErr error
	timedOut := false
	select {
	case waiterErr = <-returned:
	case <-time.After(time.Second):
		timedOut = true
	}
	close(release)
	<-flightDone

	require.False(t, timedOut, "canceled waiter remained blocked on the shared compilation")
	require.ErrorIs(t, waiterErr, context.Canceled)
}

func TestLoadSharedQueriesCache_ActiveWaiterRetriesCanceledLeader(t *testing.T) {
	clearSharedPreparedQueryCache()

	platform := "terraform"
	query := staticQuery(platform, "static_rule", "DatadogPolicy contains result if { result := \"x\" }\n")
	loader := newCacheTestLoader(t, platform, []model.QueryMetadata{query})
	stores, hashes := baseStoresFor(platform, "{}")
	key := sharedCacheKey([]model.QueryMetadata{query}, loader.platformKeyBases, hashes)

	started := make(chan struct{})
	release := make(chan struct{})
	flightDone := make(chan struct{})
	go func() {
		defer close(flightDone)
		_, _, _ = sharedPreparedQueryCache.flight.Do(strconv.FormatUint(key, 16), func() (any, error) {
			close(started)
			<-release
			return nil, context.Canceled
		})
	}()
	<-started

	type cacheResult struct {
		prepared map[int]*rego.PreparedEvalQuery
		err      error
	}
	ctx := &observedDoneContext{Context: t.Context(), observed: make(chan struct{})}
	returned := make(chan cacheResult, 1)
	go func() {
		prepared, _, err := loader.loadSharedQueriesCached(
			ctx, []model.QueryMetadata{query}, stores, hashes)
		returned <- cacheResult{prepared: prepared, err: err}
	}()
	<-ctx.observed
	close(release)
	<-flightDone

	select {
	case result := <-returned:
		require.NoError(t, result.err)
		require.Contains(t, result.prepared, 0)
	case <-time.After(time.Second):
		t.Fatal("active waiter did not retry after its singleflight leader was canceled")
	}
}
