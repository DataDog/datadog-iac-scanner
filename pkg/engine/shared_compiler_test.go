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
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
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

// TestInspect_SharedCompiler_Findings runs files + rules through the
// shared-compiler path and asserts the findings are the ones the rules specify.
func TestInspect_SharedCompiler_Findings(t *testing.T) {
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
	shared, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries(), "no query should fail")

	require.NotEmpty(t, shared, "the crafted file should trigger findings")
	queryIDs := make(map[string]struct{})
	for _, v := range shared {
		queryIDs[v.QueryID] = struct{}{}
	}
	require.Len(t, queryIDs, 2, "both rules should stay independently addressable and fire")
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
// review finding: a rule whose Rego reads its custom InputData must still fire.
// The shared compiler must fall back to the isolated per-query store for such
// rules instead of running them against the input-data-less base store.
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
	shared, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries(), "no query should fail")

	require.NotEmpty(t, shared, "the rule should fire when its custom InputData is present (no false negative)")
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

// TestInspect_PrefilteredAndBatchedParity checks that static rule prefiltering,
// document subsetting, and batched evaluation produce the same findings as
// unbatched evaluation across single-resource, absent-resource, cross-document,
// negated, and rule-argument queries.
func TestInspect_PrefilteredAndBatchedParity(t *testing.T) {
	root := t.TempDir()
	mainPath := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(mainPath, []byte(`
resource "aws_s3_bucket" "public" {
  acl = "public-read"
}
resource "aws_s3_bucket" "private" {
  bucket = "ok"
}
`), 0o600))
	otherPath := filepath.Join(root, "versioning.tf")
	require.NoError(t, os.WriteFile(otherPath, []byte(`
resource "aws_s3_bucket_versioning" "v" {
  bucket = "private"
}
`), 0o600))

	queries := []model.QueryMetadata{
		{
			Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
		},
		{
			Query: "versioning_rule", Content: secondRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "versioning-rule"}, Aggregation: 1,
		},
		{
			Query: "absent_rule", InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "absent-rule"}, Aggregation: 1,
			Content: `package datadog
import rego.v1
DatadogPolicy contains result if {
	some i, name
	_ := input.document[i].resource.aws_redshift_cluster[name]
	result := {"documentId": input.document[i].id, "searchKey": sprintf("aws_redshift_cluster[%s]", [name])}
}`,
		},
		{
			Query: "cross_doc_rule", InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "cross-doc-rule"}, Aggregation: 1,
			Content: `package datadog
import rego.v1
has_versioning(bucket_name) if {
	some j, vn
	v := input.document[j].resource.aws_s3_bucket_versioning[vn]
	v.bucket == bucket_name
}
DatadogPolicy contains result if {
	some i, name
	_ := input.document[i].resource.aws_s3_bucket[name]
	not has_versioning(name)
	result := {"documentId": input.document[i].id, "searchKey": sprintf("aws_s3_bucket[%s]", [name])}
}`,
		},
		{
			Query: "args_rule", InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "args-rule"}, Aggregation: 1,
			Content: `package datadog
import rego.v1
DatadogPolicy contains result if {
	some i, name
	b := input.document[i].resource.aws_s3_bucket[name]
	b.acl == input.arguments.bad_acl
	result := {"documentId": input.document[i].id, "searchKey": sprintf("aws_s3_bucket[%s].acl", [name])}
}`,
		},
	}

	files := append(parseTerraform(t, mainPath), parseTerraform(t, otherPath)...)
	ins := newTestInspector(t, inspectorOpts{
		queries:    queries,
		repoPath:   root,
		vb:         DefaultVulnerabilityBuilder,
		numWorkers: 2,
	})
	ins.ruleConfigs = map[string]config.IacRuleConfig{
		"args-rule": {Arguments: map[string]interface{}{"bad_acl": "public-read"}},
	}

	got, err := ins.Inspect(context.Background(), "batched", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	var gotIDs []string
	for _, v := range got {
		gotIDs = append(gotIDs, v.QueryID+":"+v.SearchKey)
	}
	sort.Strings(gotIDs)
	require.Equal(t, []string{
		"acl-rule:aws_s3_bucket[public].acl",
		"args-rule:aws_s3_bucket[public].acl",
		"cross-doc-rule:aws_s3_bucket[public]",
		"versioning-rule:aws_s3_bucket[private]",
		"versioning-rule:aws_s3_bucket[public]",
	}, gotIDs)
}

// TestInspect_PrefilterParityAcrossRegoConstructs verifies that prefiltered and
// batched evaluation produces the exact same findings and isolated failures as
// unfiltered single-rule evaluation across diverse Rego constructs.
func TestInspect_PrefilterParityAcrossRegoConstructs(t *testing.T) {
	// Build a 10-way, 6-level shared DAG subtree (1M paths, 7 unique maps) so
	// document indexing exercises shared-node memoization in linear time.
	dagNode := map[string]interface{}{"leaf": true}
	for range 6 {
		children := make([]interface{}, 10)
		for i := range children {
			children[i] = dagNode
		}
		dagNode = map[string]interface{}{"refs": children}
	}

	deployFile := &model.FileMetadata{
		ID: "doc-deploy", FilePath: "deploy.yaml", Kind: model.KindYAML, Platform: "kubernetes",
		OriginalData: "kind: Deployment\nmetadata:\n  name: web\nspec:\n  _flag: true\n",
		Document: model.Document{
			"kind":     "Deployment",
			"metadata": map[string]interface{}{"name": "web"},
			"spec":     map[string]interface{}{"_flag": true, "shared": dagNode},
		},
	}
	podFile := &model.FileMetadata{
		ID: "doc-pod", FilePath: "pod.yaml", Kind: model.KindYAML, Platform: "kubernetes",
		OriginalData: "kind: Pod\nmetadata:\n  name: helper\n",
		Document: model.Document{
			"kind":     "Pod",
			"metadata": map[string]interface{}{"name": "helper"},
		},
	}
	deployFile.SetLazyLines()
	podFile.SetLazyLines()

	queries := []model.QueryMetadata{
		{
			Query: "closure_cross_doc", InputData: "{}", Platform: "k8s",
			Metadata: map[string]interface{}{"id": "closure-cross-doc"}, Aggregation: 1,
			Content: `package datadog
import rego.v1
DatadogPolicy contains result if {
	some i
	d := input.document[i]
	d.kind == "Deployment"
	count([p | some i; p := input.document[i]; p.kind == "Pod"]) > 0
	result := {"documentId": d.id, "searchKey": "kind"}
}`,
		},
		{
			Query: "input_import_rule", InputData: "{}", Platform: "k8s",
			Metadata: map[string]interface{}{"id": "input-import"}, Aggregation: 1,
			Content: `package datadog
import rego.v1
import input.document as docs
DatadogPolicy contains result if {
	some i
	d := input.document[i]
	d.kind == "Pod"
	some j
	docs[j].kind == "Deployment"
	result := {"documentId": d.id, "searchKey": "kind"}
}`,
		},
		{
			Query: "with_override_rule", InputData: "{}", Platform: "k8s",
			Metadata: map[string]interface{}{"id": "with-override"}, Aggregation: 1,
			Content: `package datadog
import rego.v1
DatadogPolicy contains result if {
	some i
	d := input.document[i]
	d.kind == "Pod"
	input.document[0].kind == "Service" with input.document as [{"kind": "Service"}]
	result := {"documentId": d.id, "searchKey": "kind"}
}`,
		},
		{
			Query: "shadowed_const_rule", InputData: "{}", Platform: "k8s",
			Metadata: map[string]interface{}{"id": "shadowed-const"}, Aggregation: 1,
			Content: `package datadog
import rego.v1
kinds := {"Deployment"}
DatadogPolicy contains result if {
	kinds := {"Pod"}
	some i
	d := input.document[i]
	d.kind == kinds[_]
	result := {"documentId": d.id, "searchKey": "kind"}
}`,
		},
		{
			Query: "object_head_rule", InputData: "{}", Platform: "k8s",
			Metadata: map[string]interface{}{"id": "object-head"}, Aggregation: 1,
			Content: `package datadog
import rego.v1
kinds["Pod"] := {"Service"}
DatadogPolicy contains result if {
	some i
	d := input.document[i]
	kinds[d.kind]
	result := {"documentId": d.id, "searchKey": "kind"}
}`,
		},
		{
			Query: "underscore_alt_rule", InputData: "{}", Platform: "k8s",
			Metadata: map[string]interface{}{"id": "underscore-alt"}, Aggregation: 1,
			Content: `package datadog
import rego.v1
DatadogPolicy contains result if {
	some i
	d := input.document[i]
	key := {"foo", "_flag"}[_]
	d.spec[key] == true
	result := {"documentId": d.id, "searchKey": "spec"}
}`,
		},
		{
			Query: "malformed_decode_rule", InputData: "{}", Platform: "k8s",
			Metadata: map[string]interface{}{"id": "malformed-decode"}, Aggregation: 1,
			Content: `package datadog
import rego.v1
DatadogPolicy contains result if {
	some i
	d := input.document[i]
	d.kind == "Pod"
	result := {"documentId": d.id, "searchKey": "kind", "overrideKey": 42}
}`,
		},
	}

	run := func(coverage bool) ([]string, map[string]error) {
		files := model.FileMetadatas{deployFile.ShallowCopy(), podFile.ShallowCopy()}
		workers := 2
		if coverage {
			workers = 1
		}
		ins := newTestInspector(t, inspectorOpts{
			queries:    queries,
			vb:         DefaultVulnerabilityBuilder,
			numWorkers: workers,
		})
		if coverage {
			// Coverage mode disables prefiltering and batching, giving the baseline.
			ins.EnableCoverageReport()
		}
		vulns, err := ins.Inspect(context.Background(), "parity", files, []string{"kubernetes"})
		require.NoError(t, err)
		var ids []string
		for _, v := range vulns {
			ids = append(ids, v.QueryID+":"+v.FileID)
		}
		sort.Strings(ids)
		return ids, ins.GetFailedQueries()
	}

	baselineIDs, baselineFailed := run(true)
	optimizedIDs, optimizedFailed := run(false)
	require.Equal(t, baselineIDs, optimizedIDs)
	require.Len(t, optimizedIDs, 6)
	require.Contains(t, baselineFailed, "malformed_decode_rule")
	require.Contains(t, optimizedFailed, "malformed_decode_rule")
}
