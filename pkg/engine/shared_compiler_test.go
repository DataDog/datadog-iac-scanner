/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/contractlibs"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
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

func TestLegacyCompileOnlyInjectsReferencedContractLibraries(t *testing.T) {
	parse := func(name, content string) *ast.Module {
		t.Helper()
		module, err := ast.ParseModuleWithOpts(name, content, ast.ParserOptions{RegoVersion: ast.RegoV1})
		require.NoError(t, err)
		return module
	}

	libraries, err := contractlibs.Modules()
	require.NoError(t, err)
	outputRule := parse("legacy", `package datadog
import rego.v1
output := true
DatadogPolicy contains result if { result := {"ok": true} }
`)
	used := contractLibrariesUsedByModule(outputRule, libraries)
	require.Empty(t, used, "a legacy rule with no Contract v2 references must not receive Contract v2 packages")

	outputConsumer := parse("legacy", `package datadog
import rego.v1
import data.datadog.output as dd_output
DatadogPolicy contains result if { result := dd_output.format({}, {}) }
`)
	used = contractLibrariesUsedByModule(outputConsumer, libraries)
	require.Len(t, used, 1)
	require.Contains(t, used, "datadog_output.rego")

	common := source.RegoLibraries{LibraryCode: "package generic.common\n", LibraryInputData: "{}"}
	platform := source.RegoLibraries{
		LibraryCode:      "package generic.terraform\n# source refers to data.datadog.iac in v2\n",
		LibraryInputData: "{}",
	}
	parsedCommon := parse("Common", common.LibraryCode)
	parsedGeneric := parse("Generic", platform.LibraryCode)
	loader := &QueryLoader{
		commonLibrary:     common,
		platformLibraries: map[string]source.RegoLibraries{"terraform": platform},
		parsedCommon:      parsedCommon,
		parsedGeneric:     map[string]*ast.Module{"terraform": parsedGeneric},
		contractLibraries: map[string]map[string]*ast.Module{"terraform": libraries},
	}
	query := model.QueryMetadata{
		Query:    "legacy-output-rule",
		Platform: "terraform",
		Content:  outputRule.String(),
	}
	_, err = loader.LoadQuery(context.Background(), &query, nil, nil, nil, false)
	require.NoError(t, err, "isolated legacy compile must not collide with data.datadog.output")

	renamed := parse("legacy", pkgDatadogDecl.ReplaceAllString(query.Content, "package datadog.q0"))
	sharedModules, queryPath := loader.buildSharedPlatformModules(
		context.Background(), "terraform", platform, []int{0}, []model.QueryMetadata{query},
		[]ruleExecPlan{{mod: renamed}},
	)
	require.Len(t, queryPath, 1)
	for name, module := range sharedModules {
		if module != nil {
			require.NotContains(t, []string{"datadog_output.rego", "datadog_iac.rego", "datadog_terraform.rego"}, name)
		}
	}
	compiler := ast.NewCompiler().WithCapabilities(safeCapabilities())
	compiler.Compile(sharedModules)
	require.False(t, compiler.Failed(), "%v", compiler.Errors)
}

func TestContractV2SelectPlatformLibraries(t *testing.T) {
	parse := func(name, source string) *ast.Module {
		t.Helper()
		module, err := ast.ParseModuleWithOpts(name, source, ast.ParserOptions{RegoVersion: ast.RegoV1})
		require.NoError(t, err)
		return module
	}
	common := parse("Common", `package generic.common
import rego.v1
helper := true
`)
	generic := parse("Generic", `package generic.terraform
import rego.v1
import data.generic.common as common_lib
helper := common_lib.helper
`)

	for _, tc := range []struct {
		name        string
		root        string
		wantCommon  bool
		wantGeneric bool
	}{
		{
			name: "facades only",
			root: `package datadog
import rego.v1
results contains result if { result := {"ok": true} }
`,
		},
		{
			name: "direct common dependency",
			root: `package datadog
import rego.v1
import data.generic.common as common_lib
results contains result if { result := common_lib.helper }
`,
			wantCommon: true,
		},
		{
			name: "generic dependency retains its common dependency",
			root: `package datadog
import rego.v1
import data.generic.terraform as tf
results contains result if { result := tf.helper }
`,
			wantCommon:  true,
			wantGeneric: true,
		},
		{
			name: "dynamic data references retain both libraries",
			root: `package datadog
import rego.v1
results contains result if {
  value := data[input.library]
  result := value
}
`,
			wantCommon:  true,
			wantGeneric: true,
		},
		{
			name: "bare data references retain both libraries",
			root: `package datadog
import rego.v1
results contains result if { result := data }
`,
			wantCommon:  true,
			wantGeneric: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := parse("Rule", tc.root)
			gotCommon, gotGeneric := contractV2SelectPlatformLibraries([]*ast.Module{root}, common, generic)
			assert.Equal(t, tc.wantCommon, gotCommon)
			assert.Equal(t, tc.wantGeneric, gotGeneric)
		})
	}
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
func TestContractV2SharedCompilerNamespacesAndRemediation(t *testing.T) {
	queries := []model.QueryMetadata{
		staticQuery("terraform", "v2-first", `import rego.v1
allow if { true }
results contains {"_dd_id": "first", "path": []} if { allow }
remediate(_, _) := {"remediation": "first-fix", "remediationType": "addition"}
`),
		staticQuery("terraform", "v2-second", `import rego.v1
allow if { true }
results contains {"_dd_id": "second", "path": []} if { allow }
remediate(_, _) := {"remediation": "second-fix", "remediationType": "replacement"}
`),
	}
	loader := newCacheTestLoader(t, "terraform", queries)
	inspector := &Inspector{QueryLoader: loader}
	libs, err := contractlibs.Modules()
	require.NoError(t, err)
	stores, _ := baseStoresFor("terraform", "{}")

	groups := make(map[string][]contractV2SharedSpec)
	for i := range queries {
		module, shareable := contractV2ModuleForSharedCompiler(&queries[i], i)
		require.True(t, shareable)
		groups[queries[i].Platform] = append(groups[queries[i].Platform], contractV2SharedSpec{
			index: i, module: module, hasRemediate: true,
		})
	}
	prepared, err := inspector.compileSharedContractV2Rules(t.Context(), groups, libs, stores)
	require.NoError(t, err)
	require.Len(t, prepared, 2)

	for i, want := range []string{"first", "second"} {
		entry := prepared[i]
		require.NotNil(t, entry.results)
		results, err := entry.results.Eval(t.Context())
		require.NoError(t, err)
		require.Len(t, results, 1)
		values, ok := results[0].Bindings["result"].([]any)
		require.True(t, ok, "partial set result should be an array")
		require.Len(t, values, 1)
		finding, ok := values[0].(map[string]any)
		require.True(t, ok)
		require.Equal(t, want, finding["_dd_id"], "each entrypoint must use its own rule package")

		require.NotNil(t, entry.remediate)
		remediation, err := entry.remediate.Eval(t.Context(), rego.EvalInput(map[string]any{
			"resource": map[string]any{},
			"finding":  map[string]any{},
		}))
		require.NoError(t, err)
		require.Len(t, remediation, 1)
		remediationValue, ok := remediation[0].Bindings["out"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, want+"-fix", remediationValue["remediation"])
	}
}

func TestContractV2SharedCompilerRenamePreservesRawStringLiterals(t *testing.T) {
	query := staticQuery("terraform", "v2-raw-string", "import rego.v1\n"+
		"message := `first\npackage datadog\nlast`\n"+
		"results contains {\"_dd_id\": \"literal\", \"path\": []} if { message == \"first\\npackage datadog\\nlast\" }\n")
	module, ok := contractV2ModuleForSharedCompiler(&query, 7)
	require.True(t, ok)
	require.Equal(t, "data.datadog.q7", module.Package.Path.String())
	require.Contains(t, module.String(), `package datadog\nlast`,
		"the normalized raw string should retain its original package-like line")

	loader := newCacheTestLoader(t, "terraform", []model.QueryMetadata{query})
	inspector := &Inspector{QueryLoader: loader}
	spec, recognized := analyzeContractV2Rule(&query)
	require.True(t, recognized)
	stores, hashes := baseStoresFor("terraform", "{}")
	ready, err := inspector.compileContractV2Rules(t.Context(), []*contractV2Rule{spec}, stores, hashes)
	require.NoError(t, err)
	require.Len(t, ready, 1)
	results, err := ready[0].prepared.Eval(t.Context())
	require.NoError(t, err)
	require.Len(t, results, 1)
	items := results[0].Bindings["result"].([]any)
	require.Len(t, items, 1, "the literal remains intact and the renamed module remains evaluable")
}

func TestContractV2SharedCompilerRejectsNamespaceInspection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		content   string
		shareable bool
	}{
		{
			name: "engine facade import",
			content: `package datadog
import rego.v1
import data.datadog.iac
results contains {"_dd_id": "x", "path": []} if { iac.is_known({}, []) }
`,
			shareable: true,
		},
		{
			name: "sibling package reference",
			content: `package datadog
import rego.v1
results contains {"_dd_id": "x", "path": []} if { data.datadog.q1.results }
`,
		},
		{
			name: "root namespace import",
			content: `package datadog
import rego.v1
import data.datadog as dd
results contains {"_dd_id": "x", "path": []} if { dd.iac }
`,
		},
		{
			name: "bare data value",
			content: `package datadog
import rego.v1
results contains {"_dd_id": "x", "path": []} if { object.get(data, "datadog", {}) != {} }
`,
		},
		{
			name: "dynamic data root",
			content: `package datadog
import rego.v1
results contains {"_dd_id": "x", "path": []} if {
	some key in ["datadog"]
	ns := data[key]
	ns != {}
}
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mod, err := ast.ParseModuleWithOpts(tc.name, tc.content, ast.ParserOptions{RegoVersion: ast.RegoV1})
			require.NoError(t, err)
			assert.Equal(t, tc.shareable, contractV2ModuleCanShare(mod))
		})
	}
}

func TestContractV2SharedCompilerFallsBackForSelfNamespaceReferences(t *testing.T) {
	query := staticQuery("terraform", "v2-self-reference", `import rego.v1
local if { true }
results contains {"_dd_id": "self", "path": []} if { data.datadog.local }
`)
	module, shareable := contractV2ModuleForSharedCompiler(&query, 0)
	require.Nil(t, module)
	require.False(t, shareable)

	loader := newCacheTestLoader(t, "terraform", []model.QueryMetadata{query})
	inspector := &Inspector{QueryLoader: loader}
	spec, ok := analyzeContractV2Rule(&query)
	require.True(t, ok)
	stores, hashes := baseStoresFor("terraform", "{}")
	ready, err := inspector.compileContractV2Rules(t.Context(), []*contractV2Rule{spec}, stores, hashes)
	require.NoError(t, err)
	require.Len(t, ready, 1)

	results, err := ready[0].prepared.Eval(t.Context())
	require.NoError(t, err)
	require.Len(t, results, 1)
	values, ok := results[0].Bindings["result"].([]any)
	require.True(t, ok)
	require.Len(t, values, 1)
	finding := values[0].(map[string]any)
	require.Equal(t, "self", finding["_dd_id"], "isolated fallback preserves the original self-package reference")
}

func TestContractV2SharedCompilerFallsBackForNamespaceCollisions(t *testing.T) {
	query := staticQuery("terraform", "v2-collision", `import rego.v1
results contains {"_dd_id": "safe", "path": []} if { true }
`)
	tests := []struct {
		name        string
		libraryCode string
		baseData    string
	}{
		{
			name: "library exact generated package",
			libraryCode: `package datadog.q0
import rego.v1
results contains {"_dd_id": "library-only", "path": []} if { true }
`,
		},
		{
			name: "library descendant of generated package",
			libraryCode: `package datadog.q0.helper
import rego.v1
marker := true
`,
		},
		{
			name: "library ancestor of generated package",
			libraryCode: `package datadog
import rego.v1
marker := true
`,
		},
		{
			name:     "base input document at generated package",
			baseData: `{"datadog":{"q0":{"marker":"from-input"}}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			libraryCode := tc.libraryCode
			if libraryCode == "" {
				libraryCode = "package generic.terraform\n"
			}
			loader, err := prepareQueries([]model.QueryMetadata{query},
				source.RegoLibraries{LibraryCode: "package common\n", LibraryInputData: "{}"},
				map[string]source.RegoLibraries{"terraform": {
					LibraryCode: libraryCode, LibraryInputData: "{}",
				}}, cacheTracker{})
			require.NoError(t, err)
			inspector := &Inspector{QueryLoader: &loader}
			data := tc.baseData
			if data == "" {
				data = "{}"
			}
			stores, hashes := baseStoresFor("terraform", data)
			spec, ok := analyzeContractV2Rule(&query)
			require.True(t, ok)
			ready, err := inspector.compileContractV2Rules(t.Context(), []*contractV2Rule{spec}, stores, hashes)
			require.NoError(t, err)
			require.Len(t, ready, 1)
			require.Nil(t, ready[0].sharedCompiler, "a namespace collision must use isolated compilation")

			v2Libs, err := contractlibs.Modules()
			require.NoError(t, err)
			isolated, err := inspector.compileOneContractV2Rule(
				t.Context(), &query, contractV2Query, v2Libs, stores, hashes)
			require.NoError(t, err)
			actualResults, err := ready[0].prepared.Eval(t.Context())
			require.NoError(t, err)
			expectedResults, err := isolated.Eval(t.Context())
			require.NoError(t, err)
			actual, err := resultItems(actualResults)
			require.NoError(t, err)
			expected, err := resultItems(expectedResults)
			require.NoError(t, err)
			require.Equal(t, expected, actual, "isolated fallback preserves the original finding set")
			require.Len(t, actual, 1, "the colliding library's partial set must not leak into a rule result")
		})
	}
}

func TestContractV2CustomInputRulesKeepIsolatedStores(t *testing.T) {
	queries := []model.QueryMetadata{
		staticQuery("terraform", "v2-custom-one", `import rego.v1
results contains {"_dd_id": "one", "path": []} if { data.selected == "one" }
`),
		staticQuery("terraform", "v2-custom-two", `import rego.v1
results contains {"_dd_id": "two", "path": []} if { data.selected == "two" }
`),
	}
	queries[0].InputData = `{"selected":"one"}`
	queries[1].InputData = `{"selected":"two"}`
	loader := newCacheTestLoader(t, "terraform", queries)
	inspector := &Inspector{QueryLoader: loader}
	specs := make([]*contractV2Rule, 0, len(queries))
	for i := range queries {
		spec, ok := analyzeContractV2Rule(&queries[i])
		require.True(t, ok)
		specs = append(specs, spec)
	}
	stores, hashes := baseStoresFor("terraform", "{}")
	ready, err := inspector.compileContractV2Rules(t.Context(), specs, stores, hashes)
	require.NoError(t, err)
	require.Len(t, ready, 2)
	runner := &contractV2Runner{c: inspector}
	tasks := runner.contractV2EvalTasks(t.Context(), ready)
	require.Len(t, tasks, 2, "custom-input rules remain independent eval tasks")
	for _, rule := range ready {
		require.Nil(t, rule.sharedCompiler, "custom InputData must not enter the shared batch cohort")
	}
	for _, task := range tasks {
		require.Nil(t, task.prepared, "custom-input rules are not batched")
		require.Len(t, task.rules, 1)
	}
	for i, want := range []string{"one", "two"} {
		results, err := ready[i].prepared.Eval(t.Context())
		require.NoError(t, err)
		require.Len(t, results, 1, "rule %d must see only its own custom InputData", i)
		values := results[0].Bindings["result"].([]any)
		finding := values[0].(map[string]any)
		require.Equal(t, want, finding["_dd_id"])
	}
}

func TestContractV2BatchTaskConservationAndExclusions(t *testing.T) {
	compiler, _, cohort := newContractV2BatchTestCohort(t, 33)
	for _, count := range []int{1, 2, 3, 16, 17, 33} {
		for _, workers := range []int{1, 2, 4, 8} {
			inspector := &Inspector{numWorkers: workers}
			runner := &contractV2Runner{c: inspector}
			tasks := runner.contractV2EvalTasks(t.Context(), cohort[:count])
			seen := make(map[*contractV2Rule]int, count)
			for _, task := range tasks {
				require.NotEmpty(t, task.rules)
				if task.prepared != nil {
					require.GreaterOrEqual(t, len(task.rules), 2)
					require.LessOrEqual(t, len(task.rules), contractV2MaxBatchQueries)
				} else {
					require.Len(t, task.rules, 1)
				}
				for _, rule := range task.rules {
					seen[rule]++
				}
			}
			require.Len(t, seen, count, "every candidate must occur in exactly one eval task")
			for _, rule := range cohort[:count] {
				require.Equal(t, 1, seen[rule], "rule %s must not be dropped or duplicated", rule.meta.Query)
			}
		}
	}

	inspector := &Inspector{
		numWorkers: 2,
		ruleConfigs: map[string]config.IacRuleConfig{
			"with-arguments": {Arguments: map[string]any{"strict": true}},
		},
	}
	argumentRule := *cohort[0]
	argumentRule.meta = model.QueryMetadata{
		Query:    "with-arguments",
		Platform: "terraform",
		Metadata: map[string]interface{}{"id": "with-arguments"},
	}
	customInputRule := &contractV2Rule{
		meta: model.QueryMetadata{Query: "custom-input", InputData: `{"setting":true}`},
	}
	nonPartialRule := *cohort[1]
	nonPartialRule.meta.Query = "non-partial-results"
	nonPartialRule.partialSetResults = false
	runner := &contractV2Runner{c: inspector}
	candidates := []*contractV2Rule{cohort[0], cohort[1], &argumentRule, customInputRule, &nonPartialRule}
	tasks := runner.contractV2EvalTasks(t.Context(), candidates)
	seen := make(map[*contractV2Rule]int, len(candidates))
	batchCount := 0
	for _, task := range tasks {
		if task.prepared != nil {
			batchCount++
			require.ElementsMatch(t, []*contractV2Rule{cohort[0], cohort[1]}, task.rules)
			continue
		}
		require.Len(t, task.rules, 1)
		require.Contains(t, []*contractV2Rule{&argumentRule, customInputRule, &nonPartialRule}, task.rules[0])
	}
	require.Equal(t, 1, batchCount)
	for _, task := range tasks {
		for _, rule := range task.rules {
			seen[rule]++
		}
	}
	for _, rule := range candidates {
		require.Equal(t, 1, seen[rule], "excluded candidates still run singly")
	}

	coverageInspector := &Inspector{numWorkers: 2}
	coverageInspector.EnableCoverageReport()
	coverageRunner := &contractV2Runner{c: coverageInspector}
	coverageTasks := coverageRunner.contractV2EvalTasks(t.Context(), cohort[:2])
	require.Len(t, coverageTasks, 2, "coverage keeps per-rule tracing")
	for _, task := range coverageTasks {
		require.Nil(t, task.prepared)
		require.Len(t, task.rules, 1)
	}

	cacheRunner := &contractV2Runner{c: &Inspector{numWorkers: 2}}
	firstBatch, err := cacheRunner.prepareContractV2Batch(t.Context(), cohort[:2])
	require.NoError(t, err)
	reusedBatch, err := cacheRunner.prepareContractV2Batch(t.Context(), cohort[:2])
	require.NoError(t, err)
	require.Same(t, firstBatch, reusedBatch, "identical batch packages reuse the prepared query")
	differentStoreRule := *cohort[2]
	differentStoreRule.sharedStore = inmem.New()
	_, err = cacheRunner.prepareContractV2Batch(t.Context(), []*contractV2Rule{cohort[0], &differentStoreRule})
	require.Error(t, err, "one compiler cohort must not mix stores")

	added := 0
	for left := range len(cohort) {
		for right := left + 1; right < len(cohort); right++ {
			if left == 0 && right == 1 {
				continue
			}
			_, err = cacheRunner.prepareContractV2Batch(t.Context(), []*contractV2Rule{cohort[left], cohort[right]})
			require.NoError(t, err)
			added++
			if added == contractV2BatchCacheEntryLimit+1 {
				break
			}
		}
		if added == contractV2BatchCacheEntryLimit+1 {
			break
		}
	}
	require.Equal(t, contractV2BatchCacheEntryLimit, len(cacheRunner.batchCache))
	firstKey := contractV2BatchCacheKey{
		compiler: compiler,
		packages: cohort[0].sharedPackage + "\x00" + cohort[1].sharedPackage,
	}
	require.NotContains(t, cacheRunner.batchCache, firstKey, "the least-recently used entry is evicted at the fixed cache bound")
}

func TestContractV2BatchesKeepEmptyResultsAndInputBoundaries(t *testing.T) {
	queries := []model.QueryMetadata{
		staticQuery("terraform", "v2-batch-first", `import rego.v1
results contains {"_dd_id": "first", "path": []} if {
	some resource in input.resources.aws_s3_bucket
	resource.name == "first"
}
`),
		staticQuery("terraform", "v2-batch-second", `import rego.v1
results contains {"_dd_id": "second", "path": []} if {
	some resource in input.resources.aws_s3_bucket
	resource.name == "second"
}
`),
		staticQuery("terraform", "v2-batch-empty", `import rego.v1
results contains {"_dd_id": "empty", "path": []} if { false }
`),
	}
	inspector := newTestInspector(t, inspectorOpts{queries: queries, numWorkers: 1})
	specs := make([]*contractV2Rule, len(queries))
	for i := range queries {
		spec, ok := analyzeContractV2Rule(&queries[i])
		require.True(t, ok)
		specs[i] = spec
	}
	stores, hashes := baseStoresFor("terraform", "{}")
	ready, err := inspector.compileContractV2Rules(t.Context(), specs, stores, hashes)
	require.NoError(t, err)
	require.Len(t, ready, 3)
	runner := &contractV2Runner{c: inspector}
	tasks := runner.contractV2EvalTasks(t.Context(), ready)
	require.Len(t, tasks, 1)
	require.NotNil(t, tasks[0].prepared)
	require.Len(t, tasks[0].rules, 3)

	input := func(names ...string) ast.Value {
		resources := make([]*policy.Resource, 0, len(names))
		for i, name := range names {
			resources = append(resources, &policy.Resource{
				ID: fmt.Sprintf("bucket-%d", i), Kind: "resource", Type: "aws_s3_bucket",
				ResourceKey: "aws_s3_bucket", Name: name,
			})
		}
		unit := &policy.Unit{ID: "scope", Platform: "terraform", ScopeComplete: true, Resources: resources}
		return policy.ProjectUnits("terraform", []*policy.Unit{unit}, policy.ProjectOptions{})
	}
	evaluate := func(payload ast.Value) [][]interface{} {
		t.Helper()
		results, err := tasks[0].prepared.Eval(t.Context(), rego.EvalParsedInput(payload),
			rego.EvalVirtualCache(newIdentityVirtualCache()))
		require.NoError(t, err)
		items, ok := contractV2BatchResultItems(results, 3)
		require.True(t, ok, "every partial set, including an empty one, must bind independently")
		return items
	}
	firstScope := evaluate(input("first", "other"))
	require.Len(t, firstScope[0], 1)
	require.Equal(t, "first", firstScope[0][0].(map[string]any)["_dd_id"])
	require.Empty(t, firstScope[1])
	require.Empty(t, firstScope[2])
	secondScope := evaluate(input("second"))
	require.Empty(t, secondScope[0])
	require.Len(t, secondScope[1], 1)
	require.Equal(t, "second", secondScope[1][0].(map[string]any)["_dd_id"])
	require.Empty(t, secondScope[2])
}

func TestContractV2BatchFailureReplaysRulesIndependently(t *testing.T) {
	queries := []model.QueryMetadata{
		staticQuery("terraform", "v2-batch-healthy", `import rego.v1
results contains {"_dd_id": "bucket-1", "path": []} if { true }
`),
		staticQuery("terraform", "v2-batch-failing", `import rego.v1
value := 1 if { input.fail }
value := 2 if { input.fail }
results contains {"_dd_id": "bucket-1", "path": []} if { value == 1 }
`),
	}
	inspector := newTestInspector(t, inspectorOpts{queries: queries, numWorkers: 2})
	specs := make([]*contractV2Rule, len(queries))
	for i := range queries {
		spec, ok := analyzeContractV2Rule(&queries[i])
		require.True(t, ok)
		specs[i] = spec
	}
	stores, hashes := baseStoresFor("terraform", "{}")
	ready, err := inspector.compileContractV2Rules(t.Context(), specs, stores, hashes)
	require.NoError(t, err)
	runner := &contractV2Runner{
		c:           inspector,
		scanID:      "batch-fallback",
		callers:     map[string]*model.FileMetadata{},
		filesByPath: map[string]*model.FileMetadata{},
		findings:    newFindingSet(false, nil),
	}
	lines := []string{`resource "aws_s3_bucket" "bucket" {}`}
	file := &model.FileMetadata{
		ID: "file-1", FilePath: "main.tf", Kind: model.KindTerraform,
		OriginalData: lines[0], LinesOriginalData: &lines,
	}
	resource := &policy.Resource{
		ID: "bucket-1", Kind: "resource", Type: "aws_s3_bucket", ResourceKey: "aws_s3_bucket",
		Name: "bucket", Address: "aws_s3_bucket.bucket", File: "main.tf",
		Source: &policy.SourceMapping{BlockSpan: policy.SourceSpan{File: "main.tf", StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 1}},
	}
	runner.filesByPath["main.tf"] = file
	payload, err := ast.InterfaceToValue(map[string]any{"fail": true})
	require.NoError(t, err)
	tasks := runner.contractV2EvalTasks(t.Context(), ready)
	require.Len(t, tasks, 1)
	require.NotNil(t, tasks[0].prepared)
	require.NoError(t, runner.evalContractV2Batch(t.Context(), tasks[0], payload,
		map[string]*policy.Resource{resource.ID: resource}))
	failed := inspector.GetFailedQueries()
	require.Contains(t, failed, queries[1].Query, "the runtime error belongs only to the failing sibling")
	require.NotContains(t, failed, queries[0].Query)
	require.Len(t, runner.findings.out, 1, "the successful sibling still contributes its finding")
	require.Equal(t, resource.Address, runner.findings.out[0].ResourceID)
}

func newContractV2BatchTestCohort(t *testing.T, count int) (*ast.Compiler, storage.Store, []*contractV2Rule) {
	t.Helper()
	modules := make(map[string]*ast.Module, count)
	rules := make([]*contractV2Rule, count)
	store := inmem.New()
	for i := range count {
		pkg := "data.datadog.q" + strconv.Itoa(i)
		content := fmt.Sprintf("package datadog.q%d\nresults contains {\"_dd_id\": \"rule-%d\", \"path\": []} if { true }\n", i, i)
		module, err := ast.ParseModuleWithOpts(fmt.Sprintf("rule-%d", i), content, ast.ParserOptions{RegoVersion: ast.RegoV1})
		require.NoError(t, err)
		modules[fmt.Sprintf("rule-%d", i)] = module
		rules[i] = &contractV2Rule{
			meta:           model.QueryMetadata{Query: fmt.Sprintf("v2-rule-%d", i), Platform: "terraform"},
			sharedCompiler: nil, sharedStore: store, sharedPackage: pkg, partialSetResults: true,
		}
	}
	compiler := ast.NewCompiler().WithCapabilities(safeCapabilities())
	compiler.Compile(modules)
	require.False(t, compiler.Failed(), "batch fixture rules compile: %v", compiler.Errors)
	for _, rule := range rules {
		rule.sharedCompiler = compiler
	}
	return compiler, store, rules
}

func TestContractV2SharedCacheTracksWholeCohort(t *testing.T) {
	ResetCompiledQueryCachesForTest()
	t.Cleanup(ResetCompiledQueryCachesForTest)
	queries := []model.QueryMetadata{
		staticQuery("terraform", "v2-first", `import rego.v1
results contains {"_dd_id": "first", "path": []} if { true }
`),
		staticQuery("terraform", "v2-second", `import rego.v1
results contains {"_dd_id": "second", "path": []} if { true }
`),
	}
	loader := newCacheTestLoader(t, "terraform", queries)
	inspector := &Inspector{QueryLoader: loader, useRulesCache: true}
	stores, hashes := baseStoresFor("terraform", "{}")
	compile := func(input []model.QueryMetadata) []*contractV2Rule {
		t.Helper()
		specs := make([]*contractV2Rule, 0, len(input))
		for i := range input {
			spec, ok := analyzeContractV2Rule(&input[i])
			require.True(t, ok)
			specs = append(specs, spec)
		}
		ready, err := inspector.compileContractV2Rules(t.Context(), specs, stores, hashes)
		require.NoError(t, err)
		require.Len(t, ready, 2)
		return ready
	}
	first := compile(queries)
	second := compile(queries)
	require.Same(t, first[0].prepared, second[0].prepared, "identical cohorts reuse one bounded shared compiler cache entry")
	require.Same(t, first[1].prepared, second[1].prepared)

	changed := append([]model.QueryMetadata(nil), queries...)
	changed[1].Content += "\nunused := true\n"
	third := compile(changed)
	require.NotSame(t, first[0].prepared, third[0].prepared, "changing any rule invalidates the whole cohort")
}
