/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/contractlibs"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	terraformJSONParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/DataDog/datadog-iac-scanner/pkg/ruletest"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"

	"github.com/open-policy-agent/opa/v1/cover"
)

// stubQueriesSource is an in-memory [source.QueriesSource] that returns a
// fixed slice of query metadata and a trivial rego library for any platform.
type stubQueriesSource struct {
	queries []model.QueryMetadata
}

func (s *stubQueriesSource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return s.queries, nil
}

func (s *stubQueriesSource) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	return source.RegoLibraries{
		LibraryCode:      "package generic." + platform + "\n",
		LibraryInputData: "{}",
	}, nil
}

// inspectorOpts configures [newTestInspector]; zero values yield an inspector
// with no rules. Set `querySource` to plug in a custom QueriesSource (e.g. a
// gomock) instead of the default in-memory stub backed by `queries`.
type inspectorOpts struct {
	queries          []model.QueryMetadata
	querySource      source.QueriesSource
	queryParameters  *source.QueryInspectorParameters
	repoPath         string
	useOldSeverities bool
	needsLog         bool
	numWorkers       int
	vb               VulnerabilityBuilder
	tracker          Tracker
	flagEvaluator    featureflags.FlagEvaluator
	useRulesCache    bool
	fsys             vfs.FS
}

// newTestInspector runs the real [NewInspector] against a configurable
// [source.QueriesSource] so callers get the production constructor wiring
// without loading any rules from disk.
func newTestInspector(t *testing.T, opts inspectorOpts) *Inspector {
	t.Helper()

	if opts.querySource == nil {
		opts.querySource = &stubQueriesSource{queries: opts.queries}
	}
	if opts.queryParameters == nil {
		opts.queryParameters = &source.QueryInspectorParameters{}
	}
	if opts.repoPath == "" {
		opts.repoPath = "."
	}
	if opts.numWorkers == 0 {
		opts.numWorkers = 1
	}
	if opts.vb == nil {
		opts.vb = func(_ context.Context, _ *QueryContext, _ Tracker, _ interface{},
			_ *detector.DetectLine, _ bool, _ time.Duration) (*model.Vulnerability, error) {
			return &model.Vulnerability{}, nil
		}
	}
	if opts.tracker == nil {
		opts.tracker = &tracker.CITracker{}
	}
	if opts.flagEvaluator == nil {
		opts.flagEvaluator = featureflags.NewLocalEvaluator()
	}

	fsys := opts.fsys
	if fsys == nil {
		fsys = vfs.DiskFS{}
	}
	ins, err := NewInspector(
		context.Background(),
		opts.querySource,
		opts.vb,
		opts.tracker,
		opts.queryParameters,
		nil,
		opts.repoPath,
		opts.useOldSeverities,
		opts.needsLog,
		opts.numWorkers,
		opts.flagEvaluator,
		fsys,
		opts.useRulesCache,
	)
	require.NoError(t, err)
	return ins
}

func TestWarnSlowRuleUsesSummedEvalAndDecodeThreshold(t *testing.T) {
	threshold := 100 * time.Millisecond
	cases := []struct {
		name           string
		evalDuration   time.Duration
		decodeDuration time.Duration
		wantWarning    bool
	}{
		{name: "sum crosses threshold", evalDuration: 70 * time.Millisecond, decodeDuration: 31 * time.Millisecond, wantWarning: true},
		{name: "sum below threshold", evalDuration: 70 * time.Millisecond, decodeDuration: 29 * time.Millisecond},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			contextLogger := zerolog.New(&logs).Level(zerolog.WarnLevel)

			warnSlowRule(&contextLogger, "terraform.example", "Terraform", tc.evalDuration, tc.decodeDuration, threshold)

			if tc.wantWarning {
				require.Contains(t, logs.String(), `"event":"slow_rule"`)
				require.Contains(t, logs.String(), `"totalMs":101`)
				require.Contains(t, logs.String(), `"thresholdMs":100`)
			} else {
				require.Empty(t, logs.String())
			}
		})
	}
}

// TestInspector_EnableCoverageReport tests the functions [EnableCoverageReport()] and all the methods called by them
func TestInspector_EnableCoverageReport(t *testing.T) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: io.Discard})

	type fields struct {
		queryLoader          *QueryLoader
		vb                   VulnerabilityBuilder
		tracker              Tracker
		enableCoverageReport bool
		coverageReport       cover.Report
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "enable_coverage_report_1",
			fields: fields{
				queryLoader:          &QueryLoader{},
				vb:                   DefaultVulnerabilityBuilder,
				tracker:              &tracker.CITracker{},
				enableCoverageReport: false,
				coverageReport:       cover.Report{},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Inspector{
				QueryLoader:          tt.fields.queryLoader,
				vb:                   tt.fields.vb,
				tracker:              tt.fields.tracker,
				enableCoverageReport: tt.fields.enableCoverageReport,
				coverageReport:       tt.fields.coverageReport,
			}
			c.EnableCoverageReport()
			if !reflect.DeepEqual(c.enableCoverageReport, tt.want) {
				t.Errorf("Inspector.enableCoverageReport() = %v, want %v", c.enableCoverageReport, tt.want)
			}
		})
	}
}

// TestInspector_GetCoverageReport tests the functions [GetCoverageReport()] and all the methods called by them
func TestInspector_GetCoverageReport(t *testing.T) {
	coverageReports := cover.Report{
		Coverage: 75.5,
		Files:    map[string]*cover.FileReport{},
	}

	type fields struct {
		queryLoader          *QueryLoader
		vb                   VulnerabilityBuilder
		tracker              Tracker
		enableCoverageReport bool
		coverageReport       cover.Report
	}
	tests := []struct {
		name   string
		fields fields
		want   cover.Report
	}{
		{
			name: "get_coverage_report_1",
			fields: fields{
				queryLoader:          &QueryLoader{},
				vb:                   DefaultVulnerabilityBuilder,
				tracker:              &tracker.CITracker{},
				enableCoverageReport: false,
				coverageReport:       coverageReports,
			},
			want: coverageReports,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Inspector{
				QueryLoader:          tt.fields.queryLoader,
				vb:                   tt.fields.vb,
				tracker:              tt.fields.tracker,
				enableCoverageReport: tt.fields.enableCoverageReport,
				coverageReport:       tt.fields.coverageReport,
			}
			if got := c.GetCoverageReport(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Inspector.GetCoverageReport() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNewInspector smoke-tests the [NewInspector] wiring: vb, tracker, and
// the queries returned by the source must flow through to the resulting
// inspector unchanged.
func TestNewInspector(t *testing.T) {
	track := &tracker.CITracker{}
	queries := []model.QueryMetadata{
		{
			Query:       "stub_terraform_rule",
			Content:     "package stub_terraform_rule\n",
			InputData:   "{}",
			Platform:    "terraform",
			Metadata:    map[string]interface{}{"id": "stub-terraform"},
			Aggregation: 1,
		},
		{
			Query:       "stub_common_rule",
			Content:     "package stub_common_rule\n",
			InputData:   "{}",
			Platform:    "common",
			Metadata:    map[string]interface{}{"id": "stub-common"},
			Aggregation: 1,
		},
	}

	ins := newTestInspector(t, inspectorOpts{
		queries:  queries,
		tracker:  track,
		needsLog: true,
	})

	require.NotNil(t, ins.vb, "vulnerability builder should be wired")
	require.Same(t, track, ins.tracker, "tracker should be the one we passed in")
	require.NotNil(t, ins.QueryLoader, "query loader should be initialized")
	require.Equal(t, queries, ins.QueryLoader.QueriesMetadata,
		"queries supplied by the source should flow through to QueryLoader")
}

func TestEngine_contains(t *testing.T) {
	type args struct {
		s []string
		e string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "test_contains_common",
			args: args{
				s: []string{""},
				e: "common",
			},
			want: true,
		},
		{
			name: "test_contains_k8s",
			args: args{
				s: []string{"kubernetes"},
				e: "k8s",
			},
			want: true,
		},
		{
			name: "test_contains_k8s",
			args: args{
				s: []string{"terraform", "cloudformation"},
				e: "terraform",
			},
			want: true,
		},
		{
			name: "test_not_contains",
			args: args{
				s: []string{"cloudformation"},
				e: "terraform",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contains(tt.args.s, tt.args.e)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestEngine_canonicalPlatformKey(t *testing.T) {
	cases := map[string]string{
		"k8s":                  "kubernetes",
		"Kubernetes":           "kubernetes",
		"K8S":                  "kubernetes",
		"bicep":                "azureresourcemanager",
		"Bicep":                "azureresourcemanager",
		"azureResourceManager": "azureresourcemanager",
		"cloudFormation":       "cloudformation",
		"serverlessFW":         "serverlessfw",
		"Ansible":              "ansible",
		"terraform":            "terraform",
		"common":               "common",
	}
	for in, want := range cases {
		require.Equal(t, want, canonicalPlatformKey(in), "canonicalPlatformKey(%q)", in)
	}
}

func TestEngine_platformBucketKeys(t *testing.T) {
	cases := map[string][]string{
		"":           nil,
		"ansible":    {"ansible"},
		"k8s":        {"kubernetes"},
		"kubernetes": {"kubernetes"},
		"bicep":      {"azureresourcemanager"},
		"terraform":  {"terraform"},
		"knative":    {"knative", "kubernetes"},
		"Knative":    {"knative", "kubernetes"},
		// Crossplane has its own queries and is classified consistently by the
		// sink, so it maps to a single bucket (no kubernetes fan-out).
		"crossplane":   {"crossplane"},
		"serverlessfw": {"serverlessfw", "cloudformation"},
		"serverlessFW": {"serverlessfw", "cloudformation"},
	}
	for in, want := range cases {
		require.Equal(t, want, platformBucketKeys(in), "platformBucketKeys(%q)", in)
	}
}

func Test_partitionDocsByPlatform(t *testing.T) {
	filesMap := map[string]*model.FileMetadata{
		"ansible-id":      {ID: "ansible-id", Platform: "ansible"},
		"k8s-id":          {ID: "k8s-id", Platform: "kubernetes"},
		"unknown-id":      {ID: "unknown-id", Platform: ""},
		"query-k8s-id":    {ID: "query-k8s-id", Platform: "k8s"},
		"knative-id":      {ID: "knative-id", Platform: "knative"},
		"crossplane-id":   {ID: "crossplane-id", Platform: "crossplane"},
		"serverlessfw-id": {ID: "serverlessfw-id", Platform: "serverlessfw"},
	}
	combined := []model.Document{
		{"id": "ansible-id", "playbooks": []interface{}{}},
		{"id": "k8s-id", "apiVersion": "v1", "kind": "Pod"},
		{"id": "unknown-id", "foo": "bar"},
		{"id": "query-k8s-id", "apiVersion": "v1", "kind": "Service"},
		{"id": "knative-id", "apiVersion": "serving.knative.dev/v1", "kind": "Service"},
		{"id": "crossplane-id", "apiVersion": "s3.aws.crossplane.io/v1beta1", "kind": "Bucket"},
		{"id": "serverlessfw-id", "service": "my-svc", "provider": map[string]interface{}{}},
	}

	all, bucketsPerDoc, unknown := partitionDocsByPlatform(filesMap, combined, nil)

	require.Len(t, all, 7)
	require.Len(t, unknown, 1)
	require.Equal(t, "unknown-id", all[unknown[0]].(map[string]interface{})["id"])
	bucketOf := func(id string) []string {
		for i, doc := range all {
			if doc.(map[string]interface{})["id"] == id {
				return bucketsPerDoc[i]
			}
		}
		return nil
	}
	require.Equal(t, []string{"ansible"}, bucketOf("ansible-id"))
	// Knative docs are also scanned by Kubernetes rules; the kubernetes bucket
	// holds the two k8s docs plus the knative one.
	require.Equal(t, []string{"knative", "kubernetes"}, bucketOf("knative-id"))
	require.Equal(t, []string{"kubernetes"}, bucketOf("k8s-id"))
	// Crossplane is classified consistently and has its own queries, so it maps
	// to a single bucket and is not mirrored into kubernetes.
	require.Equal(t, []string{"crossplane"}, bucketOf("crossplane-id"))
	// Serverless Framework docs are scanned by both ServerlessFW and CloudFormation rules.
	require.Equal(t, []string{"serverlessfw", "cloudformation"}, bucketOf("serverlessfw-id"))
	require.Nil(t, bucketOf("unknown-id"))
}

func TestInterfaceToPayloadValueMatchesExistingTransformation(t *testing.T) {
	shared := map[string]interface{}{"name": "example", "encoded": `jsonencode({foo = "bar"})`}
	input := map[string]interface{}{
		"document": []interface{}{
			map[string]interface{}{
				"id":       "one",
				"resource": shared,
				"mirror":   map[string]interface{}{"resource": shared},
			},
		},
	}
	inspector := &Inspector{}

	raw, err := ast.InterfaceToValue(input)
	require.NoError(t, err)
	want := inspector.TransformJsonencodeInPayload(context.Background(), raw)
	got, err := inspector.interfaceToPayloadValue(
		context.Background(),
		input,
		newPayloadHashCons(),
	)

	require.NoError(t, err)
	require.Equal(t, want.String(), got.String())
}

func TestTransformJsonencodeInPayloadLeavesSuffixExpressionUnchanged(t *testing.T) {
	input := ast.String(`${jsonencode(each.value.role_name_patterns)}.exists(r, attribute.aws_role.matches(r))`)
	var logs bytes.Buffer
	ctx := zerolog.New(&logs).WithContext(context.Background())

	got := (&Inspector{}).TransformJsonencodeInPayload(ctx, input)

	require.Equal(t, input, got)
	require.Empty(t, logs.String())
}

func TestBuildPlatformPayloadsReusesEquivalentFullPayload(t *testing.T) {
	filesMap := map[string]*model.FileMetadata{
		"terraform-id": {ID: "terraform-id", Platform: "terraform"},
	}
	documents := []model.Document{
		{"id": "terraform-id", "resource": map[string]interface{}{"test": map[string]interface{}{}}},
	}
	queries := []model.QueryMetadata{
		{Platform: "terraform"},
		{Platform: "common"},
	}

	payloads, err := (&Inspector{}).buildPlatformPayloads(
		context.Background(),
		filesMap,
		documents,
		nil,
		queries,
	)

	require.NoError(t, err)
	require.Equal(
		t,
		reflect.ValueOf(payloads.full).Pointer(),
		reflect.ValueOf(payloads.byPlatform["terraform"]).Pointer(),
	)
}

func TestBuildPlatformPayloadsSharesSubtreesAndReleases(t *testing.T) {
	// Two kubernetes files with identical content share every child map (the
	// shared-parse cache hands each file a fresh top-level map), exactly like
	// duplicate files in community-operators.
	sharedChild := map[string]interface{}{"spec": map[string]interface{}{"paused": false}}
	filesMap := map[string]*model.FileMetadata{
		"k8s-1": {ID: "k8s-1", Platform: "kubernetes", Document: model.Document{
			"id": "k8s-1", "file": "a.yaml", "kind": "Pod", "metadata": sharedChild}},
		"k8s-2": {ID: "k8s-2", Platform: "kubernetes", Document: model.Document{
			"id": "k8s-2", "file": "b.yaml", "kind": "Pod", "metadata": sharedChild}},
	}
	combined := []model.Document{filesMap["k8s-1"].Document, filesMap["k8s-2"].Document}
	queries := []model.QueryMetadata{{Platform: "k8s"}}

	inspector := &Inspector{releaseDocumentsAfterPayload: true}
	payloads, err := inspector.buildPlatformPayloads(
		context.Background(), filesMap, combined, nil, queries)
	require.NoError(t, err)

	// Progressive release: every source document is dropped after conversion.
	for id, f := range filesMap {
		require.Nil(t, f.Document, "document for %s should be released", id)
	}

	// The shared child subtree converts to a single ast.Value: both payload
	// entries hold the same metadata object.
	obj := payloads.byPlatform["kubernetes"].(ast.Object)
	docs := obj.Get(ast.StringTerm("document"))
	arr := docs.Value.(*ast.Array)
	require.Equal(t, 2, arr.Len())
	meta1 := arr.Elem(0).Value.(ast.Object).Get(ast.StringTerm("metadata")).Value
	meta2 := arr.Elem(1).Value.(ast.Object).Get(ast.StringTerm("metadata")).Value
	require.Equal(t, reflect.ValueOf(meta1).Pointer(), reflect.ValueOf(meta2).Pointer(),
		"shared child subtrees must map to one ast.Value")
}

func TestEngine_selectPlatformPayload(t *testing.T) {
	full := ast.String("FULL")
	byPlatform := map[string]ast.Value{
		"ansible":    ast.String("ANSIBLE"),
		"kubernetes": ast.String("K8S"),
	}

	// A query is routed to its own platform's payload.
	require.Equal(t, ast.String("ANSIBLE"), selectPlatformPayload("ansible", byPlatform, full))
	// "k8s" query metadata normalizes to the "kubernetes" bucket.
	require.Equal(t, ast.String("K8S"), selectPlatformPayload("k8s", byPlatform, full))
	// Common rules always see the full payload.
	require.Equal(t, full, selectPlatformPayload("common", byPlatform, full))
	require.Equal(t, full, selectPlatformPayload("Common", byPlatform, full))
	// Defensive fallback: a platform with no built payload uses the full payload.
	require.Equal(t, full, selectPlatformPayload("terraform", byPlatform, full))
}

func TestEngine_LenQueriesByPlat(t *testing.T) {
	queries := []model.QueryMetadata{
		{Query: "tf_rule_a", Content: "package tf_rule_a\n", InputData: "{}", Platform: "terraform", Aggregation: 1},
		{Query: "tf_rule_b", Content: "package tf_rule_b\n", InputData: "{}", Platform: "terraform", Aggregation: 1},
		{Query: "k8s_rule", Content: "package k8s_rule\n", InputData: "{}", Platform: "kubernetes", Aggregation: 1},
	}
	ins := newTestInspector(t, inspectorOpts{queries: queries})

	require.Equal(t, 2, ins.LenQueriesByPlat([]string{"terraform"}))
	require.Equal(t, 1, ins.LenQueriesByPlat([]string{"kubernetes"}))
	require.Equal(t, 3, ins.LenQueriesByPlat([]string{"terraform", "kubernetes"}))
	require.Equal(t, 0, ins.LenQueriesByPlat([]string{"cloudformation"}))
}

func TestEngine_GetFailedQueries(t *testing.T) {
	ins := newTestInspector(t, inspectorOpts{})
	const nrFailedQueries = 5
	for idx := 0; idx < nrFailedQueries; idx++ {
		ins.failedQueries[fmt.Sprint(idx)] = nil
	}
	require.Equal(t, nrFailedQueries, len(ins.GetFailedQueries()))
}

func TestShouldSkipFile(t *testing.T) {
	type args struct {
		commands       model.CommentsCommands
		queryID        string
		legacyQueryID  string
		legacyQueryIDs []string
	}
	tests := []struct {
		name     string
		args     args
		expected bool
	}{
		{
			name: "test_enabled_queries_valid_query_legacy_id",
			args: args{
				commands: model.CommentsCommands{
					"enable": "ffdf4b37-7703-4dfe-a682-9d2e99bc6c09,0afa6ab8-a047-48cf-be07-93a2f8c34cf7",
				},
				queryID:       "platform-cloudprovider-slug",
				legacyQueryID: "ffdf4b37-7703-4dfe-a682-9d2e99bc6c09",
			},
			expected: false,
		},
		{
			name: "test_enabled_queries_valid_query_id",
			args: args{
				commands: model.CommentsCommands{
					"enable": "platform-cloudprovider-slug,0afa6ab8-a047-48cf-be07-93a2f8c34cf7",
				},
				queryID:       "platform-cloudprovider-slug",
				legacyQueryID: "ffdf4b37-7703-4dfe-a682-9d2e99bc6c09",
			},
			expected: false,
		},
		{
			name: "test_enabled_queries_invalid_query",
			args: args{
				commands: model.CommentsCommands{
					"enable": "0afa6ab8-a047-48cf-be07-93a2f8c34cf7",
				},
				queryID:       "platform-cloudprovider-slug",
				legacyQueryID: "ffdf4b37-7703-4dfe-a682-9d2e99bc6c09",
			},
			expected: true,
		},
		{
			name: "test_disabled_queries_valid_query_legacy_id",
			args: args{
				commands: model.CommentsCommands{
					"disable": "ffdf4b37-7703-4dfe-a682-9d2e99bc6c09,0afa6ab8-a047-48cf-be07-93a2f8c34cf7",
				},
				queryID:       "platform-cloudprovider-slug",
				legacyQueryID: "ffdf4b37-7703-4dfe-a682-9d2e99bc6c09",
			},
			expected: true,
		},
		{
			name: "test_disabled_queries_valid_query_id",
			args: args{
				commands: model.CommentsCommands{
					"disable": "platform-cloudprovider-slug,0afa6ab8-a047-48cf-be07-93a2f8c34cf7",
				},
				queryID:       "platform-cloudprovider-slug",
				legacyQueryID: "ffdf4b37-7703-4dfe-a682-9d2e99bc6c09",
			},
			expected: true,
		},
		{
			name: "test_disabled_queries_invalid_query",
			args: args{
				commands: model.CommentsCommands{
					"disable": "0afa6ab8-a047-48cf-be07-93a2f8c34cf7",
				},
				queryID:       "platform-cloudprovider-slug",
				legacyQueryID: "ffdf4b37-7703-4dfe-a682-9d2e99bc6c09",
			},
			expected: false,
		},
		{
			name: "test_withoutCommands",
			args: args{
				commands:      model.CommentsCommands{},
				queryID:       "platform-cloudprovider-slug",
				legacyQueryID: "ffdf4b37-7703-4dfe-a682-9d2e99bc6c09",
			},
			expected: false,
		},
		{
			name: "test_enabled_queries_valid_legacy_ids_entry",
			args: args{
				commands: model.CommentsCommands{
					"enable": "old-renamed-id,0afa6ab8-a047-48cf-be07-93a2f8c34cf7",
				},
				queryID:        "platform-cloudprovider-slug",
				legacyQueryID:  "ffdf4b37-7703-4dfe-a682-9d2e99bc6c09",
				legacyQueryIDs: []string{"old-renamed-id", "merged-rule-id"},
			},
			expected: false,
		},
		{
			name: "test_disabled_queries_valid_legacy_ids_entry_case_insensitive",
			args: args{
				commands: model.CommentsCommands{
					"disable": "Merged-Rule-Id",
				},
				queryID:        "platform-cloudprovider-slug",
				legacyQueryID:  "ffdf4b37-7703-4dfe-a682-9d2e99bc6c09",
				legacyQueryIDs: []string{"old-renamed-id", "merged-rule-id"},
			},
			expected: true,
		},
		{
			name: "test_disabled_queries_invalid_legacy_ids_entry",
			args: args{
				commands: model.CommentsCommands{
					"disable": "unrelated-id",
				},
				queryID:        "platform-cloudprovider-slug",
				legacyQueryID:  "ffdf4b37-7703-4dfe-a682-9d2e99bc6c09",
				legacyQueryIDs: []string{"old-renamed-id", "merged-rule-id"},
			},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldSkipVulnerability(tt.args.commands, tt.args.queryID, tt.args.legacyQueryID, tt.args.legacyQueryIDs)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestLookupRuleConfig(t *testing.T) {
	canonicalConfig := config.IacRuleConfig{Severity: strPtr("HIGH")}
	legacyConfig := config.IacRuleConfig{Severity: strPtr("MEDIUM")}
	sortedConfig := config.IacRuleConfig{Severity: strPtr("LOW")}

	tests := []struct {
		name           string
		ruleConfigs    map[string]config.IacRuleConfig
		queryID        string
		legacyQueryID  string
		legacyQueryIDs []string
		found          bool
		severity       string
	}{
		{
			name:        "match_by_canonical_id",
			ruleConfigs: map[string]config.IacRuleConfig{"platform-provider-slug": canonicalConfig},
			queryID:     "platform-provider-slug",
			found:       true,
			severity:    "HIGH",
		},
		{
			name:          "match_by_legacy_id",
			ruleConfigs:   map[string]config.IacRuleConfig{"old-legacy-id": legacyConfig},
			queryID:       "platform-provider-slug",
			legacyQueryID: "old-legacy-id",
			found:         true,
			severity:      "MEDIUM",
		},
		{
			name:           "match_by_each_legacy_ids_entry",
			ruleConfigs:    map[string]config.IacRuleConfig{"merged-b": sortedConfig},
			queryID:        "platform-provider-slug",
			legacyQueryIDs: []string{"merged-a", "merged-b"},
			found:          true,
			severity:       "LOW",
		},
		{
			name:           "no_match",
			ruleConfigs:    map[string]config.IacRuleConfig{"unrelated": canonicalConfig},
			queryID:        "platform-provider-slug",
			legacyQueryID:  "old-legacy-id",
			legacyQueryIDs: []string{"merged-a"},
			found:          false,
		},
		// Precedence: canonical id, then legacy id, then legacy_ids entries in
		// sorted order, when several IDs of one rule have config keys.
		{
			name: "precedence_canonical_id_wins_over_legacy_id",
			ruleConfigs: map[string]config.IacRuleConfig{
				"platform-provider-slug": canonicalConfig,
				"old-legacy-id":          legacyConfig,
			},
			queryID:       "platform-provider-slug",
			legacyQueryID: "old-legacy-id",
			found:         true,
			severity:      "HIGH",
		},
		{
			name: "precedence_canonical_id_wins_over_legacy_ids_entry",
			ruleConfigs: map[string]config.IacRuleConfig{
				"platform-provider-slug": canonicalConfig,
				"merged-a":               sortedConfig,
			},
			queryID:        "platform-provider-slug",
			legacyQueryIDs: []string{"merged-a"},
			found:          true,
			severity:       "HIGH",
		},
		{
			name: "precedence_legacy_id_wins_over_legacy_ids_entry",
			ruleConfigs: map[string]config.IacRuleConfig{
				"old-legacy-id": legacyConfig,
				"merged-a":      sortedConfig,
			},
			queryID:        "platform-provider-slug",
			legacyQueryID:  "old-legacy-id",
			legacyQueryIDs: []string{"merged-a"},
			found:          true,
			severity:       "MEDIUM",
		},
		{
			name: "precedence_legacy_ids_entries_in_sorted_order",
			ruleConfigs: map[string]config.IacRuleConfig{
				"merged-b": sortedConfig,
				"merged-a": legacyConfig,
			},
			queryID:        "platform-provider-slug",
			legacyQueryIDs: []string{"merged-b", "merged-a"},
			found:          true,
			severity:       "MEDIUM",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc, found := lookupRuleConfig(tt.ruleConfigs, tt.queryID, tt.legacyQueryID, tt.legacyQueryIDs)
			require.Equal(t, tt.found, found)
			if tt.found {
				require.NotNil(t, rc.Severity)
				require.Equal(t, tt.severity, *rc.Severity)
			}
		})
	}
}

// TestQueryIDsFromMetadata_LegacyIdsWiring proves the loading path: legacyIds
// entries parsed from metadata.json reach queryIDsFromMetadata.
func TestQueryIDsFromMetadata_LegacyIdsWiring(t *testing.T) {
	ctx := context.Background()
	queryDir := t.TempDir()
	metadata := `{
  "id": "platform-provider-slug",
  "legacyId": "old-legacy-id",
  "legacyIds": ["renamed-away-id", "merged-rule-id"],
  "queryName": "Wired rule",
  "severity": "HIGH",
  "category": "Security",
  "platform": "Terraform"
}`
	require.NoError(t, os.WriteFile(filepath.Join(queryDir, "metadata.json"), []byte(metadata), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(queryDir, "query.rego"), []byte("package datadog"), 0o644))
	loaded, err := source.ReadQueryFile(ctx, queryDir)
	require.NoError(t, err)

	queryID, legacyQueryID, legacyQueryIDs := queryIDsFromMetadata(ctx, &loaded)
	require.Equal(t, "platform-provider-slug", queryID)
	require.Equal(t, "old-legacy-id", legacyQueryID)
	require.Equal(t, []string{"renamed-away-id", "merged-rule-id"}, legacyQueryIDs)
}

// TestDoRun_WiresHistoricalIDsThroughConfigAndSuppression drives the real
// production paths end to end: doRun must resolve a rule config keyed only by
// a legacy_ids entry (its arguments gate the rule, so a finding only appears
// when the arguments were forwarded), and the decoded finding — built by the
// real vulnerability builder from a result carrying legacyIds — must be
// severity-overridden and suppressed through the same historical ID.
func TestDoRun_WiresHistoricalIDsThroughConfigAndSuppression(t *testing.T) {
	ctx := context.Background()
	const (
		ruleID       = "platform-provider-slug"
		legacyID     = "old-legacy-id"
		historicalID = "renamed-away-id"
	)
	ruleRego := `package datadog
import rego.v1

DatadogPolicy contains result if {
	input.arguments.strict == "true"
	result := {
		"documentId": "doc-1",
		"resourceType": "AWS::S3::Bucket",
		"resourceName": "Bucket",
		"searchKey": "Bucket.Encryption",
		"id": "platform-provider-slug",
		"legacyId": "old-legacy-id",
		"legacyIds": ["renamed-away-id", "merged-rule-id"],
	}
}`
	metadata := model.QueryMetadata{
		Query: ruleID, Content: ruleRego, Platform: "Terraform",
		Metadata: map[string]interface{}{
			"id": ruleID, "legacyId": legacyID, "legacyIds": []string{historicalID, "merged-rule-id"},
			"queryName": "Wired rule", "severity": "HIGH", "platform": "Terraform",
		},
	}

	prepared, err := rego.New(
		rego.Query(utils.RegoQuery),
		rego.SetRegoVersion(ast.RegoV1),
		rego.Module("Common", "package generic.common\n"),
		rego.Module("Generic", "package generic.terraform\n"),
		rego.Module(ruleID, ruleRego),
	).PrepareForEval(ctx)
	require.NoError(t, err)

	payloadValue, err := ast.InterfaceToValue(map[string]interface{}{
		"document": map[string]interface{}{"id": "doc-1"},
	})
	require.NoError(t, err)

	newInspector := func(ruleConfigs map[string]config.IacRuleConfig) *Inspector {
		ins := newTestInspector(t, inspectorOpts{queries: []model.QueryMetadata{metadata}, vb: DefaultVulnerabilityBuilder})
		ins.ruleConfigs = ruleConfigs
		return ins
	}
	newQueryCtx := func(commands model.CommentsCommands) *QueryContext {
		file := &model.FileMetadata{
			ID:                "doc-1",
			FilePath:          "bucket.yaml",
			LinesOriginalData: &[]string{"Bucket:", "  Encryption:"},
			Commands:          commands,
		}
		return &QueryContext{
			Ctx:           ctx,
			scanID:        "scan-id",
			Files:         map[string]*model.FileMetadata{"doc-1": file},
			Query:         &PreparedQuery{OpaQuery: prepared, Metadata: metadata},
			payload:       &payloadValue,
			FlagEvaluator: featureflags.NewLocalEvaluator(),
			findings:      newFindingSet(false, nil),
		}
	}

	t.Run("config_keyed_by_legacy_ids_entry_gates_and_overrides", func(t *testing.T) {
		severity := "CRITICAL"
		ins := newInspector(map[string]config.IacRuleConfig{
			historicalID: {Arguments: map[string]any{"strict": "true"}, Severity: &severity},
		})
		vulns, _, _, err := ins.doRun(ctx, newQueryCtx(model.CommentsCommands{"disable": historicalID}))
		require.NoError(t, err)
		require.Len(t, vulns, 1, "the rule fires only when the config arguments keyed by the legacy_ids entry were forwarded")
		require.Equal(t, model.Severity(model.SeverityCritical), vulns[0].Severity, "the config found via the legacy_ids entry must also override the severity")
		require.Equal(t, []string{historicalID, "merged-rule-id"}, vulns[0].LegacyQueryIDs)
		require.True(t, vulns[0].IsSuppressed)
		require.Equal(t, model.SuppressionJustificationDisableInFile, vulns[0].SuppressionJustification,
			"the decoded finding must be suppressed by a disable comment naming a legacy_ids entry")
	})

	t.Run("without_the_historical_config_key_the_rule_never_fires", func(t *testing.T) {
		severity := "CRITICAL"
		ins := newInspector(map[string]config.IacRuleConfig{
			"unrelated-id": {Arguments: map[string]any{"strict": "true"}, Severity: &severity},
		})
		vulns, _, _, err := ins.doRun(ctx, newQueryCtx(nil))
		require.NoError(t, err)
		require.Empty(t, vulns, "arguments from a config that matches no ID of the rule must not be forwarded")
	})
}

func strPtr(s string) *string {
	return &s
}

// TestGetVulnerabilitiesFromQuery_SuppressionPaths covers the suppression
// gates (`disable:<queryID>`, `ignore-line`) plus the non-suppressed baseline.
func TestGetVulnerabilitiesFromQuery_SuppressionPaths(t *testing.T) {
	const (
		fileID        = "file-1"
		queryID       = "platform-provider-rule"
		legacyQueryID = "legacy-id"
		matchingLine  = 7
	)

	baseFile := func() *model.FileMetadata {
		return &model.FileMetadata{
			ID:       fileID,
			FilePath: "main.tf",
			Commands: model.CommentsCommands{},
		}
	}

	buildVulnerability := func() *model.Vulnerability {
		return &model.Vulnerability{
			FileID:        fileID,
			QueryID:       queryID,
			LegacyQueryID: legacyQueryID,
			QueryName:     "rule",
			Line:          matchingLine,
		}
	}

	cases := []struct {
		name                  string
		file                  *model.FileMetadata
		expectSuppressed      bool
		expectSuppressionKind string
		expectJustification   string
	}{
		{
			name:             "not_suppressed",
			file:             baseFile(),
			expectSuppressed: false,
		},
		{
			name: "disable_directive_in_file",
			file: func() *model.FileMetadata {
				file := baseFile()
				file.Commands = model.CommentsCommands{"disable": queryID}
				return file
			}(),
			expectSuppressed:      true,
			expectSuppressionKind: model.SuppressionKindInSource,
			expectJustification:   model.SuppressionJustificationDisableInFile,
		},
		{
			name: "ignore_comment_directive",
			file: func() *model.FileMetadata {
				file := baseFile()
				file.LinesIgnore = []int{matchingLine}
				return file
			}(),
			expectSuppressed:      true,
			expectSuppressionKind: model.SuppressionKindInSource,
			expectJustification:   model.SuppressionJustificationIgnoreComment,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			built := buildVulnerability()
			ins := newTestInspector(t, inspectorOpts{
				vb: func(_ context.Context, _ *QueryContext, _ Tracker, _ interface{},
					_ *detector.DetectLine, _ bool, _ time.Duration) (*model.Vulnerability, error) {
					return built, nil
				},
			})

			queryCtx := &QueryContext{
				Ctx:   context.Background(),
				Files: map[string]*model.FileMetadata{fileID: tc.file},
				Query: &PreparedQuery{Metadata: model.QueryMetadata{Query: "q"}},
			}

			got, retry := getVulnerabilitiesFromQuery(context.Background(), queryCtx, ins, nil, 0)
			require.NotNil(t, got, "suppressed vulnerabilities must still flow through; got nil")
			require.False(t, retry, "retry flag should never be set for suppression paths")
			require.Equal(t, tc.expectSuppressed, got.IsSuppressed)
			require.Equal(t, tc.expectSuppressionKind, got.SuppressionKind)
			require.Equal(t, tc.expectJustification, got.SuppressionJustification)
		})
	}
}

// TestGetVulnerabilitiesFromQuery_SuppressedSurvivesUndetectedLine guards
// against a regression where the detect-line failure branch would drop a
// vulnerability already marked as suppressed.
func TestGetVulnerabilitiesFromQuery_SuppressedSurvivesUndetectedLine(t *testing.T) {
	const (
		fileID  = "file-1"
		queryID = "platform-provider-rule"
	)

	file := &model.FileMetadata{
		ID:       fileID,
		FilePath: "main.tf",
		Commands: model.CommentsCommands{"disable": queryID},
	}

	built := &model.Vulnerability{
		FileID:    fileID,
		QueryID:   queryID,
		QueryName: "rule",
		Line:      UndetectedVulnerabilityLine,
	}

	ins := newTestInspector(t, inspectorOpts{
		vb: func(_ context.Context, _ *QueryContext, _ Tracker, _ interface{},
			_ *detector.DetectLine, _ bool, _ time.Duration) (*model.Vulnerability, error) {
			return built, nil
		},
	})

	queryCtx := &QueryContext{
		Ctx:   context.Background(),
		Files: map[string]*model.FileMetadata{fileID: file},
		Query: &PreparedQuery{Metadata: model.QueryMetadata{Query: "q"}},
	}

	got, failedDetect := getVulnerabilitiesFromQuery(context.Background(), queryCtx, ins, nil, 0)
	require.NotNil(t, got, "suppressed vulnerability must not be dropped when the line is undetected")
	require.False(t, failedDetect, "detect-line failure should not be reported for suppressed findings")
	require.True(t, got.IsSuppressed)
	require.Equal(t, model.SuppressionJustificationDisableInFile, got.SuppressionJustification)
}

// TestGetVulnerabilitiesFromQuery_FirstJustificationWins covers the edge case
// where multiple suppression gates match the same vulnerability. The first
// gate to fire must own the justification so the SARIF output stays stable
// for a given input.
func TestGetVulnerabilitiesFromQuery_FirstJustificationWins(t *testing.T) {
	const (
		fileID       = "file-1"
		queryID      = "platform-provider-rule"
		matchingLine = 11
	)

	file := &model.FileMetadata{
		ID:          fileID,
		FilePath:    "main.tf",
		Commands:    model.CommentsCommands{"disable": queryID},
		LinesIgnore: []int{matchingLine},
	}

	built := &model.Vulnerability{
		FileID:    fileID,
		QueryID:   queryID,
		QueryName: "rule",
		Line:      matchingLine,
	}

	ins := newTestInspector(t, inspectorOpts{
		vb: func(_ context.Context, _ *QueryContext, _ Tracker, _ interface{},
			_ *detector.DetectLine, _ bool, _ time.Duration) (*model.Vulnerability, error) {
			return built, nil
		},
	})

	queryCtx := &QueryContext{
		Ctx:   context.Background(),
		Files: map[string]*model.FileMetadata{fileID: file},
		Query: &PreparedQuery{Metadata: model.QueryMetadata{Query: "q"}},
	}

	got, _ := getVulnerabilitiesFromQuery(context.Background(), queryCtx, ins, nil, 0)
	require.NotNil(t, got)
	require.True(t, got.IsSuppressed)
	require.Equal(t, model.SuppressionJustificationDisableInFile, got.SuppressionJustification,
		"the disable-in-file gate runs first and must own the SARIF justification")
}

func TestInspector_DecodeQueryResults(t *testing.T) {
	ctx := context.Background()
	c := newTestInspector(t, inspectorOpts{})

	queryContext := newQueryContext(ctx)

	// Pass a context that is already expired so DecodeQueryResults must short-circuit
	// on its cancellation branch and return no results.
	expiredCtx, cancel := context.WithTimeout(ctx, 0)
	defer cancel()
	result, _, _, err := c.DecodeQueryResults(ctx, &queryContext, expiredCtx, newResultset(), 57)
	assert.Nil(t, err, "Error not as expected")
	assert.Equal(t, 0, len(result), "Array size is not as expected")
}

func newResultset() rego.ResultSet {
	myValue := make(map[string]interface{})
	myValue["documentId"] = "3a3be8f7-896e-4ef8-9db3-d6c19e60510b"
	myValue["searchKey"] = "{{ADD ${JAR_FILE} app.jar}}"

	myBinding := make([]interface{}, 1)
	myBinding[0] = myValue

	myresult := rego.Result{
		Bindings: map[string]interface{}{
			"result": myBinding,
		},
	}
	myResultSet := rego.ResultSet{myresult}
	return myResultSet
}

func newQueryContext(ctx context.Context) QueryContext {
	queryMetadata := model.QueryMetadata{
		Platform: "myPlatform",
		Query:    "myQuery"}
	myQuery := PreparedQuery{
		Metadata: queryMetadata,
	}
	queryContext := QueryContext{
		Ctx:   ctx,
		Query: &myQuery,
	}
	return queryContext
}

func TestExpressionToAST_RelativeTraversalExpr(t *testing.T) {
	t.Run("relative_traversal_after_index", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("list[var.i].name"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.RelativeTraversalExpr); !ok {
			t.Fatalf("expected *hclsyntax.RelativeTraversalExpr, got %T", expr)
		}

		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}

		got := val.String()
		want := `"list[var.i].name"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})

	t.Run("relative_traversal_multi_step", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("list[var.i].a.b"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.RelativeTraversalExpr); !ok {
			t.Fatalf("expected *hclsyntax.RelativeTraversalExpr, got %T", expr)
		}

		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}

		got := val.String()
		want := `"list[var.i].a.b"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})

	t.Run("function_call_source_now_resolves", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("tostring(var.x).attr"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}

		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST should not return error, got: %v", err)
		}

		got := val.String()
		want := `"tostring(var.x).attr"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})
}

func TestExpressionToAST_ParenthesesExpr(t *testing.T) {
	t.Run("unwraps_to_inner_expression", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("(var.x)"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.ParenthesesExpr); !ok {
			t.Fatalf("expected *hclsyntax.ParenthesesExpr, got %T", expr)
		}

		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		got := val.String()
		want := `"var.x"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})

	t.Run("nested_parentheses_unwrap", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("((1))"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}

		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		got := val.String()
		want := `1`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})
}

func TestExpressionToAST_ConditionalExpr(t *testing.T) {
	t.Run("returns_condition_true_false_string", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`true ? "a" : "b"`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.ConditionalExpr); !ok {
			t.Fatalf("expected *hclsyntax.ConditionalExpr, got %T", expr)
		}

		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		got := val.String()
		want := `"true ? a : b"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})
}

func TestExpressionToAST_FunctionCallExpr(t *testing.T) {
	t.Run("simple_function_call", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`upper("hello")`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.FunctionCallExpr); !ok {
			t.Fatalf("expected *hclsyntax.FunctionCallExpr, got %T", expr)
		}

		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}

		got := val.String()
		want := `"upper(hello)"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})

	t.Run("function_call_with_multiple_args", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`format("%s", var.name)`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.FunctionCallExpr); !ok {
			t.Fatalf("expected *hclsyntax.FunctionCallExpr, got %T", expr)
		}

		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}

		got := val.String()
		want := `"format(%s, var.name)"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})

	t.Run("function_call_no_args", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`timestamp()`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.FunctionCallExpr); !ok {
			t.Fatalf("expected *hclsyntax.FunctionCallExpr, got %T", expr)
		}

		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}

		got := val.String()
		want := `"timestamp()"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})
}

func TestExpressionToAST_BinaryOpExpr(t *testing.T) {
	t.Run("arithmetic", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`1 + 2`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		got := val.String()
		want := `"1 + 2"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})
	t.Run("comparison", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`var.count > 0`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		got := val.String()
		want := `"var.count > 0"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})
}

func TestExpressionToAST_SplatExpr(t *testing.T) {
	// SplatExpr is handled in hclexpr.Dispatch (see pkg/hclexpr TestDispatch/SplatExpr).
	// expressionToAST uses Dispatch; behavior is covered by converter and modules tests.
	t.Run("splat_dispatch_routes_in_hclexpr", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`var.list[*]`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.SplatExpr); !ok {
			t.Fatalf("expected *hclsyntax.SplatExpr, got %T", expr)
		}
		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		got := val.String()
		if got != `"var.list[*]"` {
			t.Errorf("expressionToAST = %s", got)
		}
	})
	t.Run("splat_with_traversal", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`var.list[*].id`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		// The anonymous splat item renders empty, so the trailing traversal
		// composes onto the base to yield the full path.
		if got := val.String(); got != `"var.list[*].id"` {
			t.Errorf("expressionToAST = %s", got)
		}
	})
}

func TestExpressionToAST_TemplateJoin(t *testing.T) {
	// A TemplateJoinExpr wraps the for-loop of a %{for}...%{endfor} directive.
	// Build one directly (the parser nests it inside a TemplateExpr part) and
	// verify it renders the underlying for-expression instead of __UNSUPPORTED_EXPR__.
	forExpr, diags := hclsyntax.ParseExpression([]byte(`[for v in var.list : v]`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		t.Fatalf("parse failed: %v", diags)
	}
	val, err := expressionToAST(&hclsyntax.TemplateJoinExpr{Tuple: forExpr})
	if err != nil {
		t.Fatalf("expressionToAST error: %v", err)
	}
	if got := val.String(); got != `"[for v in var.list : v]"` {
		t.Errorf("expressionToAST = %s", got)
	}
}

func TestExpressionToAST_TemplateExpr_WithFor(t *testing.T) {
	t.Run("one_var", func(t *testing.T) {
		f, diags := hclsyntax.ParseConfig([]byte(`x = "%{for v in var.list}${v}%{endfor}"`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		attr := f.Body.(*hclsyntax.Body).Attributes["x"]
		val, err := expressionToAST(attr.Expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		if got := val.String(); got != `"[for v in var.list : v]"` {
			t.Errorf("expressionToAST = %s", got)
		}
	})
	t.Run("template_for_two_vars", func(t *testing.T) {
		f, diags := hclsyntax.ParseConfig([]byte(`x = "%{for k, v in var.map}${k}%{endfor}"`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		attr := f.Body.(*hclsyntax.Body).Attributes["x"]
		val, err := expressionToAST(attr.Expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		got := val.String()
		want := `"[for k, v in var.map : k]"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})
}

func TestExpressionToAST_TemplateExpr_UnsupportedPartFallback(t *testing.T) {
	// ExprSyntaxError in a template part must collapse to "${...}", not leak the sentinel string.
	// Parse a template with a literal prefix followed by a syntax error placeholder.
	f, diags := hclsyntax.ParseConfig([]byte(`x = "prefix-${"`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
	if !diags.HasErrors() {
		t.Fatal("expected parse error")
	}
	_ = f
	// Construct the template manually to avoid parse-level rejection.
	errExpr := &hclsyntax.ExprSyntaxError{}
	val := expressionToASTTemplateExpr(&hclsyntax.TemplateExpr{
		Parts: []hclsyntax.Expression{errExpr},
	})
	if got := val.String(); got != `"${...}"` {
		t.Errorf("expressionToASTTemplateExpr = %s, want \"${...}\"", got)
	}
}

func TestExpressionToAST_ForExpr(t *testing.T) {
	t.Run("tuple_for", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`[for x in var.list : x]`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		got := val.String()
		want := `"[for x in var.list : x]"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})
	t.Run("tuple_for_two_vars", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`[for k, v in var.map : k]`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		got := val.String()
		want := `"[for k, v in var.map : k]"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})
}

func TestExpressionToAST_UnaryOpExpr(t *testing.T) {
	t.Run("negate", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`-1`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		got := val.String()
		want := `"-1"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})
	t.Run("logical_not", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`!var.enabled`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		got := val.String()
		want := `"!var.enabled"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})
}

func TestExpressionToAST_ScopeTraversalWithIndex(t *testing.T) {
	t.Run("numeric_index_uses_brackets", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("var.list[0]"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}

		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		got := val.String()
		want := `"var.list[0]"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})

	t.Run("string_index_uses_brackets", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`var.map["key"]`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}

		val, err := expressionToAST(expr)
		if err != nil {
			t.Fatalf("expressionToAST error: %v", err)
		}
		got := val.String()
		want := `"var.map[key]"`
		if got != want {
			t.Errorf("expressionToAST = %s, want %s", got, want)
		}
	})
}

func TestInspector_checkComment(t *testing.T) {
	tests := []struct {
		name  string
		lines []int
		line  int
		want  bool
	}{
		{
			name:  "test_checkComment_true",
			lines: []int{1, 2, 3, 4, 5, 6},
			line:  3,
			want:  true,
		},
		{
			name:  "test_checkComment_false",
			lines: []int{1, 2, 3, 4, 5, 6},
			line:  7,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkComment(tt.line, tt.lines); got != tt.want {
				t.Errorf("checkComment() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRulePathExcluded(t *testing.T) {
	tests := []struct {
		name        string
		filePath    string
		ignorePaths []string
		onlyPaths   []string
		want        bool
	}{
		{
			name:        "no filters",
			filePath:    "/repo/src/main.tf",
			ignorePaths: nil,
			onlyPaths:   nil,
			want:        false,
		},
		{
			name:        "ignored by ignore-paths",
			filePath:    "/repo/test/fixture.tf",
			ignorePaths: []string{"/repo/test"},
			onlyPaths:   nil,
			want:        true,
		},
		{
			name:        "not ignored",
			filePath:    "/repo/src/main.tf",
			ignorePaths: []string{"/repo/test"},
			onlyPaths:   nil,
			want:        false,
		},
		{
			name:        "only-paths match",
			filePath:    "/repo/src/main.tf",
			ignorePaths: nil,
			onlyPaths:   []string{"/repo/src"},
			want:        false,
		},
		{
			name:        "only-paths no match",
			filePath:    "/repo/test/fixture.tf",
			ignorePaths: nil,
			onlyPaths:   []string{"/repo/src"},
			want:        true,
		},
		{
			name:        "ignore-paths takes precedence over only-paths",
			filePath:    "/repo/src/main.tf",
			ignorePaths: []string{"/repo/src"},
			onlyPaths:   []string{"/repo/src"},
			want:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rulePathExcluded(tt.filePath, tt.ignorePaths, tt.onlyPaths))
		})
	}
}

// TestInspector_FailedQueriesConcurrentWrites reproduces the data race on
// Inspector.failedQueries.
func TestInspector_FailedQueriesConcurrentWrites(t *testing.T) {
	buildErr := fmt.Errorf("vulnerability build failed")

	ins := newTestInspector(t, inspectorOpts{
		// vb always errors (and never with ErrNoResult), forcing the
		// worker-side failedQueries write in getVulnerabilitiesFromQuery.
		vb: func(_ context.Context, _ *QueryContext, _ Tracker, _ interface{},
			_ *detector.DetectLine, _ bool, _ time.Duration) (*model.Vulnerability, error) {
			return nil, buildErr
		},
	})

	ctx := context.Background()

	const goroutines = 64
	queries := make([]model.QueryMetadata, goroutines)
	for i := range queries {
		queries[i] = model.QueryMetadata{Query: fmt.Sprintf("query-%d", i)}
	}

	var wg sync.WaitGroup
	// start gates every goroutine so the writes overlap instead of running
	// serially as each goroutine is scheduled.
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		i := i

		// Worker path: getVulnerabilitiesFromQuery writes failedQueries on a vb error.
		wg.Add(1)
		go func() {
			defer wg.Done()
			qCtx := &QueryContext{
				Ctx:   ctx,
				Query: &PreparedQuery{Metadata: queries[i]},
				Files: map[string]*model.FileMetadata{},
			}
			<-start
			getVulnerabilitiesFromQuery(ctx, qCtx, ins, struct{}{}, 0)
		}()

		// Collector path: processResult writes failedQueries on a query error.
		wg.Add(1)
		go func() {
			defer wg.Done()
			vulns := make([]model.Vulnerability, 0)
			moduleVulns := make(map[string]moduleVulnCounts)
			result := QueryResult{err: buildErr, queryID: i}
			<-start
			processResult(ctx, &result, &vulns, &moduleVulns, queries, ins)
		}()
	}

	close(start)
	wg.Wait()

	// Sanity: the failures were actually recorded
	require.NotEmpty(t, ins.GetFailedQueries())
}

// The module info log must use a surviving finding's already-resolved
// severity (case-normalized, overridable) rather than the raw pre-decode
// value, which can differ in case or have been overridden downstream.
func TestProcessResult_LogsASurvivingFindingsSeverityOverTheRawOne(t *testing.T) {
	var logs bytes.Buffer
	ctx := zerolog.New(&logs).WithContext(context.Background())
	ins := newTestInspector(t, inspectorOpts{})
	queries := []model.QueryMetadata{{Query: "my-rule"}}
	result := QueryResult{
		queryID:             0,
		moduleResultsRaised: 1,
		moduleSeverity:      "high", // raw, lowercase: not a valid model.Severity as-is
		vulnerabilities: []model.Vulnerability{
			{ResourceType: moduleCallRoot, Severity: model.SeverityCritical},
		},
	}
	vulns := make([]model.Vulnerability, 0)
	moduleVulns := make(map[string]moduleVulnCounts)
	processResult(ctx, &result, &vulns, &moduleVulns, queries, ins)
	require.Contains(t, logs.String(), "CRITICAL")
	require.NotContains(t, logs.String(), "high")
}

// When every module result was filtered or deduplicated before decode, the
// raw pre-decode severity is the only one available; it must still be
// normalized the same way a resolved finding's severity would be.
func TestProcessResult_NormalizesTheRawSeverityWhenNothingSurvivedDecode(t *testing.T) {
	var logs bytes.Buffer
	ctx := zerolog.New(&logs).WithContext(context.Background())
	ins := newTestInspector(t, inspectorOpts{})
	queries := []model.QueryMetadata{{Query: "my-rule"}}
	result := QueryResult{
		queryID:             0,
		moduleResultsRaised: 1,
		moduleSeverity:      "high",
		// No surviving vulnerabilities: every module result was filtered or
		// deduplicated before decode.
	}
	vulns := make([]model.Vulnerability, 0)
	moduleVulns := make(map[string]moduleVulnCounts)
	processResult(ctx, &result, &vulns, &moduleVulns, queries, ins)
	require.Contains(t, logs.String(), "HIGH")
	require.NotContains(t, logs.String(), "\"high\"")
}

// TestExecuteQueries_CanceledContextReturnsError guards the cancellation
// contract: a scan whose context is canceled must surface ctx.Err() rather than
// be reported as a successful scan with partial/empty results.
func TestExecuteQueries_CanceledContextReturnsError(t *testing.T) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: io.Discard})

	queries := []model.QueryMetadata{
		{Query: "query-0", Platform: "terraform"},
		{Query: "query-1", Platform: "terraform"},
	}
	inspector := newTestInspector(t, inspectorOpts{numWorkers: len(queries), queries: queries})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled scan

	vulns, err := inspector.executeQueries(
		ctx,
		"scan-id",
		map[string]*model.FileMetadata{},
		platformPayloads{},
		queries,
		nil,
		map[string]storage.Store{},
		nil,
		nil,
		nil,
	)

	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, vulns)
}

func TestExpandModuleFindings_NoExtrasUnchanged(t *testing.T) {
	vulns := []model.Vulnerability{{FileID: "primary", QueryName: "rule-a"}}
	got := expandModuleFindings(vulns, nil, nil)
	require.Equal(t, vulns, got)
}

func TestExpandModuleFindings_ClonesPerExtraCaller(t *testing.T) {
	primaryID := "primary\x00stack-a|module.app\x00this"
	extraID := "extra\x00stack-b|module.app\x00this"
	extras := map[string][]extraCallerInfo{
		primaryID: {{callChain: "stack-b|module.app", docID: extraID}},
	}
	path := model.SourcePath{{Key: "resource"}, {Key: "aws_s3_bucket"}, {Key: "this"}}
	primary := &model.ResourceOccurrence{DocumentID: "primary", StructuralPath: path}
	extra := &model.ResourceOccurrence{DocumentID: "extra", StructuralPath: path}
	vulns := []model.Vulnerability{{
		FileID:              primaryID,
		FileName:            "modules/app/main.tf",
		Line:                5,
		QueryName:           "rule-a",
		ResourceOccurrences: []*model.ResourceOccurrence{primary},
	}}
	got := expandModuleFindings(vulns, extras, documentOccurrenceIndex{extraID: {extra}})
	require.Len(t, got, 2)
	require.Equal(t, primaryID, got[0].FileID)
	require.Equal(t, extraID, got[1].FileID)
	require.Equal(t, "stack-b|module.app", got[1].ModuleCallChain)
	require.Equal(t, got[0].Line, got[1].Line)
	require.Equal(t, got[0].FileName, got[1].FileName)
	require.Equal(t, got[0].QueryName, got[1].QueryName)
	require.Equal(t, []*model.ResourceOccurrence{primary}, got[0].ResourceOccurrences)
	require.Equal(t, []*model.ResourceOccurrence{extra}, got[1].ResourceOccurrences)
}

func TestInspectorExternalModulePathBypassesRulePathFilter(t *testing.T) {
	ins := &Inspector{}
	ins.SetExternalModulePaths([]string{"/tmp/remote-module"})

	require.True(t, ins.isExternalModulePath("/tmp/remote-module/main.tf"))
	require.True(t, rulePathExcluded("/tmp/remote-module/main.tf", nil, []string{"/repo/src"}))
	require.False(t, ins.rulePathsExcluded([]string{"/tmp/remote-module/main.tf"}, nil, []string{"/repo/src"}))
	require.False(t, ins.rulePathsExcluded([]string{"/tmp/remote-module/main.tf"}, []string{"/tmp/**"}, nil))
}

// The archive a packaged dependency was rendered from is one more path its
// findings are known by, so a glob naming it drops them.
func TestInspectorRulePathsExcludedNamesArchive(t *testing.T) {
	ins := &Inspector{}
	paths := []string{"app/charts/lib/templates/pod.yaml", "app/Chart.yaml", "app/charts/lib-1.0.0.tgz"}
	require.True(t, ins.rulePathsExcluded(paths, []string{"app/charts/*.tgz"}, nil))
	require.False(t, ins.rulePathsExcluded(paths[:2], []string{"app/charts/*.tgz"}, nil))
}

// A file inside a chart archive is known by its path in the archive and by the
// declaration it is reported at; the rule's filters apply to both.
func TestInspectorRulePathsExcludedArchiveFile(t *testing.T) {
	ins := &Inspector{}
	paths := []string{"app/charts/pkg/templates/pod.yaml", "app/Chart.yaml"}
	tests := []struct {
		name         string
		ignore, only []string
		want         bool
	}{
		{name: "no filters", want: false},
		{name: "ignore matching the archive", ignore: []string{"app/charts/**"}, want: true},
		{name: "ignore matching the declaration", ignore: []string{"app/Chart.yaml"}, want: true},
		{name: "ignore matching neither", ignore: []string{"lib/**"}, want: false},
		{name: "only matching the declaration", only: []string{"app/Chart.yaml"}, want: false},
		{name: "only matching the archive", only: []string{"app/charts/**"}, want: false},
		{name: "only matching neither", only: []string{"lib/**"}, want: true},
		{name: "ignore wins over only", ignore: []string{"app/charts/**"}, only: []string{"app/Chart.yaml"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ins.rulePathsExcluded(paths, tt.ignore, tt.only))
		})
	}
}

// TestNodeFingerprintOf verifies the fingerprint used to validate byPointer
// hits: equal-content nodes at different addresses share a fingerprint,
// different-content nodes do not, and nodes holding non-canonical types have
// no fingerprint at all (their memos can never validate).
func TestNodeFingerprintOf(t *testing.T) {
	child := map[string]interface{}{"a": float64(1)}
	equalA := map[string]interface{}{"k": child, "s": "v", "b": true}
	equalB := map[string]interface{}{"s": "v", "k": child, "b": true}
	fpA, okA := nodeFingerprintOf(equalA)
	fpB, okB := nodeFingerprintOf(equalB)
	assert.True(t, okA)
	assert.True(t, okB)
	assert.Equal(t, fpA, fpB, "same content (shared child) must share a fingerprint regardless of key order")

	different := map[string]interface{}{"k": child, "s": "other", "b": true}
	fpD, okD := nodeFingerprintOf(different)
	assert.True(t, okD)
	assert.NotEqual(t, fpA, fpD, "a different scalar must change the fingerprint")

	otherChild := map[string]interface{}{"a": float64(2)}
	differentChild := map[string]interface{}{"k": otherChild, "s": "v", "b": true}
	fpC, okC := nodeFingerprintOf(differentChild)
	assert.True(t, okC)
	assert.NotEqual(t, fpA, fpC, "a different child object must change the fingerprint")

	// A node sharing the same child objects but with one extra key is a
	// different node and must not validate against the first memo.
	extraKey := map[string]interface{}{"k": child, "s": "v", "b": true, "x": nil}
	fpX, okX := nodeFingerprintOf(extraKey)
	assert.True(t, okX)
	assert.NotEqual(t, fpA, fpX)

	fpArrA, ok := nodeFingerprintOf([]interface{}{child, "x"})
	assert.True(t, ok)
	fpArrB, ok := nodeFingerprintOf([]interface{}{child, "x"})
	assert.True(t, ok)
	assert.Equal(t, fpArrA, fpArrB, "slices of equal content share a fingerprint")

	// Non-canonical child types disable memoization for their parents.
	unmemoizable := map[string]interface{}{"k": struct{ X int }{1}}
	_, ok = nodeFingerprintOf(unmemoizable)
	assert.False(t, ok, "non-canonical child type must yield no fingerprint")
}

// TestPayloadHashConsPointerMemoValidation covers the address-reuse safety of
// byPointer: a memo recorded for one node must not be served for a different
// node that happens to sit at the same address.
func TestPayloadHashConsPointerMemoValidation(t *testing.T) {
	cons := newPayloadHashCons()
	child := map[string]interface{}{"a": float64(1)}
	node := map[string]interface{}{"k": child, "s": "v"}
	// Record a memo for the node (val is irrelevant to validation).
	cons.setPointerMemo(0x1234, node, ast.String("first"))
	if memo, ok := cons.byPointer[0x1234]; ok && cons.pointerMemoMatches(memo, node) {
		// sanity: the fresh memo validates
	} else {
		t.Fatal("expected fresh memo to validate")
	}

	// A different node "reusing" the address must not match the memo.
	impostor := map[string]interface{}{"k": child, "s": "other"}
	memo, ok := cons.byPointer[0x1234]
	assert.True(t, ok)
	assert.False(t, cons.pointerMemoMatches(memo, impostor),
		"a different node at a recorded address must not be served the stale memo")

	// Content-equal but built from distinct child objects: by the runner-side
	// canonicalization guarantee such twins are the same object in practice;
	// at the engine boundary only same-child-pointer twins validate, which is
	// the conservative direction (a miss is safe, a stale hit is not).
	twinChild := map[string]interface{}{"a": float64(1)}
	distinct := map[string]interface{}{"k": twinChild, "s": "v"}
	assert.False(t, cons.pointerMemoMatches(memo, distinct),
		"a node with distinct child objects must not validate (conservative miss)")

	// Non-canizable nodes never validate.
	assert.False(t, cons.pointerMemoMatches(memo, map[string]interface{}{"k": struct{ X int }{}}))
}

func TestIdenticalOrEqualTerms(t *testing.T) {
	doc := ast.MustParseTerm(`{"resource": {"a": [1, {"b": true}]}}`)
	require.True(t, identicalOrEqualTerms(doc, doc))
	require.True(t, identicalOrEqualTerms(doc, &ast.Term{Value: doc.Value}))
	require.True(t, identicalOrEqualTerms(doc, ast.MustParseTerm(`{"resource": {"a": [1, {"b": true}]}}`)))
	require.False(t, identicalOrEqualTerms(doc, ast.MustParseTerm(`{"resource": {"a": [1, {"b": false}]}}`)))
	// Values backed by slices are compared by value without panicking.
	require.True(t, identicalOrEqualTerms(ast.MustParseTerm(`data.x.y`), ast.MustParseTerm(`data.x.y`)))
	require.False(t, identicalOrEqualTerms(ast.MustParseTerm(`"x"`), ast.MustParseTerm(`{"x": 1}`)))
}

// TestIdentityVirtualCacheMatchesOPA checks that memoized function calls
// taking whole documents give the results of OPA's own virtual cache.
func TestIdentityVirtualCacheMatchesOPA(t *testing.T) {
	ctx := context.Background()
	query, err := rego.New(
		rego.Query("data.p.out"),
		rego.Module("p.rego", `package p

f(doc, name) := doc.resource[name].v

out := {name: f(doc, name) | some doc in input.document; some name, _ in doc.resource}
`),
	).PrepareForEval(ctx)
	require.NoError(t, err)
	input := ast.MustParseTerm(`{"document": [{"resource": {"a": {"v": 1}, "b": {"v": 2}}}, {"resource": {"c": {"v": 3}}}]}`).Value

	want, err := query.Eval(ctx, rego.EvalParsedInput(input))
	require.NoError(t, err)
	got, err := query.Eval(ctx, rego.EvalParsedInput(input), rego.EvalVirtualCache(newIdentityVirtualCache()))
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Equal(t, map[string]interface{}{"a": json.Number("1"), "b": json.Number("2"), "c": json.Number("3")},
		got[0].Expressions[0].Value)
}

func TestInspectorQueryConcurrency(t *testing.T) {
	for _, workers := range []int{1, 2, utils.AvailableCPUs() + 1} {
		inspector := &Inspector{numWorkers: workers}
		require.Equal(t, min(workers, utils.AvailableCPUs()), inspector.QueryConcurrency())
	}
}

// TestContractV2TerraformEvaluationAndCoexistence verifies the full Contract v2
// lifecycle end-to-end inside Inspector.Inspect:
//   - Entry-rule routing (`results` vs legacy `DatadogPolicy`) with zero metadata.json changes
//   - 4-state unknowns + attr-filtered single-compiler verification of negated exemptions
//   - Proof/remediation separation (`after`-only replacement extracting `before` from source)
//   - Intra-root companion relations (`iac.no_related`)
//   - Embedded JSON with typed `json_refs` provenance (no regexes)
//   - Unified HCL and Terraform Plan JSON evaluation with the exact same Rego rule
//   - Coexistence of Contract v2 and legacy rules in the same scan with fingerprint parity
func TestContractV2TerraformEvaluationAndCoexistence(t *testing.T) {
	ctx := context.Background()
	t.Run("companion completeness matrix", testContractV2CompanionCompletenessMatrix)

	tfSource := `
variable "unknown_mode" {}
variable "unknown_enc" {}

data "aws_caller_identity" "current" {}

resource "aws_rds_cluster" "unencrypted_known" {
  engine_mode       = "provisioned"
  storage_encrypted = false
}

resource "aws_rds_cluster" "unknown_exempt" {
  engine_mode       = var.unknown_mode
  storage_encrypted = false
}

resource "aws_rds_cluster" "unknown_encrypted" {
  engine_mode       = "provisioned"
  storage_encrypted = var.unknown_enc
}

resource "aws_s3_bucket" "versioned_via_companion" {
  bucket = "good-bucket"
}

resource "aws_s3_bucket_versioning" "good" {
  bucket = aws_s3_bucket.versioned_via_companion.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "unversioned" {
  bucket = "bad-bucket"
}

resource "aws_s3_bucket" "zero_count" {
  count  = 0
  bucket = "never-created"
}

resource "aws_kms_key" "own_account" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "kms:*"
      Resource  = "*"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
    }]
  })
}

resource "aws_kms_key" "wildcard_public" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "kms:*"
      Resource  = "*"
      Principal = { AWS = "*" }
    }]
  })
}

resource "terraform_data" "slot_provenance" {
  input = {
    "_dd_root" = "source-root"
    "_dd_prefix" = "source-prefix"
    "_dd_parent_state" = {unknown = {"input._dd_root" = true}}
    marker_map = {"$unknown" = true}
    marker_list = [{"$unknown" = true, "_dd_root" = "slot-root", "_dd_prefix" = "slot-prefix", "_dd_parent_state" = {unknown = {"input.marker_list.0.value" = true}}, "_dd_value" = {forged = "reserved-data"}, value = "slot-value"}, var.unknown_mode, null]
  }
}

resource "aws_kms_key" "slot_provenance_json" {
  policy = jsonencode({
    "" = null
    "_dd_root" = "json-root"
    "_dd_prefix" = "json-prefix"
    "_dd_parent_state" = {"unknown" = {"known" = true}}
    known = "json-known"
    marker = {"$unknown" = true}
    items = [{"$unknown" = true}, var.unknown_mode, null]
  })
}
`

	planSource := `{
  "format_version": "1.2",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.plan_unversioned",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "plan_unversioned",
          "values": { "bucket": "plan-bad" }
        }
      ]
    }
  },
  "configuration": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.plan_unversioned",
          "expressions": { "bucket": { "constant_value": "plan-bad" } }
        }
      ]
    }
  }
}`

	fs := vfs.NewMemFS(map[string][]byte{
		"/repo/main.tf":     []byte(tfSource),
		"/repo/tfplan.json": []byte(planSource),
	})

	// Rule 1 (v2): RDS storage_encrypted using fail-closed 3-valued iac.not_equals
	// and scanner-derived `after` replacement remediation.
	rdsRuleV2 := model.QueryMetadata{
		Query:    "rds_v2",
		Platform: "terraform",
		Metadata: map[string]interface{}{
			"id":        "terraform-aws-rds-storage-not-encrypted-v2",
			"queryName": "RDS storage not encrypted",
			"severity":  model.SeverityHigh,
			"platform":  "Terraform",
		},
		Content: `package datadog

import rego.v1

import data.datadog.iac
import data.datadog.output as dd_output

results contains result if {
	some cluster in input.resources.aws_rds_cluster
	iac.not_equals(cluster, ["engine_mode"], "serverless")
	iac.is_false(cluster, ["storage_encrypted"])
	result := dd_output.format(cluster, {
		"path": ["storage_encrypted"],
		"after": "true",
	})
}
`,
		Aggregation: 1,
	}

	// Rule 2 (v2): S3 bucket without versioning (companion relation + HCL & Plan unity).
	s3RuleV2 := model.QueryMetadata{
		Query:    "s3_v2",
		Platform: "terraform",
		Metadata: map[string]interface{}{
			"id":        "terraform-aws-s3-bucket-without-versioning",
			"queryName": "S3 bucket without versioning",
			"severity":  model.SeverityMedium,
			"platform":  "Terraform",
		},
		Content: `package datadog

import rego.v1

import data.datadog.iac
import data.datadog.output as dd_output

results contains result if {
	some bucket in input.resources.aws_s3_bucket
	iac.is_empty(bucket, ["versioning"])
	iac.no_related(bucket, "aws_s3_bucket_versioning", "bucket")
	result := dd_output.format(bucket, {"path": []})
}
`,
		Aggregation: 1,
	}

	// Rule 3 (v2): KMS key with typed json_refs (zero regexes over ${...}).
	kmsRuleV2 := model.QueryMetadata{
		Query:    "kms_v2",
		Platform: "terraform",
		Metadata: map[string]interface{}{
			"id":        "terraform-aws-kms-key-full-perms-v2",
			"queryName": "KMS key full permissions",
			"severity":  model.SeverityHigh,
			"platform":  "Terraform",
		},
		Content: `package datadog

import rego.v1

import data.datadog.iac
import data.datadog.output as dd_output

own_account(key, idx) if {
	some ref in iac.json_refs(key, ["policy"], ["Statement", idx, "Principal", "AWS"])
	ref.kind == "data"
	ref.type == "aws_caller_identity"
	ref.attr == "account_id"
}

results contains result if {
	some key in input.resources.aws_kms_key
	policy := iac.json_doc(key, ["policy"])
	some idx, stmt in policy.Statement
	stmt.Effect == "Allow"
	stmt.Action == "kms:*"
	stmt.Principal.AWS == "*"
	not own_account(key, idx)
	result := dd_output.format(key, {"path": ["policy"]})
}
`,
		Aggregation: 1,
	}

	// Rule 4 (v2): the user data can contain the reserved-looking marker shape;
	// only indexed paths explicitly marked unknown in ValueState are unknown.
	slotProvenanceRuleV2 := model.QueryMetadata{
		Query:    "slot_provenance_v2",
		Platform: "terraform",
		Metadata: map[string]interface{}{
			"id":        "terraform-slot-provenance-v2",
			"queryName": "Unknown slot provenance",
			"severity":  model.SeverityMedium,
			"platform":  "Terraform",
		},
		Content: `package datadog

import rego.v1

import data.datadog.iac
import data.datadog.output as dd_output

results contains result if {
	some r in input.resources.terraform_data
	iac.get(r, ["input", "marker_map", "$unknown"]) == true
	"$unknown" in iac.object_keys(r, ["input", "marker_map"])
	some input_view in iac.blocks(r, "input")
	iac.get(input_view, ["_dd_root"]) == "source-root"
	"_dd_root" in iac.object_keys(input_view, [])
	items := iac.known_items(r, ["input", "marker_list"])
	count(items) == 1
	items[0]["$unknown"] == true
	iac.get(items[0], ["_dd_root"]) == "slot-root"
	iac.get(items[0], ["value"]) == "slot-value"
	iac.get(items[0], ["_dd_value", "forged"]) == "reserved-data"
	"_dd_prefix" in iac.object_keys(items[0], [])
	iac.indexed_items(r, ["input", "marker_list"]) == [[0, items[0]]]
	iac.is_unknown(r, ["input", "marker_list", 1])
	iac.is_null_value(r, ["input", "marker_list", 2])
	not iac.is_unknown(r, ["input", "marker_list", 2])
	result := dd_output.format(r, {"path": ["input"]})
}

results contains result if {
	some key in input.resources.aws_kms_key
	doc := iac.json_doc(key, ["policy"])
	iac.get(doc, ["marker", "$unknown"]) == true
	"$unknown" in iac.object_keys(doc, ["marker"])
	iac.get(doc, ["_dd_root"]) == "json-root"
	"_dd_root" in iac.object_keys(doc, [])
	iac.get(doc, ["known"]) == "json-known"
	iac.is_null_value(doc, [""])
	not iac.is_unknown(doc, [""])
	not iac.is_known(doc, [""])
	result := dd_output.format(key, {"path": ["policy", "marker"]})
}

results contains result if {
	some key in input.resources.aws_kms_key
	doc := iac.json_doc(key, ["policy"])
	items := iac.known_items(doc, ["items"])
	count(items) == 1
	items[0]["$unknown"] == true
	iac.indexed_items(doc, ["items"]) == [[0, items[0]]]
	iac.is_unknown(doc, ["items", 1])
	iac.is_null_value(doc, ["items", 2])
	not iac.is_unknown(doc, ["items", 2])
	not iac.is_known(doc, ["items", 2])
	result := dd_output.format(key, {"path": ["policy", "items"]})
}
`,
		Aggregation: 1,
	}

	// Rule 4 (legacy): Coexisting legacy DatadogPolicy rule targeting the same unversioned S3 bucket.
	s3RuleLegacy := model.QueryMetadata{
		Query:    "s3_legacy",
		Platform: "terraform",
		Metadata: map[string]interface{}{
			"id":        "terraform-aws-s3-bucket-without-versioning-legacy",
			"queryName": "S3 bucket legacy",
			"severity":  model.SeverityMedium,
			"platform":  "Terraform",
		},
		Content: `package datadog

import rego.v1

DatadogPolicy contains result if {
	some doc in input.document
	some name, bucket in doc.resource.aws_s3_bucket
	bucket.bucket == "bad-bucket"
	result := {
		"documentId": doc.id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
	}
}
`,
		Aggregation: 1,
	}

	mockSource := &mockQueriesSource{
		queries: []model.QueryMetadata{rdsRuleV2, s3RuleV2, kmsRuleV2, slotProvenanceRuleV2, s3RuleLegacy},
	}
	tkr := &tracker.CITracker{}
	ins, err := NewInspector(ctx, mockSource, DefaultVulnerabilityBuilder, tkr,
		&source.QueryInspectorParameters{}, nil, "/repo", false, true, 2, nil, fs, false)
	require.NoError(t, err)

	// Verify routing without metadata.json changes.
	require.True(t, UsesContractV2(&rdsRuleV2))
	require.True(t, UsesContractV2(&s3RuleV2))
	require.True(t, UsesContractV2(&kmsRuleV2))
	require.True(t, UsesContractV2(&slotProvenanceRuleV2))
	require.False(t, UsesContractV2(&s3RuleLegacy))
	require.False(t, ins.OnlyTerraformContractV2([]string{"terraform"}))

	files := model.FileMetadatas{
		{
			ID:           "file-hcl",
			FilePath:     "/repo/main.tf",
			Kind:         model.KindTerraform,
			Platform:     "terraform",
			OriginalData: tfSource,
			Document: model.Document{
				"resource": map[string]interface{}{
					"aws_s3_bucket": map[string]interface{}{
						"unversioned": map[string]interface{}{"bucket": "bad-bucket"},
					},
				},
			},
		},
		{
			ID:           "file-plan",
			FilePath:     "/repo/tfplan.json",
			Kind:         model.KindTerraformPlan,
			Platform:     "terraform",
			OriginalData: planSource,
			Document:     model.Document{},
		},
	}

	vulns, err := ins.Inspect(ctx, "scan-v2-test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	byQueryAndRes := map[string]model.Vulnerability{}
	for _, v := range vulns {
		byQueryAndRes[v.QueryID+"|"+v.ResourceName] = v
	}

	// 1. RDS: flags unencrypted_known with scanner-derived {"before":"false","after":"true"},
	// suppresses unknown_exempt (negated helper over unknown engine_mode), and skips unknown_encrypted.
	rdsFinding, ok := byQueryAndRes["terraform-aws-rds-storage-not-encrypted-v2|unencrypted_known"]
	require.True(t, ok, "known unencrypted provisioned cluster must fire")
	require.Equal(t, `{"after":"true","before":"false"}`, rdsFinding.Remediation)
	require.Equal(t, "replacement", rdsFinding.RemediationType)
	require.NotContains(t, byQueryAndRes, "terraform-aws-rds-storage-not-encrypted-v2|unknown_exempt",
		"negated exemption reading unknown engine_mode must be suppressed")
	require.NotContains(t, byQueryAndRes, "terraform-aws-rds-storage-not-encrypted-v2|unknown_encrypted")

	// 2. S3: flags HCL unversioned AND Plan plan_unversioned; skips companion-versioned & count=0.
	s3HCL, ok := byQueryAndRes["terraform-aws-s3-bucket-without-versioning|unversioned"]
	require.True(t, ok, "unversioned HCL bucket must fire")
	require.Equal(t, "/repo/main.tf", s3HCL.FileName)
	require.Contains(t, byQueryAndRes, "terraform-aws-s3-bucket-without-versioning|plan_unversioned",
		"same v2 rule must evaluate Terraform Plan JSON uniformly")
	require.NotContains(t, byQueryAndRes, "terraform-aws-s3-bucket-without-versioning|versioned_via_companion")
	require.NotContains(t, byQueryAndRes, "terraform-aws-s3-bucket-without-versioning|zero_count")

	// 3. KMS: flags wildcard_public, exempts own_account via typed json_refs.
	require.Contains(t, byQueryAndRes, "terraform-aws-kms-key-full-perms-v2|wildcard_public")
	require.NotContains(t, byQueryAndRes, "terraform-aws-kms-key-full-perms-v2|own_account")

	// 4. Marker-shaped user values remain known, while only state-marked list
	// slots are unknown and explicit null remains null. This covers direct HCL
	// attributes and JSON derived from jsonencode through the Go adapter.
	require.Contains(t, byQueryAndRes, "terraform-slot-provenance-v2|slot_provenance")
	require.Contains(t, byQueryAndRes, "terraform-slot-provenance-v2|slot_provenance_json")
	var jsonSlotPaths []string
	for _, finding := range vulns {
		if finding.QueryID == "terraform-slot-provenance-v2" && finding.ResourceName == "slot_provenance_json" {
			jsonSlotPaths = append(jsonSlotPaths, finding.SearchKey)
		}
	}
	require.ElementsMatch(t, []string{
		"aws_kms_key.slot_provenance_json.policy.marker",
		"aws_kms_key.slot_provenance_json.policy.items",
	}, jsonSlotPaths)

	// 5. Coexistence & fingerprint stability: legacy rule ran alongside v2 in the same scan
	// and shares the exact fingerprint input identity (modulo rule ID).
	s3Leg, ok := byQueryAndRes["terraform-aws-s3-bucket-without-versioning-legacy|unversioned"]
	require.True(t, ok, "coexisting legacy rule must still fire")
	fpV2 := model.GetDatadogFingerprintHash(model.SCIInfo{}, s3HCL.FileName, s3HCL.Platform, s3HCL.ResourceType, s3HCL.ResourceName, "same-rule", "", s3HCL.ModuleCallChain)
	fpLeg := model.GetDatadogFingerprintHash(model.SCIInfo{}, s3Leg.FileName, s3Leg.Platform, s3Leg.ResourceType, s3Leg.ResourceName, "same-rule", "", s3Leg.ModuleCallChain)
	require.Equal(t, fpLeg, fpV2, "Contract v2 and legacy findings on the same resource must produce identical fingerprints")

	// 5. Verify stateful nested blocks, index-preserving list items, constant-set
	// AST type extraction, repeated module call attribution, and fingerprint parity.
	t.Run("stateful_nested_blocks_modules_and_constant_sets", func(t *testing.T) {
		modFS := vfs.NewMemFS(map[string][]byte{
			"/repo/main.tf": []byte(`
variable "unk_enabled" {}
variable "unk_cidr" {}

module "app_a" {
  source = "./modules/s3"
  acl    = "public-read"
}

module "app_b" {
  source = "./modules/s3"
  acl    = "public-read-write"
}

resource "aws_s3_bucket" "enabled_inline" {
  bucket = "good-inline"
  versioning {
    enabled = true
  }
}

resource "aws_s3_bucket" "unknown_inline" {
  bucket = "unk-inline"
  versioning {
    enabled = var.unk_enabled
  }
}

resource "aws_s3_bucket" "disabled_inline" {
  bucket = "bad-inline"
  versioning {
    enabled = false
  }
}

resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = [var.unk_cidr, "0.0.0.0/0"]
  }
}
`),
			"/repo/modules/s3/main.tf": []byte(`
variable "acl" {}
resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`),
		})

		nestedRule := model.QueryMetadata{
			Query:    "nested_v2",
			Platform: "terraform",
			Metadata: map[string]interface{}{
				"id":        "terraform-nested-test",
				"queryName": "Nested versioning check",
				"severity":  model.SeverityMedium,
				"platform":  "Terraform",
			},
			Content: `package datadog

import rego.v1

import data.datadog.iac
import data.datadog.output as dd_output

target_types := {"aws_s3_bucket"}

results contains result if {
	some typ in target_types
	some bucket in input.resources[typ]
	some i, v in iac.blocks(bucket, "versioning")
	iac.is_unset(v, ["enabled"])
	result := dd_output.format(bucket, {"path": ["versioning", i, "enabled"]})
}

results contains result if {
	some typ in target_types
	some bucket in input.resources[typ]
	some i, v in iac.blocks(bucket, "versioning")
	iac.is_false(v, ["enabled"])
	result := dd_output.format(bucket, {"path": ["versioning", i, "enabled"], "after": "true"})
}
`,
			Aggregation: 1,
		}

		// Verify top-level constant set resolves statically (no wildcard fallback).
		spec, ok := analyzeContractV2Rule(&nestedRule)
		require.True(t, ok)
		require.False(t, spec.wildcard)
		require.True(t, spec.types["aws_s3_bucket"])

		modRule := model.QueryMetadata{
			Query:    "mod_acl_v2",
			Platform: "terraform",
			Metadata: map[string]interface{}{
				"id":        "terraform-mod-acl-v2",
				"queryName": "Public ACL",
				"severity":  model.SeverityHigh,
				"platform":  "Terraform",
			},
			Content: `package datadog

import rego.v1

import data.datadog.iac
import data.datadog.output as dd_output

results contains result if {
	some bucket in input.resources.aws_s3_bucket
	iac.get(bucket, ["acl"]) in {"public-read", "public-read-write"}
	result := dd_output.format(bucket, {"path": ["acl"]})
}
`,
			Aggregation: 1,
		}

		sgRule := model.QueryMetadata{
			Query:    "sg_indexed_v2",
			Platform: "terraform",
			Metadata: map[string]interface{}{
				"id":        "terraform-sg-indexed-v2",
				"queryName": "Open CIDR",
				"severity":  model.SeverityHigh,
				"platform":  "Terraform",
			},
			Content: `package datadog

import rego.v1

import data.datadog.iac
import data.datadog.output as dd_output

results contains result if {
	some sg in input.resources.aws_security_group
	some ing in iac.blocks(sg, "ingress")
	some [idx, cidr] in iac.indexed_items(ing, ["cidr_blocks"])
	cidr == "0.0.0.0/0"
	result := dd_output.format(sg, {"path": iac.path_of(ing, ["cidr_blocks", idx])})
}
`,
			Aggregation: 1,
		}

		legacyModuleRule := model.QueryMetadata{
			Query: "legacy-module-acl", Platform: "terraform", InputData: "{}", Aggregation: 1,
			Metadata: map[string]interface{}{"id": "legacy-module-acl", "platform": "Terraform"},
			Content:  displayNameAclRule,
		}
		src := &mockQueriesSource{queries: []model.QueryMetadata{nestedRule, modRule, sgRule, legacyModuleRule}}
		ins2, err := NewInspector(ctx, src, DefaultVulnerabilityBuilder, &tracker.CITracker{},
			&source.QueryInspectorParameters{}, nil, "/repo", false, true, 2, nil, modFS, false)
		require.NoError(t, err)
		ins2.SetCompactFindingsAtDecode(true)
		modInventory := &collectingSink{}
		ins2.SetInventory(modInventory)

		rootRaw, _ := modFS.ReadFile("/repo/main.tf")
		modRaw, _ := modFS.ReadFile("/repo/modules/s3/main.tf")
		modFiles := model.FileMetadatas{
			{ID: "f-root", FilePath: "/repo/main.tf", Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(rootRaw)},
			{ID: "f-mod", FilePath: "/repo/modules/s3/main.tf", Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(modRaw)},
		}

		got, err := ins2.Inspect(ctx, "scan-mod-test", modFiles, []string{"terraform"})
		require.NoError(t, err)
		require.Empty(t, ins2.GetFailedQueries())

		var nestedRes []string
		var modChains []string
		var modFindings []model.Vulnerability
		var sgFindings []model.Vulnerability
		for _, v := range got {
			switch v.QueryID {
			case "terraform-nested-test":
				nestedRes = append(nestedRes, v.ResourceName)
			case "terraform-mod-acl-v2":
				require.NotNil(t, v.ModuleAttribution, "child module finding must carry ModuleAttribution")
				modChains = append(modChains, v.ModuleCallChain)
				modFindings = append(modFindings, v)
			case "terraform-sg-indexed-v2":
				sgFindings = append(sgFindings, v)
			}
		}

		// Nested block 4-state: ONLY disabled_inline fires (NOT enabled_inline, NOT unknown_inline!).
		require.Equal(t, []string{"disabled_inline"}, nestedRes)
		// Repeated module calls keep BOTH distinct callers under compaction!
		require.ElementsMatch(t, []string{"main.tf|module.app_a", "main.tf|module.app_b"}, modChains)
		var moduleResourceAddresses []string
		for _, finding := range modFindings {
			require.NotEmpty(t, finding.ResourceOccurrences, "each module finding links to its inventory occurrence")
			for _, occurrence := range finding.ResourceOccurrences {
				moduleResourceAddresses = append(moduleResourceAddresses, occurrence.Terraform.Address)
			}
		}
		require.ElementsMatch(t, []string{"module.app_a.aws_s3_bucket.this", "module.app_b.aws_s3_bucket.this"}, moduleResourceAddresses)
		require.NotEmpty(t, modInventory.rows)
		// Index-preserving list: 0.0.0.0/0 is at original index 1 (NOT shifted to 0!).
		require.Len(t, sgFindings, 1)
		require.Equal(t, "aws_security_group.sg.ingress.0.cidr_blocks.1", sgFindings[0].SearchKey)
	})

	t.Run("provider_no_resources_object_sets_and_module_narrowing", func(t *testing.T) {
		// AST analysis checks: object value binding, mixed literal fallback, no_resources wildcard, multi-type scopeRoot.
		objValRule := model.QueryMetadata{
			Query: "obj-val",
			Content: `package datadog
import rego.v1
import data.datadog.output as dd_output
m := {"s3": "aws_s3_bucket"}
results contains result if {
	some rt in m
	some b in input.resources[rt]
	result := dd_output.format(b, {})
}`,
		}
		specObj, ok := analyzeContractV2Rule(&objValRule)
		require.True(t, ok)
		require.False(t, specObj.wildcard)
		require.True(t, specObj.types["aws_s3_bucket"])
		require.False(t, specObj.types["s3"])

		noResRule := model.QueryMetadata{
			Query:    "no-cloudtrail",
			Platform: "Terraform",
			Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some p in input.resources["provider.aws"]
	iac.no_resources("aws_cloudtrail")
	result := dd_output.format(p, {})
}`,
			Metadata:    map[string]interface{}{"id": "terraform-no-cloudtrail", "queryName": "No CloudTrail", "severity": "HIGH", "platform": "Terraform"},
			Aggregation: 1,
		}
		specNoRes, ok := analyzeContractV2Rule(&noResRule)
		require.True(t, ok)
		require.True(t, specNoRes.wildcard)
		require.True(t, specNoRes.hasNoResources)
		require.True(t, specNoRes.needsProviders)

		provOnlyFS := vfs.NewMemFS(map[string][]byte{
			"/repo/main.tf": []byte(`
provider "aws" {
  region = "us-east-1"
}
`),
		})
		provSrc := &mockQueriesSource{queries: []model.QueryMetadata{noResRule}}
		insProv, err := NewInspector(ctx, provSrc, DefaultVulnerabilityBuilder, &tracker.CITracker{},
			&source.QueryInspectorParameters{}, nil, "/repo", false, true, 1, nil, provOnlyFS, false)
		require.NoError(t, err)
		provRaw, _ := provOnlyFS.ReadFile("/repo/main.tf")
		provFiles := model.FileMetadatas{
			{ID: "f-prov", FilePath: "/repo/main.tf", Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(provRaw)},
		}
		provVulns, err := insProv.Inspect(ctx, "scan-prov-only", provFiles, []string{"terraform"})
		require.NoError(t, err)
		require.Len(t, provVulns, 1, "provider-only root with absent aws_cloudtrail must fire")
		require.Equal(t, "aws", provVulns[0].ResourceType)
	})

	t.Run("representative_rules_without_manual_unknown_guards", func(t *testing.T) {
		// Demonstrates representative real Contract v2 rules using the agreed
		// data.datadog.iac facade — absence, exemptions, collection checks, and
		// decoupled optional remediation — with zero manual unknown guards.
		compFS := vfs.NewMemFS(map[string][]byte{
			"/repo/main.tf": []byte(`
variable "unk_mode" {}
variable "unk_alg" {}
variable "unk_rules" {}
variable "unk_cidr" {}
variable "unk_bucket" {}

resource "aws_rds_cluster" "known_bad" {
  engine_mode       = "provisioned"
  storage_encrypted = false
}

resource "aws_rds_cluster" "unk_exempt" {
  engine_mode       = var.unk_mode
  storage_encrypted = false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "known_aes" {
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "unk_alg" {
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = var.unk_alg
    }
  }
}

resource "aws_security_group" "known_sg" {
  ingress {
    from_port   = 80
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "open_sg" {
  ingress {
    from_port   = 80
    cidr_blocks = [var.unk_cidr, "0.0.0.0/0"]
  }
  dynamic "ingress" {
    for_each = var.unk_rules
    content {
      from_port = ingress.value
    }
  }
}

resource "aws_s3_bucket" "b_known" {
  bucket = var.unk_bucket
  acl    = "public-read"
}

resource "aws_s3_bucket" "b_concrete" {
  bucket = "prod-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket" "b_dyn_ver" {
  bucket = "dyn-ver-bucket"
  dynamic "versioning" {
    for_each = var.unk_rules
    content {
      enabled = true
    }
  }
}

resource "aws_s3_bucket_versioning" "v_unk" {
  bucket = var.unk_bucket
  versioning_configuration {
    status = "Enabled"
  }
}
`),
		})

		compRules := []model.QueryMetadata{
			{
				// 1. Exemption without manual unknown guards (iac.not_in + iac.is_false).
				Query: "rds-exemption", Platform: "terraform", Aggregation: 1,
				Metadata: map[string]interface{}{"id": "rep-exemption", "queryName": "RDS exemption", "severity": model.SeverityHigh, "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some c in input.resources.aws_rds_cluster
	iac.not_in(c, ["engine_mode"], {"serverless", "global"})
	iac.is_false(c, ["storage_encrypted"])
	result := dd_output.format(c, {"path": ["storage_encrypted"], "after": "true"})
}`,
			},
			{
				// 2. Depth-2 nested block exemption via stateful iac.blocks + iac.not_equals.
				Query: "depth2-nested", Platform: "terraform", Aggregation: 1,
				Metadata: map[string]interface{}{"id": "rep-depth2", "queryName": "Depth2", "severity": model.SeverityHigh, "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some s in input.resources.aws_s3_bucket_server_side_encryption_configuration
	some rule in iac.blocks(s, "rule")
	some apply in iac.blocks(rule, "apply_server_side_encryption_by_default")
	iac.not_equals(apply, ["sse_algorithm"], "aws:kms")
	result := dd_output.format(s, {"path": iac.path_of(apply, ["sse_algorithm"])})
}`,
			},
			{
				// 3. Absence check (iac.is_empty + iac.no_related) handles both dynamic blocks and unknown companions.
				Query: "s3-absence", Platform: "terraform", Aggregation: 1,
				Metadata: map[string]interface{}{"id": "rep-absence", "queryName": "S3 absence", "severity": model.SeverityMedium, "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some b in input.resources.aws_s3_bucket
	iac.is_empty(b, ["versioning"])
	iac.no_related(b, "aws_s3_bucket_versioning", "bucket")
	result := dd_output.format(b, {})
}`,
			},
			{
				// 4a. Collection check: complete_items + sort fails closed on unknown elements.
				Query: "collection-sort", Platform: "terraform", Aggregation: 1,
				Metadata: map[string]interface{}{"id": "rep-sort", "queryName": "Collection sort", "severity": model.SeverityHigh, "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some sg in input.resources.aws_security_group
	some ing in iac.blocks(sg, "ingress")
	ordered := sort(iac.complete_items(ing, ["cidr_blocks"]))
	ordered[0] == "0.0.0.0/0"
	result := dd_output.format(sg, {"path": iac.path_of(ing, ["cidr_blocks"])})
}`,
			},
			{
				// 4b. Collection check: closed-list length succeeds on ["unk", "0.0.0.0/0"], open dynamic block stays undefined.
				Query: "collection-length", Platform: "terraform", Aggregation: 1,
				Metadata: map[string]interface{}{"id": "rep-length", "queryName": "Collection length", "severity": model.SeverityMedium, "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some sg in input.resources.aws_security_group
	some ing in iac.blocks(sg, "ingress")
	iac.length(ing, ["cidr_blocks"]) == 2
	result := dd_output.format(sg, {"path": iac.path_of(ing, ["cidr_blocks"])})
}`,
			},
			{
				// 4c. Collection check: open dynamic block length must NOT fire.
				Query: "open-collection-length", Platform: "terraform", Aggregation: 1,
				Metadata: map[string]interface{}{"id": "rep-open-length", "queryName": "Open length", "severity": model.SeverityMedium, "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some sg in input.resources.aws_security_group
	iac.length(sg, ["ingress"]) == 1
	result := dd_output.format(sg, {"path": ["ingress"]})
}`,
			},
			{
				// 5. Explicit decoupled optional remediation: unknown remediation omits fix, preserves proven finding.
				Query: "decoupled-remediate", Platform: "terraform", Aggregation: 1,
				Metadata: map[string]interface{}{"id": "rep-rem", "queryName": "Decoupled rem", "severity": model.SeverityHigh, "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some b in input.resources.aws_s3_bucket
	iac.equals(b, ["acl"], "public-read")
	result := dd_output.format(b, {"path": ["acl"]})
}
remediate(b, _) := {
	"remediation": sprintf("lock %s", [iac.get(b, ["bucket"])]),
	"remediationType": "replacement",
}`,
			},
		}

		compSrc := &mockQueriesSource{queries: compRules}
		insComp, err := NewInspector(ctx, compSrc, DefaultVulnerabilityBuilder, &tracker.CITracker{},
			&source.QueryInspectorParameters{}, nil, "/repo", false, true, 2, nil, compFS, false)
		require.NoError(t, err)
		raw, _ := compFS.ReadFile("/repo/main.tf")
		compFiles := model.FileMetadatas{
			{ID: "f-comp", FilePath: "/repo/main.tf", Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(raw)},
		}
		got, err := insComp.Inspect(ctx, "scan-rep", compFiles, []string{"terraform"})
		require.NoError(t, err)
		require.Empty(t, insComp.GetFailedQueries())

		byQ := map[string][]string{}
		byQAndRes := map[string]model.Vulnerability{}
		for _, v := range got {
			byQ[v.QueryID] = append(byQ[v.QueryID], v.ResourceName)
			byQAndRes[v.QueryID+"|"+v.ResourceName] = v
		}
		require.Equal(t, []string{"known_bad"}, byQ["rep-exemption"])
		require.Equal(t, `{"after":"true","before":"false"}`, byQAndRes["rep-exemption|known_bad"].Remediation)
		require.Equal(t, []string{"known_aes"}, byQ["rep-depth2"])
		require.Empty(t, byQ["rep-absence"], "unknown companion + dynamic versioning must suppress absence findings")
		require.Equal(t, []string{"known_sg"}, byQ["rep-sort"], "sort(complete_items) must fail closed on partial list")
		require.Equal(t, []string{"open_sg"}, byQ["rep-length"], "iac.length proves known size on closed list with unknown element")
		require.Equal(t, []string{"known_sg"}, byQ["rep-open-length"], "iac.length must stay undefined on open dynamic block")
		require.ElementsMatch(t, []string{"b_known", "b_concrete"}, byQ["rep-rem"])
		require.Equal(t, "lock prod-bucket", byQAndRes["rep-rem|b_concrete"].Remediation)
		require.Empty(t, byQAndRes["rep-rem|b_known"].Remediation)
	})

	t.Run("root_isolation_enforced_independently", func(t *testing.T) {
		// Two independent roots (root_a has 1 bucket, root_b has 2 buckets).
		// Single-type rules using count/self-join/helper over input.resources
		// must be classified as scopeRoot=true and never mix resources across roots.
		isoFS := vfs.NewMemFS(map[string][]byte{
			"/repo/root_a/main.tf": []byte(`
resource "aws_s3_bucket" "only_a" {
  bucket = "a-bucket"
}
`),
			"/repo/root_b/main.tf": []byte(`
resource "aws_s3_bucket" "b1" {
  bucket = "b1-bucket"
}
resource "aws_s3_bucket" "b2" {
  bucket = "b2-bucket"
}
`),
		})
		countRule := model.QueryMetadata{
			Query: "single-type-count", Platform: "terraform", Aggregation: 1,
			Metadata: map[string]interface{}{"id": "iso-count", "queryName": "Root count", "severity": model.SeverityLow, "platform": "Terraform"},
			Content: `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
	count(input.resources.aws_s3_bucket) == 1
	some b in input.resources.aws_s3_bucket
	result := dd_output.format(b, {})
}`,
		}
		selfJoinRule := model.QueryMetadata{
			Query: "single-type-self-join", Platform: "terraform", Aggregation: 1,
			Metadata: map[string]interface{}{"id": "iso-self-join", "queryName": "Self join", "severity": model.SeverityLow, "platform": "Terraform"},
			Content: `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
	some a in input.resources.aws_s3_bucket
	some b in input.resources.aws_s3_bucket
	a.id != b.id
	result := dd_output.format(a, {})
}`,
		}
		helperRule := model.QueryMetadata{
			Query: "single-type-helper", Platform: "terraform", Aggregation: 1,
			Metadata: map[string]interface{}{"id": "iso-helper", "queryName": "Helper", "severity": model.SeverityLow, "platform": "Terraform"},
			Content: `package datadog
import rego.v1
import data.datadog.output as dd_output
has_b2 if {
	some x in input.resources.aws_s3_bucket
	x.name == "b2"
}
results contains result if {
	some a in input.resources.aws_s3_bucket
	not has_b2
	result := dd_output.format(a, {})
}`,
		}

		fixedIndexRule := model.QueryMetadata{
			Query: "single-type-fixed-index", Platform: "terraform", Aggregation: 1,
			Metadata: map[string]interface{}{"id": "iso-fixed-idx", "queryName": "Fixed idx", "severity": model.SeverityLow, "platform": "Terraform"},
			Content: `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
	b := input.resources.aws_s3_bucket[0]
	result := dd_output.format(b, {})
}`,
		}
		slicedRule := model.QueryMetadata{
			Query: "single-type-slice", Platform: "terraform", Aggregation: 1,
			Metadata: map[string]interface{}{"id": "iso-slice", "queryName": "Slice", "severity": model.SeverityLow, "platform": "Terraform"},
			Content: `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
	some b in array.slice(input.resources.aws_s3_bucket, 0, 1)
	result := dd_output.format(b, {})
}`,
		}

		keyedRule := fixedIndexRule
		keyedRule.Query = "single-type-keyed-iteration"
		keyedRule.Metadata = map[string]interface{}{"id": "iso-keyed", "queryName": "Keyed iteration", "severity": model.SeverityLow, "platform": "Terraform"}
		keyedRule.Content = strings.Replace(fixedIndexRule.Content, "b := input.resources.aws_s3_bucket[0]", "some i, b in input.resources.aws_s3_bucket\n\ti == 0", 1)

		for _, q := range []model.QueryMetadata{countRule, selfJoinRule, helperRule, fixedIndexRule, slicedRule, keyedRule} {
			spec, ok := analyzeContractV2Rule(&q)
			require.True(t, ok)
			require.True(t, spec.scopeRoot, "rule %s must be root-scoped to guarantee root isolation", q.Query)
		}

		isoSrc := &mockQueriesSource{queries: []model.QueryMetadata{countRule, selfJoinRule, helperRule, fixedIndexRule, slicedRule, keyedRule}}
		insIso, err := NewInspector(ctx, isoSrc, DefaultVulnerabilityBuilder, &tracker.CITracker{},
			&source.QueryInspectorParameters{}, nil, "/repo", false, true, 2, nil, isoFS, false)
		require.NoError(t, err)
		rawA, _ := isoFS.ReadFile("/repo/root_a/main.tf")
		rawB, _ := isoFS.ReadFile("/repo/root_b/main.tf")
		isoFiles := model.FileMetadatas{
			{ID: "f-a", FilePath: "/repo/root_a/main.tf", Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(rawA)},
			{ID: "f-b", FilePath: "/repo/root_b/main.tf", Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(rawB)},
		}
		got, err := insIso.Inspect(ctx, "scan-iso", isoFiles, []string{"terraform"})
		require.NoError(t, err)
		byQ := map[string][]string{}
		for _, v := range got {
			byQ[v.QueryID] = append(byQ[v.QueryID], v.ResourceName)
		}
		require.Equal(t, []string{"only_a"}, byQ["iso-count"], "root_a has 1 bucket; root_b must not contaminate root_a")
		require.ElementsMatch(t, []string{"b1", "b2"}, byQ["iso-self-join"], "root_b self-join must not see root_a")
		require.Equal(t, []string{"only_a"}, byQ["iso-helper"], "root_a must not see root_b's b2 bucket")
		require.Len(t, byQ["iso-fixed-idx"], 2, "fixed index [0] must evaluate once per root, not once per chunk")
		require.Len(t, byQ["iso-slice"], 2, "array.slice(..., 0, 1) must evaluate once per root, not once per chunk")
		require.Len(t, byQ["iso-keyed"], 2, "constrained keyed iteration must evaluate once per root")

		// Unresolved remote module must set scope_complete=false, suppressing iac.no_related,
		// and .tf.json object-form blocks must align unknown-state paths with iac.blocks.
		edgeFS := vfs.NewMemFS(map[string][]byte{
			"/repo/unresolved/main.tf": []byte(`
resource "aws_s3_bucket" "b" {
  bucket = "app-bucket"
}
module "remote_ver" {
  source = "terraform-aws-modules/s3-bucket/aws"
  bucket = aws_s3_bucket.b.id
}
`),
			"/repo/json_block/main.tf.json": []byte(`{
  "variable": { "unk_enabled": {} },
  "resource": {
    "aws_s3_bucket": {
      "json_unk": {
        "bucket": "json-bucket",
        "versioning": { "enabled": "${var.unk_enabled}" }
      }
    }
  }
}`),
		})
		edgeRules := []model.QueryMetadata{
			{
				Query: "unresolved-mod-absence", Platform: "terraform", Aggregation: 1,
				Metadata: map[string]interface{}{"id": "edge-unresolved-mod", "queryName": "Unresolved mod", "severity": model.SeverityMedium, "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some b in input.resources.aws_s3_bucket
	iac.no_related(b, "aws_s3_bucket_versioning", "bucket")
	result := dd_output.format(b, {})
}`,
			},
			{
				Query: "json-obj-block-unknown", Platform: "terraform", Aggregation: 1,
				Metadata: map[string]interface{}{"id": "edge-json-blk", "queryName": "JSON obj block", "severity": model.SeverityMedium, "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some b in input.resources.aws_s3_bucket
	some v in iac.blocks(b, "versioning")
	iac.is_unset(v, ["enabled"])
	result := dd_output.format(b, {"path": iac.path_of(v, ["enabled"])})
}`,
			},
		}
		edgeSrc := &mockQueriesSource{queries: edgeRules}
		insEdge, err := NewInspector(ctx, edgeSrc, DefaultVulnerabilityBuilder, &tracker.CITracker{},
			&source.QueryInspectorParameters{}, nil, "/repo", false, true, 2, nil, edgeFS, false)
		require.NoError(t, err)
		uRaw, _ := edgeFS.ReadFile("/repo/unresolved/main.tf")
		jRaw, _ := edgeFS.ReadFile("/repo/json_block/main.tf.json")
		edgeFiles := model.FileMetadatas{
			{ID: "f-unres", FilePath: "/repo/unresolved/main.tf", Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(uRaw)},
			{ID: "f-jblk", FilePath: "/repo/json_block/main.tf.json", Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(jRaw)},
		}
		edgeGot, err := insEdge.Inspect(ctx, "scan-edge", edgeFiles, []string{"terraform"})
		require.NoError(t, err)
		for _, v := range edgeGot {
			if v.QueryID == "edge-unresolved-mod" {
				require.NotEqual(t, "b", v.ResourceName, "unresolved remote module must mark root scope_complete=false")
			}
			require.NotEqual(t, "edge-json-blk", v.QueryID, ".tf.json object-form block unknown enabled must not trigger iac.is_unset")
		}
	})

	t.Run("bound index root isolation, partial JSON unknown Condition, known map length, and mutation-driven evaluation", func(t *testing.T) {
		fs := vfs.NewMemFS(map[string][]byte{
			"/repo/r1/main.tf": []byte(`
resource "aws_s3_bucket" "b1" {
  bucket = "b1"
}
`),
			"/repo/r2/main.tf": []byte(`
resource "aws_s3_bucket" "b2" {
  bucket = "b2"
}
`),
			"/repo/json_and_tags/main.tf": []byte(`
variable "cond" {}
variable "accts" {}
variable "env" {}
variable "dyn_key" {}

resource "aws_kms_key" "with_unknown_cond" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "kms:*"
      Resource  = "*"
      Condition = var.cond
    }]
  })
}

data "aws_iam_policy_document" "unknown_cond_vals" {
  statement {
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = var.accts
    }
  }
}

resource "aws_kms_key" "with_data_unknown_cond" {
  policy = data.aws_iam_policy_document.unknown_cond_vals.json
}

resource "aws_kms_key" "missing_cond" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

resource "aws_s3_bucket" "known_key_unknown_val" {
  bucket = "tagged"
  rules = [{ enabled = var.env }, {}]
  tags = {
    Env = var.env
  }
}

resource "aws_s3_bucket" "unknown_key_map" {
  bucket = "dyn-tagged"
  tags = {
    (var.dyn_key) = "prod"
  }
}
`),
		})
		rules := []model.QueryMetadata{
			{
				Query:       "bound_idx",
				Platform:    "terraform",
				Aggregation: 1,
				Metadata:    map[string]any{"id": "bound-idx-root-scope", "queryName": "Bound idx", "severity": model.SeverityMedium, "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	i := 0
	b := input.resources.aws_s3_bucket[i]
	iac.get(b, ["bucket"]) in {"b1", "b2"}
	result := dd_output.format(b, {"path": ["bucket"]})
}`,
			},
			{
				Query:       "partial_json_cond",
				Platform:    "terraform",
				Aggregation: 1,
				Metadata:    map[string]any{"id": "partial-json-cond", "queryName": "Partial JSON cond", "severity": model.SeverityMedium, "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some k in input.resources.aws_kms_key
	doc := iac.json_doc(k, ["policy"])
	some stmt in iac.blocks(doc, "Statement")
	iac.equals(stmt, ["Effect"], "Allow")
	iac.is_unset(stmt, ["Condition"])
	result := dd_output.format(k, {"path": ["policy"]})
}`,
			},
			{
				Query:       "map_known_len",
				Platform:    "terraform",
				Aggregation: 1,
				Metadata:    map[string]any{"id": "map-known-len", "queryName": "Map known len", "severity": model.SeverityMedium, "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some b in input.resources.aws_s3_bucket
	iac.length(b, ["tags"]) == 1
	not iac.is_empty(b, ["tags"])
	result := dd_output.format(b, {"path": ["tags"]})
}`,
			},
		}
		for _, helper := range []string{"known_items", "indexed_items"} {
			iteration := "some item in iac.known_items(b, [\"rules\"])"
			if helper == "indexed_items" {
				iteration = "some pair in iac.indexed_items(b, [\"rules\"])\n\titem := pair[1]"
			}
			rules = append(rules, model.QueryMetadata{
				Query: helper, Platform: "terraform", Aggregation: 1,
				Metadata: map[string]any{"id": helper, "queryName": helper, "severity": model.SeverityLow, "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some b in input.resources.aws_s3_bucket
	` + iteration + `
	iac.is_unset(item, ["enabled"])
	result := dd_output.format(b, {"path": iac.path_of(item, ["enabled"])})
}`,
			})
		}
		ins, err := NewInspector(ctx, &mockQueriesSource{queries: rules}, DefaultVulnerabilityBuilder, &tracker.CITracker{},
			&source.QueryInspectorParameters{}, nil, "/repo", false, true, 2, nil, fs, false)
		require.NoError(t, err)
		r1Raw, _ := fs.ReadFile("/repo/r1/main.tf")
		r2Raw, _ := fs.ReadFile("/repo/r2/main.tf")
		jtRaw, _ := fs.ReadFile("/repo/json_and_tags/main.tf")
		got, err := ins.Inspect(ctx, "scan-review2", model.FileMetadatas{
			{ID: "f-r1", FilePath: "/repo/r1/main.tf", Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(r1Raw)},
			{ID: "f-r2", FilePath: "/repo/r2/main.tf", Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(r2Raw)},
			{ID: "f-jt", FilePath: "/repo/json_and_tags/main.tf", Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(jtRaw)},
		}, []string{"terraform"})
		require.NoError(t, err)

		var boundNames, jsonCondNames, mapLenNames []string
		itemFindings := map[string][]model.Vulnerability{}
		for _, v := range got {
			switch v.QueryID {
			case "known_items", "indexed_items":
				itemFindings[v.QueryID] = append(itemFindings[v.QueryID], v)
			case "bound-idx-root-scope":
				boundNames = append(boundNames, v.ResourceName)
			case "partial-json-cond":
				jsonCondNames = append(jsonCondNames, v.ResourceName)
			case "map-known-len":
				mapLenNames = append(mapLenNames, v.ResourceName)
			}
		}
		for _, helper := range []string{"known_items", "indexed_items"} {
			require.Len(t, itemFindings[helper], 1, "%s must preserve unknown children and report only the absent one", helper)
			require.Equal(t, "known_key_unknown_val", itemFindings[helper][0].ResourceName)
		}
		require.ElementsMatch(t, []string{"b1", "b2"}, boundNames, "bound-index selection must stay root-scoped and report both roots")
		require.Equal(t, []string{"missing_cond"}, jsonCondNames, "unknown Condition in partial JSON must not produce a false positive")
		require.Equal(t, []string{"known_key_unknown_val"}, mapLenNames, "map with known key and unknown value must have iac.length == 1 while unknown-key map stays undefined")

		// Real mutation-driven evaluation: feed ruletest.MutateAttributesToUnknown
		// directly into Inspector.Inspect and verify replacing the checked attribute
		// with an unknown produces zero false positives.
		positiveFixture := []byte(`
resource "aws_s3_bucket" "insecure" {
  bucket = "insecure-bucket"
  acl    = "public-read"
}
`)
		mutRule := model.QueryMetadata{
			Query:       "s3_acl_v2",
			Platform:    "terraform",
			Aggregation: 1,
			Metadata:    map[string]any{"id": "s3-acl-v2-mut", "queryName": "S3 ACL v2", "severity": model.SeverityMedium, "platform": "Terraform"},
			Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some b in input.resources.aws_s3_bucket
	iac.not_equals(b, ["acl"], "private")
	result := dd_output.format(b, {"path": ["acl"]})
}`,
		}
		runFixture := func(src []byte) []model.Vulnerability {
			mfs := vfs.NewMemFS(map[string][]byte{"/repo/main.tf": src})
			minsp, mErr := NewInspector(ctx, &mockQueriesSource{queries: []model.QueryMetadata{mutRule}}, DefaultVulnerabilityBuilder, &tracker.CITracker{},
				&source.QueryInspectorParameters{}, nil, "/repo", false, true, 1, nil, mfs, false)
			require.NoError(t, mErr)
			mv, mErr := minsp.Inspect(ctx, "scan-mut", model.FileMetadatas{
				{ID: "f-m", FilePath: "/repo/main.tf", Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(src)},
			}, []string{"terraform"})
			require.NoError(t, mErr)
			return mv
		}
		require.Len(t, runFixture(positiveFixture), 1, "baseline fixture must fire")
		mutations, err := ruletest.MutateAttributesToUnknown("main.tf", positiveFixture)
		require.NoError(t, err)
		require.NotEmpty(t, mutations)
		var testedACL bool
		for _, mut := range mutations {
			if mut.Attribute == "acl" {
				testedACL = true
				require.Empty(t, runFixture(mut.Source), "mutating checked attribute acl to unknown must suppress the finding")
			}
		}
		require.True(t, testedACL, "ruletest.MutateAttributesToUnknown must generate an acl mutation")
	})
	t.Run("closed_object_keys_include_unknown_and_null_children", func(t *testing.T) {
		libs, err := contractlibs.Modules()
		require.NoError(t, err)

		prepare := func(query string) rego.PreparedEvalQuery {
			opts := []func(*rego.Rego){rego.Query(query)}
			for _, module := range libs {
				opts = append(opts, rego.ParsedModule(module))
			}
			prepared, prepErr := rego.New(opts...).PrepareForEval(ctx)
			require.NoError(t, prepErr)
			return prepared
		}
		keysQuery := prepare(`keys := data.datadog.iac.object_keys(input.resource, input.path)
expected := {key | some key in input.expected}
keys == expected`)
		nestedKeysQuery := prepare(`view := data.datadog.iac.blocks(input.resource, "spec")[0]
keys := data.datadog.iac.object_keys(view, ["tags"])
expected := {key | some key in input.expected}
keys == expected`)
		jsonFallbackQuery := prepare(`doc := data.datadog.iac.json_doc(input.resource, ["policy"])
data.datadog.iac.get(doc, ["_dd_root"]) == "literal-root"
"_dd_root" in data.datadog.iac.object_keys(doc, [])
data.datadog.iac.get(doc, ["marker", "$unknown"]) == true
"$unknown" in data.datadog.iac.object_keys(doc, ["marker"])
data.datadog.iac.is_null_value(doc, [""])
not data.datadog.iac.is_unknown(doc, [""])
not data.datadog.iac.is_known(doc, [""])
data.datadog.iac.get(doc, ["known"]) == "preserved"
true`)

		assertKeys := func(query rego.PreparedEvalQuery, name string, resource map[string]any, path []any, expected []string, available bool) {
			t.Helper()
			results, evalErr := query.Eval(ctx, rego.EvalInput(map[string]any{
				"resource": resource,
				"path":     path,
				"expected": expected,
			}))
			require.NoError(t, evalErr, name)
			if !available {
				require.Empty(t, results, "%s must leave object_keys undefined", name)
				return
			}
			require.Len(t, results, 1, "%s must return exactly the expected key set", name)
		}

		fallbackResults, evalErr := jsonFallbackQuery.Eval(ctx, rego.EvalInput(map[string]any{
			"resource": map[string]any{
				"attributes": map[string]any{
					"policy": `{"":null,"_dd_root":"literal-root","_dd_prefix":"literal-prefix","_dd_parent_state":"literal-state","known":"preserved","marker":{"$unknown":true}}`,
				},
				"state": map[string]any{},
			},
		}))
		require.NoError(t, evalErr)
		require.Len(t, fallbackResults, 1,
			"json_doc fallback without derived JSON must preserve source keys, known marker-shaped objects, and explicit null state")

		assertKeys(keysQuery, "unknown and null values keep their known keys", map[string]any{
			"attributes": map[string]any{"tags": map[string]any{
				"Team": map[string]any{"$unknown": true},
				"Env":  "prod",
			}},
			"state": map[string]any{
				"unknown": map[string]any{"tags.Team": true},
				"null":    map[string]any{"tags.Owner": true},
			},
		}, []any{"tags"}, []string{"Team", "Env", "Owner"}, true)

		assertKeys(keysQuery, "escaped, numeric, and empty keys decode", map[string]any{
			"attributes": map[string]any{"labels": map[string]any{}},
			"state": map[string]any{
				"unknown": map[string]any{
					`labels.foo\.bar`:    true,
					`labels.back\\slash`: true,
					`labels.\7`:          true,
					"labels.":            true,
				},
				"null": map[string]any{"labels.null_only": true},
			},
		}, []any{"labels"}, []string{"foo.bar", `back\slash`, "7", "", "null_only"}, true)

		assertKeys(keysQuery, "root empty path uses unprefixed child flags", map[string]any{
			"attributes": map[string]any{"Team": "core"},
			"state":      map[string]any{"unknown": map[string]any{"Region": true}},
		}, []any{}, []string{"Team", "Region"}, true)

		assertKeys(nestedKeysQuery, "nested block views retain prefixed child flags", map[string]any{
			"attributes": map[string]any{"spec": []any{map[string]any{
				"tags": map[string]any{"Team": "core"},
			}}},
			"state": map[string]any{
				"unknown": map[string]any{"spec.0.tags.Region": true},
				"null":    map[string]any{"spec.0.tags.Owner": true},
			},
		}, nil, []string{"Team", "Region", "Owner"}, true)

		assertKeys(keysQuery, "empty-string path segment keeps its child prefix", map[string]any{
			"attributes": map[string]any{"": map[string]any{}},
			"state":      map[string]any{"unknown": map[string]any{".child": true}},
		}, []any{""}, []string{"child"}, true)

		assertKeys(keysQuery, "empty closed object returns an empty key set", map[string]any{
			"attributes": map[string]any{"tags": map[string]any{}},
			"state":      map[string]any{},
		}, []any{"tags"}, []string{}, true)

		assertKeys(keysQuery, "open key set is undefined", map[string]any{
			"attributes": map[string]any{"tags": map[string]any{}},
			"state":      map[string]any{"incomplete_collections": map[string]any{"tags": true}},
		}, []any{"tags"}, nil, false)

		assertKeys(keysQuery, "unknown whole map is undefined", map[string]any{
			"attributes": map[string]any{"tags": map[string]any{}},
			"state":      map[string]any{"unknown": map[string]any{"tags": true}},
		}, []any{"tags"}, nil, false)

		assertKeys(keysQuery, "unknown whole resource is undefined at root", map[string]any{
			"attributes": map[string]any{"Team": "core"},
			"state":      map[string]any{"unknown": map[string]any{"": true}},
		}, []any{}, nil, false)

		assertKeys(keysQuery, "non-object value is undefined", map[string]any{
			"attributes": map[string]any{"tags": []any{"Team"}},
			"state":      map[string]any{},
		}, []any{"tags"}, nil, false)
	})

	t.Run("is_empty_counts_preserved_null_object_keys", func(t *testing.T) {
		libs, err := contractlibs.Modules()
		require.NoError(t, err)
		opts := []func(*rego.Rego){rego.Query(`data.datadog.iac.is_empty(input.resource, ["tags"])`)}
		for _, module := range libs {
			opts = append(opts, rego.ParsedModule(module))
		}
		prepared, err := rego.New(opts...).PrepareForEval(ctx)
		require.NoError(t, err)

		for _, tc := range []struct {
			name     string
			resource map[string]any
			want     bool
		}{
			{
				name: "empty object",
				resource: map[string]any{
					"attributes": map[string]any{"tags": map[string]any{}},
					"state":      map[string]any{},
				},
				want: true,
			},
			{
				name: "null-valued child is still a key",
				resource: map[string]any{
					"attributes": map[string]any{"tags": map[string]any{}},
					"state":      map[string]any{"null": map[string]any{"tags.Owner": true}},
				},
				want: false,
			},
			{
				name: "absent attribute keeps empty semantics",
				resource: map[string]any{
					"attributes": map[string]any{},
					"state":      map[string]any{},
				},
				want: true,
			},
			{
				name: "explicitly null attribute keeps empty semantics",
				resource: map[string]any{
					"attributes": map[string]any{},
					"state":      map[string]any{"null": map[string]any{"tags": true}},
				},
				want: true,
			},
			{
				name: "unknown child remains incomplete",
				resource: map[string]any{
					"attributes": map[string]any{"tags": map[string]any{}},
					"state":      map[string]any{"unknown": map[string]any{"tags.Owner": true}},
				},
				want: false,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				results, evalErr := prepared.Eval(ctx, rego.EvalInput(map[string]any{"resource": tc.resource}))
				require.NoError(t, evalErr)
				if tc.want {
					require.Len(t, results, 1)
				} else {
					require.Empty(t, results)
				}
			})
		}
	})

	t.Run("compound_value_completeness", func(t *testing.T) {
		libs, err := contractlibs.Modules()
		require.NoError(t, err)
		opts := []func(*rego.Rego){rego.Query("data.datadog.iac.is_complete(input.resource, input.path)")}
		for _, module := range libs {
			opts = append(opts, rego.ParsedModule(module))
		}
		prepared, err := rego.New(opts...).PrepareForEval(ctx)
		require.NoError(t, err)
		for _, tc := range []struct {
			name     string
			path     []any
			state    map[string]any
			complete bool
		}{
			{"known absence", []any{"missing"}, nil, true},
			{"explicit null", []any{"null"}, map[string]any{"null": map[string]bool{"null": true}}, true},
			{"unknown child", []any{"rules"}, map[string]any{"unknown": map[string]bool{"rules.0.enabled": true}}, false},
			{"whole resource", []any{}, map[string]any{"unknown": map[string]bool{"tags.Env": true}}, false},
			{"nested open collection", []any{"rules"}, map[string]any{"incomplete_collections": map[string]bool{"rules.0.nested": true}}, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				state := tc.state
				if state == nil {
					state = map[string]any{}
				}
				results, err := prepared.Eval(ctx, rego.EvalInput(map[string]any{"resource": map[string]any{"attributes": map[string]any{}, "state": state}, "path": tc.path}))
				require.NoError(t, err)
				require.Equal(t, tc.complete, len(results) > 0)
			})
		}
	})

	t.Run("empty_block_view_has_no_metadata_attributes", func(t *testing.T) {
		libs, err := contractlibs.Modules()
		require.NoError(t, err)
		opts := []func(*rego.Rego){rego.Query(`r := {"attributes": {"probe": [{}]}, "state": {}}; v := data.datadog.iac.blocks(r, "probe")[0]; data.datadog.iac.length(v, []) == 0; data.datadog.iac.equals(v, [], {})`)}
		for _, module := range libs {
			opts = append(opts, rego.ParsedModule(module))
		}
		results, err := rego.New(opts...).Eval(ctx)
		require.NoError(t, err)
		require.Len(t, results, 1)
	})

	t.Run("configured_and_computed_value_views_preserve_state", func(t *testing.T) {
		libs, err := contractlibs.Modules()
		require.NoError(t, err)
		query := `r := {
   "attributes":{"spec":[{"configured":false}]},
   "state":{"unknown":{"spec.0.pending":true}},
   "platform":{"terraform":{"source_kind":"plan","computed":{"spec":[{"runtime":[{"enabled":true}]}]},"computed_state":{"unknown":{"spec.0.open":true}}}}
  };
  spec := data.datadog.iac.blocks(r,"spec")[0];
  actual := data.datadog.terraform.value_view(spec,["runtime"]);
  child := data.datadog.iac.blocks(actual,"runtime")[0];
  data.datadog.iac.is_true(child,["enabled"]);
  data.datadog.iac.path_of(child,["enabled"]) == ["spec",0,"runtime",0,"enabled"];
  data.datadog.iac.is_unknown(data.datadog.terraform.value_view(spec,["open"]),["open"]);
  not data.datadog.iac.is_empty(data.datadog.terraform.value_view(spec,["open"]),["open"]);
  data.datadog.iac.is_unknown(data.datadog.terraform.value_view(spec,["pending"]),["pending"]);
  data.datadog.iac.is_false(data.datadog.terraform.value_view(spec,["configured"]),["configured"])`
		opts := []func(*rego.Rego){rego.Query(query)}
		for _, module := range libs {
			opts = append(opts, rego.ParsedModule(module))
		}
		got, err := rego.New(opts...).Eval(ctx)
		require.NoError(t, err)
		require.Len(t, got, 1)
	})

	t.Run("source_null_preserves_runtime_values_and_nested_paths", func(t *testing.T) {
		libs, err := contractlibs.Modules()
		require.NoError(t, err)
		eval := func(query string) {
			opts := []func(*rego.Rego){rego.Query(query)}
			for _, module := range libs {
				opts = append(opts, rego.ParsedModule(module))
			}
			got, err := rego.New(opts...).Eval(ctx)
			require.NoError(t, err)
			require.Len(t, got, 1)
		}
		t.Run("plan source null does not replace runtime state", func(t *testing.T) {
			eval(`root := {
  "attributes":{"management":"provider-default","explicit":"provider-normalized"},
  "state":{"unknown":{"pending":true}},
  "platform":{"terraform":{"source_kind":"plan","source_null":{"management":true}}}
 };
 data.datadog.terraform.source_is_null(root,["management"]);
 data.datadog.iac.is_known(root,["management"]);
 not data.datadog.iac.is_null_value(root,["management"]);
 not data.datadog.terraform.source_is_null(root,["explicit"]);
 data.datadog.iac.is_unknown(root,["pending"]);
 not data.datadog.terraform.source_is_null(root,["pending"])`)
		})
		t.Run("nested block view keeps source path", func(t *testing.T) {
			eval(`root := {
  "attributes":{"spec":[{"container":[{"description":"provider description"}]}]},
  "state":{},
  "platform":{"terraform":{"source_kind":"plan","source_null":{"spec.0.container.0.description":true}}}
 };
 spec := data.datadog.iac.blocks(root,"spec")[0];
 container := data.datadog.iac.blocks(spec,"container")[0];
 data.datadog.terraform.source_is_null(container,["description"]);
 data.datadog.iac.path_of(container,["description"]) == ["spec",0,"container",0,"description"]`)
		})
		t.Run("HCL falls back to runtime null provenance", func(t *testing.T) {
			eval(`hcl := {"attributes":{},"state":{"null":{"field":true}},"platform":{"terraform":{"source_kind":"hcl"}}};
 data.datadog.terraform.source_is_null(hcl,["field"])`)
		})
	})

	t.Run("partial_template_through_library", func(t *testing.T) {
		raw := `variable "unknown" {}
resource "example_endpoint" "partial" {
 name = "prefix-${var.unknown}.service"
}
resource "example_endpoint" "known" {
 name = "known.service"
}
resource "example_endpoint" "unknown_suffix" {
 name = "prefix.${var.unknown}"
}
resource "example_endpoint" "unknown_whole" {
 name = var.unknown
}
`
		fs := vfs.NewMemFS(map[string][]byte{"/repo/main.tf": []byte(raw)})
		query := model.QueryMetadata{
			Query: "template-parts", Platform: "terraform", Aggregation: 1,
			Metadata: map[string]any{"id": "template-parts", "queryName": "Template parts", "severity": model.SeverityLow, "platform": "Terraform"},
			Content: `package datadog
import rego.v1
import data.generic.terraform as tf
import data.datadog.output as dd_output
results contains result if {
 some endpoint in input.resources.example_endpoint
 tf.matches_suffix(endpoint)
 result := dd_output.format(endpoint, {"path":["name"]})
}`,
		}
		library := `package generic.terraform
import rego.v1
import data.datadog.iac
matches_suffix(endpoint) if {
 parts := iac.template_parts(endpoint, ["name"])
 last := parts[count(parts)-1]
 last.known == true
 endswith(last.value, ".service")
}`
		inspector, err := NewInspector(ctx, &mockQueriesSource{queries: []model.QueryMetadata{query}, terraform: library},
			DefaultVulnerabilityBuilder, &tracker.CITracker{}, &source.QueryInspectorParameters{}, nil, "/repo", false, true, 2, nil, fs, false)
		require.NoError(t, err)
		files := model.FileMetadatas{{ID: "template", FilePath: "/repo/main.tf", Kind: model.KindTerraform, Platform: "terraform", OriginalData: raw}}
		got, err := inspector.Inspect(ctx, "template", files, []string{"terraform"})
		require.NoError(t, err)
		require.Empty(t, inspector.GetFailedQueries())
		var names []string
		for _, finding := range got {
			names = append(names, finding.ResourceName)
		}
		require.ElementsMatch(t, []string{"known", "partial"}, names)
	})

	t.Run("reachable_library_dependencies", func(t *testing.T) {
		common := `package generic.common
import rego.v1
import data.datadog.iac
policy(r) := iac.json_doc(r, ["policy"])
`
		library := `package generic.terraform
import rego.v1
import data.generic.common
import data.datadog.iac
missing(b) if { iac.no_related(b, "aws_s3_bucket_versioning", "bucket") }
allows(b) if {
    some statement in iac.blocks(common.policy(b), "Statement")
    iac.equals(statement, ["Effect"], "Allow")
}
unused if { iac.no_resources("aws_kms_key") }
`
		query := model.QueryMetadata{
			Query: "library-demands", Platform: "terraform", Aggregation: 1,
			Metadata: map[string]any{"id": "library-demands", "queryName": "Library demands", "severity": model.SeverityLow, "platform": "Terraform"},
			Content: `package datadog
import rego.v1
import data.generic.terraform as tf
import data.datadog.output as dd_output
results contains result if {
    some b in input.resources.aws_s3_bucket
    tf.missing(b)
    tf.allows(b)
    result := dd_output.format(b, {})
}`,
		}
		spec, ok := analyzeContractV2Rule(&query)
		require.True(t, ok)
		inspectContractV2Libraries(spec, ast.MustParseModule(common), ast.MustParseModule(library))
		require.True(t, spec.needsRelations)
		require.True(t, spec.needsJSON)
		require.True(t, spec.scopeRoot)
		require.False(t, spec.hasNoResources, "an unused helper must not affect dispatch")
		require.False(t, spec.wildcard)

		base := `variable "unknown" {}
resource "aws_s3_bucket" "b" {
    policy = jsonencode({ Statement = [{ Effect = "Allow", Resource = var.unknown }] })
}
`
		fs := vfs.NewMemFS(map[string][]byte{
			"/repo/missing/main.tf": []byte(base),
			"/repo/covered/main.tf": []byte(base + `resource "aws_s3_bucket_versioning" "v" { bucket = aws_s3_bucket.b.id }`),
		})
		var files model.FileMetadatas
		for _, dir := range []string{"missing", "covered"} {
			path := "/repo/" + dir + "/main.tf"
			raw, err := fs.ReadFile(path)
			require.NoError(t, err)
			files = append(files, &model.FileMetadata{ID: dir, FilePath: path, Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(raw)})
		}
		inspector, err := NewInspector(ctx, &mockQueriesSource{queries: []model.QueryMetadata{query}, common: common, terraform: library},
			DefaultVulnerabilityBuilder, &tracker.CITracker{}, &source.QueryInspectorParameters{}, nil, "/repo", false, true, 2, nil, fs, false)
		require.NoError(t, err)
		inspector.EnableCoverageReport()
		got, err := inspector.Inspect(ctx, "library-demands", files, []string{"terraform"})
		require.NoError(t, err)
		require.Empty(t, inspector.GetFailedQueries())
		require.Len(t, got, 1)
		require.Contains(t, got[0].FileName, "missing")
		require.NotEmpty(t, inspector.GetCoverageReport().Files[query.Query].Covered, "v2 coverage must include the rule across root evaluations")
	})

	t.Run("library_inventory_nested_input_calls", func(t *testing.T) {
		library := `package generic.terraform
import rego.v1
inventory contains resource if {
    some _, resources in object.get(input, "resources", {})
    some resource in resources
    resource.kind == "resource"
}
`
		query := model.QueryMetadata{
			Query: "library-inventory", Platform: "terraform", Aggregation: 1,
			Metadata: map[string]any{"id": "library-inventory", "queryName": "Library inventory", "severity": model.SeverityLow, "platform": "Terraform"},
			Content: `package datadog
import rego.v1
import data.generic.terraform as tf
import data.datadog.output as dd_output
has_provider if { some _ in input.resources["provider.example"] }
results contains result if {
    not has_provider
    some resource in tf.inventory
    result := dd_output.format(resource, {})
}`,
		}
		spec, ok := analyzeContractV2Rule(&query)
		require.True(t, ok)
		require.False(t, spec.wildcard)
		inspectContractV2Libraries(spec, ast.MustParseModule(library))
		require.True(t, spec.wildcard)
		require.True(t, spec.scopeRoot)
		require.True(t, spec.needsProviders)
		raw := `resource "example_resource" "unfiltered" { name = "test" }`
		fs := vfs.NewMemFS(map[string][]byte{"/repo/main.tf": []byte(raw)})
		inspector, err := NewInspector(ctx, &mockQueriesSource{queries: []model.QueryMetadata{query}, terraform: library},
			DefaultVulnerabilityBuilder, &tracker.CITracker{}, &source.QueryInspectorParameters{}, nil, "/repo", false, true, 2, nil, fs, false)
		require.NoError(t, err)
		files := model.FileMetadatas{{ID: "inventory", FilePath: "/repo/main.tf", Kind: model.KindTerraform, Platform: "terraform", OriginalData: raw}}
		got, err := inspector.Inspect(ctx, "library-inventory", files, []string{"terraform"})
		require.NoError(t, err)
		require.Empty(t, inspector.GetFailedQueries())
		require.Len(t, got, 1)
		require.Equal(t, "unfiltered", got[0].ResourceName)
	})

	t.Run("json_leaf_template_reference_proofs", func(t *testing.T) {
		query := model.QueryMetadata{
			Query: "json-leaf-chunks", Platform: "terraform", Aggregation: 1,
			Metadata: map[string]any{"id": "json-leaf-chunks", "queryName": "JSON leaf chunks", "severity": model.SeverityLow, "platform": "Terraform"},
			Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
    some resource in input.resources.example_payload
    parts := iac.template_parts(resource, ["payload", "items", 0, "value"])
    count(parts) == 3
    parts[0].known == true
    parts[0].value == "prefix:"
    parts[1].known == false
    parts[1].ref == {"kind":"data", "type":"example_identity", "name":"current", "attr":"id"}
    parts[2].value == ":suffix"
    opaque := iac.template_parts(resource, ["payload", "items", 1, "value"])
    count(opaque) == 1
    opaque[0].known == false
    object.get(opaque[0], "ref", null) == null
    iac.template_parts(resource, ["payload", "items", 2, "value"])[0].value == "literal"
    dot_key := iac.template_parts(resource, ["payload", "dot.key"])
    dot_nested := iac.template_parts(resource, ["payload", "dot", "key"])
    count(dot_key) == 3
    dot_key[1].ref.attr == "id"
    count(dot_nested) == 3
    dot_nested[1].ref.attr == "arn"
    slash_key := iac.template_parts(resource, ["payload", "slash\\.key"])
    slash_nested := iac.template_parts(resource, ["payload", "slash\\", "key"])
    count(slash_key) == 3
    slash_key[1].ref.attr == "name"
    count(slash_nested) == 3
    slash_nested[1].ref.attr == "region"
    numeric_key := iac.template_parts(resource, ["payload", "0"])
    array_index := iac.template_parts(resource, ["payload", "values", 0])
    count(numeric_key) == 3
    numeric_key[1].ref.attr == "name"
    count(array_index) == 3
    array_index[1].ref.attr == "arn"
    old_sentinel := iac.template_parts(resource, ["payload", "old_sentinel"])
    count(old_sentinel) == 1
    old_sentinel[0].known == true
    old_sentinel[0].value == "\u0000__dd_tpl_idx_0__\u0000"
    object.get(old_sentinel[0], "ref", null) == null
    result := dd_output.format(resource, {"path":["payload"]})
}`,
		}
		prefix := `data "example_identity" "current" {}
locals { identity = data.example_identity.current.id }
resource "example_payload" "test" {
`
		expressions := map[string]string{
			"encoded": `payload = jsonencode({ items = [
 { value = "prefix:${local.identity}:suffix" },
 { value = upper(data.example_identity.current.id) },
 { value = "literal" }
],
 "dot.key" = "dot:${data.example_identity.current.id}:tail",
 dot = { key = "nested:${data.example_identity.current.arn}:tail" },
 "slash\\.key" = "slash:${data.example_identity.current.name}:tail",
 "slash\\" = { key = "nested-slash:${data.example_identity.current.region}:tail" },
 "0" = "numeric:${data.example_identity.current.name}:tail",
 values = ["indexed:${data.example_identity.current.arn}:tail"],
 old_sentinel = "\u0000__dd_tpl_idx_0__\u0000"
})`,
			"heredoc": `payload = <<JSON
{"items":[
 {"value":"prefix:${local.identity}:suffix"},
 {"value":"${upper(data.example_identity.current.id)}"},
 {"value":"literal"}
],
 "dot.key":"dot:${data.example_identity.current.id}:tail",
 "dot":{"key":"nested:${data.example_identity.current.arn}:tail"},
 "slash\\.key":"slash:${data.example_identity.current.name}:tail",
 "slash\\":{"key":"nested-slash:${data.example_identity.current.region}:tail"},
 "0":"numeric:${data.example_identity.current.name}:tail",
 "values":["indexed:${data.example_identity.current.arn}:tail"],
 "old_sentinel":"\u0000__dd_tpl_idx_0__\u0000"
}
JSON`,
		}

		contents := map[string][]byte{}
		var files model.FileMetadatas
		for name, expression := range expressions {
			path := "/repo/" + name + "/main.tf"
			raw := prefix + expression + "\n}\n"
			contents[path] = []byte(raw)
			files = append(files, &model.FileMetadata{ID: name, FilePath: path, Kind: model.KindTerraform, Platform: "terraform", OriginalData: raw})
		}
		fs := vfs.NewMemFS(contents)
		inspector, err := NewInspector(ctx, &mockQueriesSource{queries: []model.QueryMetadata{query}},
			DefaultVulnerabilityBuilder, &tracker.CITracker{}, &source.QueryInspectorParameters{}, nil, "/repo", false, true, 2, nil, fs, false)
		require.NoError(t, err)
		got, err := inspector.Inspect(ctx, "json-leaf-chunks", files, []string{"terraform"})
		require.NoError(t, err)
		require.Empty(t, inspector.GetFailedQueries())
		require.Len(t, got, 2, "both encodings retain exact reference chunks while opaque expressions stay unproven")
	})

}

type mockQueriesSource struct {
	queries   []model.QueryMetadata
	common    string
	terraform string
}

func (m *mockQueriesSource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return m.queries, nil
}

func (m *mockQueriesSource) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	if platform == "common" && m.common != "" {
		return source.RegoLibraries{LibraryCode: m.common, LibraryInputData: "{}"}, nil
	}
	if platform == "terraform" && m.terraform != "" {
		return source.RegoLibraries{LibraryCode: m.terraform, LibraryInputData: "{}"}, nil
	}
	pkg := "generic.common"
	if platform != "common" && platform != "" {
		pkg = "generic.terraform"
	}
	return source.RegoLibraries{
		LibraryCode:      "package " + pkg + "\nimport rego.v1\n",
		LibraryInputData: "{}",
	}, nil
}

func TestContractV2ResourceRelationReadsRemainResourceScoped(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		helper    string
		scopeRoot bool
	}{
		{
			name: "direct relation reference",
			body: `bucket.relations.referrers.bucket != {}`,
		},
		{
			name: "walk resource object",
			body: `walk(bucket, [path, value])`,
		},
		{
			name: "object keys of resource",
			body: `object.keys(bucket) != []`,
		},
		{
			name: "helper parameter relation reference",
			body: `has_relations(bucket)`,
			helper: `has_relations(resource) if {
    count(resource.relations.referrers.bucket) > 0
}`,
		},
		{
			name: "aliased relation reference",
			body: `alias := bucket
alias.relations.referrers.bucket != {}`,
		},
		{
			name: "object.get relation reference",
			body: `object.get(bucket, "relations", {}).referrers.bucket != {}`,
		},
		{
			name: "object.get relation path",
			body: `object.get(bucket, ["relations", "referrers"], {}) != {}`,
		},
		{
			name: "negated object.get relation path",
			body: `not object.get(bucket, ["relations", "related", "aws_s3_bucket_acl"], false)`,
		},
		{
			name: "negated object.get relation ref",
			body: `not object.get(bucket, "relations", {}).related.aws_s3_bucket_acl`,
		},
		{
			name: "input resources relation reference",
			body: `some i
not input.resources.aws_s3_bucket[i].relations.related.aws_s3_bucket_acl`,
			scopeRoot: true,
		},
		{
			name:      "input resources relation count",
			body:      `count(input.resources.aws_s3_bucket[_].relations.referrers) > 0`,
			scopeRoot: true,
		},
		{
			name:      "input resources relation comprehension",
			body:      `[relation | relation := input.resources.aws_s3_bucket[_].relations] != []`,
			scopeRoot: true,
		},
		{
			name: "object.get dynamic key helper",
			body: `not has_relation(bucket, "relations")`,
			helper: `has_relation(resource, field) if {
    object.get(resource, field, {}).related.aws_s3_bucket_acl
}`,
		},
		{
			name: "dynamic object.get helper key without a literal field",
			body: `some field in input.dynamic_fields
not has_relation(bucket, field)`,
			helper: `has_relation(resource, field) if object.get(resource, field, {}) != {}`,
		},
		{
			name:      "by_id lookup",
			body:      `input.by_id[bucket.id] != null`,
			scopeRoot: true,
		},
		{
			name:      "scope completeness lookup",
			body:      `input.scope_complete == true`,
			scopeRoot: true,
		},
		{
			name: "multi-resource join",
			body: `some acl in input.resources.aws_s3_bucket_acl
acl.attributes.bucket == bucket.attributes.bucket`,
			scopeRoot: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := model.QueryMetadata{
				Query: "resource-relation-read",
				Content: `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    ` + tc.body + `
    result := dd_output.format(bucket, {})
}
` + tc.helper,
			}
			spec, ok := analyzeContractV2Rule(&query)
			require.True(t, ok)
			require.Equal(t, tc.scopeRoot, spec.scopeRoot, "root scope is reserved for root-level data and multi-resource joins")
			if tc.name == "by_id lookup" {
				require.True(t, spec.needsRelations, "by_id reads retain the demand that includes the root index")
			}
		})
	}
}

func TestContractV2ReachableLibraryRelationReadDoesNotRequireRootScope(t *testing.T) {
	query := model.QueryMetadata{
		Query: "library-relation-read",
		Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    iac.has_relations(bucket)
    result := dd_output.format(bucket, {})
}`,
	}
	spec, ok := analyzeContractV2Rule(&query)
	require.True(t, ok)
	library, err := ast.ParseModuleWithOpts("terraform", `package datadog.iac
import rego.v1
has_relations(resource) if {
    count(resource.relations.referrers.bucket) > 0
}`, ast.ParserOptions{RegoVersion: ast.RegoV1})
	require.NoError(t, err)

	inspectContractV2Libraries(spec, library)
	require.True(t, spec.needsRelations)
	require.False(t, spec.scopeRoot, "a helper reading one resource's relations does not require root scope")
}

// TestContractV2HelperRelationReadMatchesDirectRead checks that a relation
// read through a helper parameter, an alias or object.get sees the same
// relations as the direct `bucket.relations` read. `related` is keyed by
// referrer type, then attribute; `referrers` is keyed by attribute only. Each
// body keeps the relation ref directly under `not` (or behind a defined
// default), because OPA hoists a ref used as a call argument out of a negated
// expression, so `not count(<undefined ref>) > 0` fails the whole body.
func TestContractV2HelperRelationReadMatchesDirectRead(t *testing.T) {
	ctx := context.Background()
	bucketOnly := `resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
`
	withACL := bucketOnly + `resource "aws_s3_bucket_acl" "logs" {
  bucket = aws_s3_bucket.logs.id
  acl    = "private"
}
`
	reads := []struct {
		name   string
		body   string
		helper string
	}{
		{name: "direct", body: `not bucket.relations.related.aws_s3_bucket_acl`},
		{
			name:   "helper parameter",
			body:   `not has_acl(bucket)`,
			helper: "has_acl(resource) if resource.relations.related.aws_s3_bucket_acl",
		},
		{
			name:   "helper value",
			body:   `not has_acl(bucket)`,
			helper: "has_acl(resource) := count(resource.relations.related.aws_s3_bucket_acl.bucket.ids) > 0",
		},
		{
			name: "alias",
			body: `alias := bucket
    not alias.relations.related.aws_s3_bucket_acl`,
		},
		{name: "object.get field", body: `not object.get(bucket, "relations", {}).related.aws_s3_bucket_acl`},
		{name: "object.get path", body: `not object.get(bucket, ["relations", "related", "aws_s3_bucket_acl"], false)`},
		{
			name:   "dynamic object.get helper key",
			body:   `not has_acl(bucket, "relations")`,
			helper: `has_acl(resource, field) if object.get(resource, field, {}).related.aws_s3_bucket_acl`,
		},
		{
			name: "walk helper",
			body: `not refd(bucket)`,
			helper: `refd(resource) if {
    walk(resource, [path, _])
    path[count(path) - 1] == "aws_s3_bucket_acl"
}`,
		},
		{
			name: "object.keys helper",
			body: `not has_acl(bucket)`,
			helper: `has_acl(resource) if {
    "relations" in object.keys(resource)
    resource.relations.related.aws_s3_bucket_acl
}`,
		},
		{
			name: "key/value iteration helper",
			body: `not has_acl_kv(bucket)`,
			helper: `has_acl_kv(resource) if {
    some key, value in resource
    endswith(key, "lations")
    value.related.aws_s3_bucket_acl
}`,
		},
		{name: "json.filter path", body: `count(object.get(json.filter(bucket, ["relations/related/aws_s3_bucket_acl"]), ["relations", "related", "aws_s3_bucket_acl", "bucket", "ids"], [])) == 0`},
		{
			name: "computed bracket key",
			body: `key := concat("", ["rel", "ations"])
    not bucket[key].related.aws_s3_bucket_acl`,
		},
	}
	unrelatedRelationRule := model.QueryMetadata{
		Query: "unrelated-relation-rule", Platform: "terraform", Aggregation: 1,
		Metadata: map[string]interface{}{"id": "unrelated-relation-rule", "queryName": "unrelated-relation-rule", "severity": model.SeverityHigh, "platform": "Terraform"},
		Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    iac.related(bucket, "aws_s3_bucket_acl", "bucket")
    result := dd_output.format(bucket, {})
}`,
	}
	for _, fixture := range []struct {
		name     string
		source   string
		findings int
	}{
		{name: "referenced by acl", source: withACL, findings: 0},
		{name: "no acl", source: bucketOnly, findings: 1},
	} {
		for _, read := range reads {
			t.Run(fixture.name+"/"+read.name, func(t *testing.T) {
				rule := model.QueryMetadata{
					Query: "relation-read", Platform: "terraform", Aggregation: 1,
					Metadata: map[string]interface{}{"id": "relation-read", "queryName": "relation-read", "severity": model.SeverityHigh, "platform": "Terraform"},
					Content: `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    ` + read.body + `
    result := dd_output.format(bucket, {})
}
` + read.helper,
				}
				spec, ok := analyzeContractV2Rule(&rule)
				require.True(t, ok)
				require.False(t, spec.scopeRoot, "resource relation reads are valid in resource chunks")
				fs := vfs.NewMemFS(map[string][]byte{"/repo/main.tf": []byte(fixture.source)})
				inspector, err := NewInspector(ctx, &mockQueriesSource{queries: []model.QueryMetadata{rule}},
					DefaultVulnerabilityBuilder, &tracker.CITracker{}, &source.QueryInspectorParameters{}, nil,
					"/repo", false, true, 1, nil, fs, false)
				require.NoError(t, err)
				files := model.FileMetadatas{{ID: "file-hcl", FilePath: "/repo/main.tf", Kind: model.KindTerraform, Platform: "terraform", OriginalData: fixture.source}}
				findings, err := inspector.Inspect(ctx, "relation-helper-parity", files, []string{"terraform"})
				require.NoError(t, err)
				require.Empty(t, inspector.GetFailedQueries())
				countRelationFindings := func(findings []model.Vulnerability) int {
					count := 0
					for _, finding := range findings {
						if finding.QueryID == rule.Query {
							count++
						}
					}
					return count
				}
				require.Equal(t, fixture.findings, countRelationFindings(findings), "relation read via %s must see the same relations as a direct read", read.name)

				inspectorWithUnrelatedRule, err := NewInspector(ctx, &mockQueriesSource{queries: []model.QueryMetadata{rule, unrelatedRelationRule}},
					DefaultVulnerabilityBuilder, &tracker.CITracker{}, &source.QueryInspectorParameters{}, nil,
					"/repo", false, true, 1, nil, fs, false)
				require.NoError(t, err)
				findingsWithUnrelatedRule, err := inspectorWithUnrelatedRule.Inspect(ctx, "relation-helper-parity-with-unrelated", files, []string{"terraform"})
				require.NoError(t, err)
				require.Empty(t, inspectorWithUnrelatedRule.GetFailedQueries())
				require.Equal(t, fixture.findings, countRelationFindings(findingsWithUnrelatedRule), "relation read via %s must be independent of unrelated relation rules", read.name)
			})
		}
	}
	t.Run("mixed output-only module", testContractV2MixedOutputOnlyModuleRelationRead)
}

func testContractV2MixedOutputOnlyModuleRelationRead(t *testing.T) {
	ctx := context.Background()
	moduleRoot := t.TempDir()
	mainSource := `resource "aws_s3_bucket" "logs" {
  bucket = "logs"
  acl    = "public-read"
}
module "ids" {
  source = "./ids"
  id     = aws_s3_bucket.logs.id
}
resource "aws_s3_bucket_acl" "logs" {
  bucket = module.ids.bucket_id
  acl    = "private"
}
`
	moduleSource := `variable "id" {}
output "bucket_id" {
  value = var.id
}
`
	moduleDir := filepath.Join(moduleRoot, "ids")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	mainPath := filepath.Join(moduleRoot, "main.tf")
	modulePath := filepath.Join(moduleDir, "main.tf")
	require.NoError(t, os.WriteFile(mainPath, []byte(mainSource), 0o600))
	require.NoError(t, os.WriteFile(modulePath, []byte(moduleSource), 0o600))
	moduleFiles := append(parseTerraform(t, mainPath), parseTerraform(t, modulePath)...)
	moduleFS := vfs.NewMemFS(map[string][]byte{
		mainPath: []byte(mainSource), modulePath: []byte(moduleSource),
	})
	makeRule := func(id, content string) model.QueryMetadata {
		return model.QueryMetadata{
			Query: id, Platform: "terraform", Aggregation: 1,
			Metadata: map[string]interface{}{"id": id, "queryName": id, "severity": model.SeverityHigh, "platform": "Terraform"},
			Content:  content,
		}
	}
	mixedRelationRule := makeRule("output-only-relation", `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    some key, value in bucket
    key == concat("", ["rel", "ations"])
    count(value.related.aws_s3_bucket_acl.bucket.ids) == 0
    result := dd_output.format(bucket, {})
}`)
	mixedRelationSpec, ok := analyzeContractV2Rule(&mixedRelationRule)
	require.True(t, ok)
	require.False(t, mixedRelationSpec.needsRelations, "the dynamic relation read is intentionally not detected by the analyzer")
	unrelatedRelationRule := makeRule("unrelated-relation-rule", `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    iac.related(bucket, "aws_s3_bucket_acl", "bucket")
    result := dd_output.format(bucket, {})
}`)
	unrelatedSpec, ok := analyzeContractV2Rule(&unrelatedRelationRule)
	require.True(t, ok)
	require.True(t, unrelatedSpec.needsRelations)
	legacyRule := model.QueryMetadata{
		Query: "legacy-acl", Platform: "terraform", InputData: "{}", Aggregation: 1,
		Metadata: map[string]interface{}{"id": "legacy-acl", "platform": "Terraform"},
		Content:  displayNameAclRule,
	}
	countFindings := func(queries ...model.QueryMetadata) int {
		inspector, err := NewInspector(ctx, &mockQueriesSource{queries: queries},
			DefaultVulnerabilityBuilder, &tracker.CITracker{}, &source.QueryInspectorParameters{}, nil,
			moduleRoot, false, true, 1, nil, moduleFS, false)
		require.NoError(t, err)
		findings, err := inspector.Inspect(ctx, "mixed-output-only-module", moduleFiles, []string{"terraform"})
		require.NoError(t, err)
		require.Empty(t, inspector.GetFailedQueries())
		count := 0
		for _, finding := range findings {
			if finding.QueryID == mixedRelationRule.Query {
				count++
			}
		}
		return count
	}
	withoutUnrelated := countFindings(mixedRelationRule, legacyRule)
	withUnrelated := countFindings(mixedRelationRule, legacyRule, unrelatedRelationRule)
	require.Zero(t, withoutUnrelated, "module output relations must be available in mixed scans without a relation-demanding rule")
	require.Equal(t, withoutUnrelated, withUnrelated, "module output relations must not depend on unrelated relation readers")
}

func TestContractV2RelationProjectionKeepsTraversedResources(t *testing.T) {
	ctx := context.Background()
	sourceText := `
module "unavailable" {
  source  = "example/remote/module"
  version = "1.0.0"
}

resource "example_trail" "audit" {
  bucket_id = example_bucket.logs.id
}

resource "example_trail" "module_ref" {
  bucket_id = module.unavailable.bucket_id
}

resource "example_bucket" "logs" {
  name = "audit-logs"
}

resource "example_bucket_acl" "public" {
  bucket = example_bucket.logs.id
  acl    = "public-read"
}
`
	fs := vfs.NewMemFS(map[string][]byte{"/repo/main.tf": []byte(sourceText)})
	rule := model.QueryMetadata{
		Query:    "example_acl_relation",
		Platform: "terraform",
		Metadata: map[string]interface{}{
			"id":        "terraform-example-acl-relation",
			"queryName": "Example ACL relation",
			"severity":  model.SeverityHigh,
			"platform":  "Terraform",
		},
		Content: `package datadog

import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output

results contains result if {
  some trail in input.resources.example_trail
  some bucket in iac.targets(trail, "bucket_id")
  some acl in iac.related(bucket, "example_bucket_acl", "bucket")
  iac.get(acl, ["acl"]) == "public-read"
  result := dd_output.format(acl, {"path": ["acl"]})
}
`,
		Aggregation: 1,
	}
	spec, ok := analyzeContractV2Rule(&rule)
	require.True(t, ok)
	require.True(t, spec.needsRelations)
	require.True(t, spec.scopeRoot)
	inspector, err := NewInspector(ctx, &mockQueriesSource{queries: []model.QueryMetadata{rule}},
		DefaultVulnerabilityBuilder, &tracker.CITracker{}, &source.QueryInspectorParameters{}, nil,
		"/repo", false, true, 1, nil, fs, false)
	require.NoError(t, err)

	files := model.FileMetadatas{{
		ID:           "file-hcl",
		FilePath:     "/repo/main.tf",
		Kind:         model.KindTerraform,
		Platform:     "terraform",
		OriginalData: sourceText,
	}}
	vulns, err := inspector.Inspect(ctx, "contract-v2-relation-projection", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, inspector.GetFailedQueries())
	require.Len(t, vulns, 1, "a definite cross-resource relation must remain traversable when an unrelated module call makes root scope incomplete")
	require.Equal(t, "terraform-example-acl-relation", vulns[0].QueryID)
	require.Equal(t, "example_bucket_acl", vulns[0].ResourceType)
	require.Equal(t, "public", vulns[0].ResourceName)
}

func TestContractV2MultiTypeChunkingAndModulePrefilter(t *testing.T) {
	// Independent multi-type rule (single input.resources ref per results body)
	// must be eligible for multi-root chunking (scopeRoot == false).
	independentMultiType := model.QueryMetadata{
		Query:       "independent-multi-type",
		Platform:    "terraform",
		Aggregation: 1,
		Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
types := {"aws_s3_bucket", "aws_s3_bucket_policy"}
results contains result if {
	some typ in types
	some r in input.resources[typ]
	iac.is_unset(r, ["tags"])
	result := dd_output.format(r, {"path": ["tags"]})
}`,
	}
	spec, ok := analyzeContractV2Rule(&independentMultiType)
	require.True(t, ok)
	require.False(t, spec.scopeRoot, "independent multi-type rule with one input.resources ref per body should chunk across roots")
	require.True(t, spec.types["aws_s3_bucket"] && spec.types["aws_s3_bucket_policy"])

	// Cross-resource join across two types MUST stay root-scoped (scopeRoot == true).
	crossJoin := model.QueryMetadata{
		Query:       "cross-join-multi-type",
		Platform:    "terraform",
		Aggregation: 1,
		Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
	some a in input.resources.aws_s3_bucket
	some b in input.resources.aws_s3_bucket_policy
	iac.get(a, ["bucket"]) == iac.get(b, ["bucket"])
	result := dd_output.format(a, {"path": ["bucket"]})
}`,
	}
	joinSpec, ok := analyzeContractV2Rule(&crossJoin)
	require.True(t, ok)
	require.True(t, joinSpec.scopeRoot, "cross-resource join must stay root-scoped")

	// HCL module declaration prefilter skips comments and identifiers without excluding valid declarations.
	require.True(t, mayDeclareModuleBlockString(`module "vpc" { source = "./modules/vpc" }`))
	require.True(t, mayDeclareModuleBlockString(`module"vpc" { source = "./modules/vpc" }`))
	require.True(t, mayDeclareModuleBlockString("  module\t\"vpc\" {\n  source = \"../shared\"\n}"))
	require.False(t, mayDeclareModuleBlockString("# module \"vpc\" { source = \"./vpc\" }\nresource \"aws_s3_bucket\" \"b\" {}"))
	require.False(t, mayDeclareModuleBlockString("variable \"module_name\" { default = \"./x\" }"))
	require.True(t, mayDeclareModuleBlockString(`module /* c */ "vpc" { source = "./vpc" }`))
	require.True(t, mayDeclareModuleBlockString(`module/* c */"vpc" { source = "./vpc" }`))
	require.True(t, mayDeclareModuleBlockString("module /* a */ /* multi\nline */ vpc { source = \"./vpc\" }"))
	require.True(t, mayDeclareModuleBlockString(`module /* unterminated "vpc" {`))
	require.False(t, mayDeclareModuleBlockString(`modules/* c */"vpc" { source = "./vpc" }`))
	require.False(t, mayDeclareModuleBlockString(`module /* c */ = "vpc"`))
}

func TestContractV2ReadUnderIncompleteCollectionIsUnknown(t *testing.T) {
	ctx := context.Background()
	libs, err := contractlibs.Modules()
	require.NoError(t, err)
	opts := []func(*rego.Rego){rego.Query(`data.datadog.iac.read(input.resource, input.path)`)}
	for _, module := range libs {
		opts = append(opts, rego.ParsedModule(module))
	}
	prepared, err := rego.New(opts...).PrepareForEval(ctx)
	require.NoError(t, err)

	for _, tc := range []struct {
		name     string
		resource map[string]any
		path     []any
		want     map[string]any
	}{
		{
			name: "unknown element beneath open collection",
			resource: map[string]any{
				"attributes": map[string]any{"ingress": []any{map[string]any{"from_port": 22}}},
				"state":      map[string]any{"incomplete_collections": map[string]any{"ingress": true}},
			},
			path: []any{"ingress", 1}, want: map[string]any{"state": "unknown"},
		},
		{
			name:     "provably absent from closed resource",
			resource: map[string]any{"attributes": map[string]any{}, "state": map[string]any{}},
			path:     []any{"ingress", 1}, want: map[string]any{"state": "absent"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results, evalErr := prepared.Eval(ctx, rego.EvalInput(map[string]any{"resource": tc.resource, "path": tc.path}))
			require.NoError(t, evalErr)
			require.Len(t, results, 1)
			require.Equal(t, tc.want, results[0].Expressions[0].Value)
		})
	}
}

func TestContractV2ComputedUsesPlanProvenance(t *testing.T) {
	ctx := context.Background()
	libs, err := contractlibs.Modules()
	require.NoError(t, err)
	query := `result := {
  "computed": count({true | _ := data.datadog.terraform.computed(input.resource, ["output"])}) > 0,
  "known": count({true | data.datadog.iac.is_known(data.datadog.terraform.computed_view(input.resource), ["output"])}) > 0,
  "unknown": count({true | data.datadog.iac.is_unknown(data.datadog.terraform.computed_view(input.resource), ["output"])}) > 0,
}
result`
	opts := []func(*rego.Rego){rego.Query(query)}
	for _, module := range libs {
		opts = append(opts, rego.ParsedModule(module))
	}
	prepared, err := rego.New(opts...).PrepareForEval(ctx)
	require.NoError(t, err)

	for _, tc := range []struct {
		name     string
		resource map[string]any
		want     map[string]any
	}{
		{
			name: "known value shaped like marker",
			resource: map[string]any{
				"platform": map[string]any{"terraform": map[string]any{
					"source_kind": "plan", "computed": map[string]any{"output": map[string]any{"$unknown": true}},
					"computed_state": map[string]any{},
				}},
			},
			want: map[string]any{"computed": true, "known": true, "unknown": false},
		},
		{
			name: "unknown computed value",
			resource: map[string]any{
				"platform": map[string]any{"terraform": map[string]any{
					"source_kind": "plan", "computed": map[string]any{"output": map[string]any{"x": true}},
					"computed_state": map[string]any{"unknown": map[string]any{"output": true}},
				}},
			},
			want: map[string]any{"computed": false, "known": false, "unknown": true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results, evalErr := prepared.Eval(ctx, rego.EvalInput(map[string]any{"resource": tc.resource}))
			require.NoError(t, evalErr)
			require.Len(t, results, 1)
			require.Equal(t, tc.want, results[0].Bindings["result"])
		})
	}
}

func TestContractV2RunStatsReportFailuresAndIncompleteScopes(t *testing.T) {
	repo := t.TempDir()
	brokenRoot := filepath.Join(repo, "broken", "main.tf")
	incompleteRoot := filepath.Join(repo, "incomplete", "main.tf")
	planPath := filepath.Join(repo, "tfplan.json")
	for _, path := range []string{brokenRoot, incompleteRoot, planPath} {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	}
	broken := []byte(`resource "aws_s3_bucket" "broken" {`)
	incomplete := []byte(`module "unknown" { source = var.module_source }`)
	badPlan := []byte(`{"format_version":`)
	require.NoError(t, os.WriteFile(brokenRoot, broken, 0o600))
	require.NoError(t, os.RemoveAll(filepath.Dir(brokenRoot)), "the scan still indexes the file metadata, but root evaluation cannot read the root directory")
	require.NoError(t, os.WriteFile(incompleteRoot, incomplete, 0o600))
	require.NoError(t, os.WriteFile(planPath, badPlan, 0o600))

	rule := model.QueryMetadata{
		Query: "contract-v2-stats", Platform: "terraform", Aggregation: 1,
		Metadata: map[string]interface{}{"id": "contract-v2-stats", "queryName": "Stats", "severity": "HIGH", "platform": "Terraform"},
		Content: `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    result := dd_output.format(bucket, {})
}`,
	}
	legacyRule := model.QueryMetadata{
		Query: "legacy-stats", Platform: "terraform", Aggregation: 1,
		Metadata: map[string]interface{}{"id": "legacy-stats", "queryName": "Legacy stats", "severity": "HIGH", "platform": "Terraform"},
		Content:  displayNameAclRule,
	}
	for _, mixed := range []bool{false, true} {
		name := "standalone-v2"
		queries := []model.QueryMetadata{rule}
		if mixed {
			name = "mixed-v2-and-legacy"
			queries = append(queries, legacyRule)
		}
		t.Run(name, func(t *testing.T) {
			files := model.FileMetadatas{
				&model.FileMetadata{ID: "broken", FilePath: brokenRoot, Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(broken)},
				&model.FileMetadata{ID: "incomplete", FilePath: incompleteRoot, Kind: model.KindTerraform, Platform: "terraform", OriginalData: string(incomplete)},
				&model.FileMetadata{ID: "plan", FilePath: planPath, Kind: model.KindTerraformPlan, Platform: "terraform", OriginalData: string(badPlan)},
			}
			ins := newTestInspector(t, inspectorOpts{queries: queries, repoPath: repo, vb: DefaultVulnerabilityBuilder})
			_, err := ins.Inspect(context.Background(), name, files, []string{"terraform"})
			require.NoError(t, err)
			require.Equal(t, ContractV2RunStats{RootsFailed: 1, PlansFailed: 1, RootsScopeIncomplete: 1}, ins.ContractV2RunStats())
			_, err = ins.Inspect(context.Background(), name+"-non-terraform", nil, []string{"kubernetes"})
			require.NoError(t, err)
			require.Equal(t, ContractV2RunStats{RootsFailed: 1, PlansFailed: 1, RootsScopeIncomplete: 1}, ins.ContractV2RunStats(), "a later platform service must not reset scan-wide counters")
		})
	}
}

// relationBuildCancelCtx is canceled by the cancelAt-th Err() call made from
// inside the Contract v2 relation builder, so the scan stops while that
// builder is running, whatever goroutine or worker it runs on.
type relationBuildCancelCtx struct {
	context.Context
	cancel   context.CancelFunc
	cancelAt int32
	calls    atomic.Int32 // Err() calls from the relation builder
	after    atomic.Int32 // ... of which after the cancellation
}

func newRelationBuildCancelCtx(cancelAt int32) *relationBuildCancelCtx {
	ctx, cancel := context.WithCancel(context.Background())
	return &relationBuildCancelCtx{Context: ctx, cancel: cancel, cancelAt: cancelAt}
}

func (c *relationBuildCancelCtx) Err() error {
	if calledFromRelationBuilder() {
		if c.Context.Err() != nil {
			c.after.Add(1)
		} else if c.calls.Add(1) >= c.cancelAt {
			c.cancel()
		}
	}
	return c.Context.Err()
}

func calledFromRelationBuilder() bool {
	pcs := make([]uintptr, 32)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(3, pcs)])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, "terraform/contract.buildIntraRootRelations") {
			return true
		}
		if !more {
			return false
		}
	}
}

// A scan canceled while Contract v2 builds a root's relations must stop that
// build and fail with the cancellation, never evaluate the half-built unit,
// and not count the root as failed. Covers the serial and worker-pool roots of
// a Contract v2-only scan and the coexistence path of a mixed scan.
func TestContractV2CancelDuringRelationBuildStopsScan(t *testing.T) {
	repo := t.TempDir()
	var big strings.Builder
	for i := range 200 {
		fmt.Fprintf(&big, "resource \"aws_s3_bucket\" \"b%d\" { bucket = \"bucket-%d\" }\n", i, i)
	}
	contents := map[string]string{
		"a-big/main.tf": big.String(),
		// Roots without resources never reach the relation builder, so only
		// the big root can trigger the cancellation.
		"b-empty/main.tf": `locals { a = 1 }`,
		"c-empty/main.tf": `locals { b = 2 }`,
	}
	files := make(model.FileMetadatas, 0, len(contents))
	for rel, content := range contents {
		path := filepath.Join(repo, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		files = append(files, &model.FileMetadata{
			ID: rel, FilePath: path, Kind: model.KindTerraform, Platform: "terraform", OriginalData: content,
		})
	}
	v2 := model.QueryMetadata{
		Query: "cancel-v2", Platform: "terraform", Aggregation: 1,
		Metadata: map[string]any{"id": "cancel-v2", "queryName": "Cancel v2", "severity": "HIGH", "platform": "Terraform"},
		Content: `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    result := dd_output.format(bucket, {})
}`,
	}
	legacy := model.QueryMetadata{
		Query: "cancel-legacy", Platform: "terraform", Aggregation: 1,
		Metadata: map[string]any{"id": "cancel-legacy", "queryName": "Cancel legacy", "severity": "HIGH", "platform": "Terraform"},
		Content:  displayNameAclRule,
	}
	for _, tc := range []struct {
		name       string
		queries    []model.QueryMetadata
		numWorkers int
	}{
		{name: "v2 serial roots", queries: []model.QueryMetadata{v2}, numWorkers: 1},
		{name: "v2 worker pool", queries: []model.QueryMetadata{v2}, numWorkers: 4},
		{name: "mixed v2 and legacy", queries: []model.QueryMetadata{v2, legacy}, numWorkers: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ins := newTestInspector(t, inspectorOpts{
				queries: tc.queries, repoPath: repo, vb: DefaultVulnerabilityBuilder, numWorkers: tc.numWorkers,
			})
			// The third check is the builder's periodic check at the 65th of
			// 200 resources, so cancellation lands mid-build.
			ctx := newRelationBuildCancelCtx(3)
			defer ctx.cancel()

			vulns, err := ins.Inspect(ctx, "cancel-"+tc.name, files, []string{"terraform"})

			require.ErrorIs(t, err, context.Canceled, "a scan canceled mid-build must fail, not report a partial unit")
			require.Empty(t, vulns)
			require.EqualValues(t, 3, ctx.calls.Load(), "the relation builder must consult the scan context")
			require.Zero(t, ctx.after.Load(), "the relation builder must stop at the check that saw the cancellation")
			require.Equal(t, ContractV2RunStats{}, ins.ContractV2RunStats(), "a canceled scan is not a failed root")
		})
	}
}

func TestInspectorAccumulatesContractV2StatsConcurrently(t *testing.T) {
	ins := &Inspector{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			ins.addContractV2RunStats(ContractV2RunStats{RootsFailed: 1, PlansFailed: 2, RootsScopeIncomplete: 3})
		})
	}
	wg.Wait()
	require.Equal(t, ContractV2RunStats{RootsFailed: 8, PlansFailed: 16, RootsScopeIncomplete: 24}, ins.ContractV2RunStats())
}

type panicReadFS struct {
	vfs.FS
	panicFile string
}

func (fs panicReadFS) ReadFile(name string) ([]byte, error) {
	if filepath.Clean(name) == filepath.Clean(fs.panicFile) {
		panic("injected filesystem panic")
	}
	return fs.FS.ReadFile(name)
}

type recordingInventorySink struct {
	failure string
}

func (sink *recordingInventorySink) AddResource(*inventory.Resource) {}

func (sink *recordingInventorySink) Fail(reason string) {
	sink.failure = reason
}

func TestContractV2MixedRootPanicsFailInventoryAndCountFailures(t *testing.T) {
	for _, tc := range []struct {
		rootCount int
		procs     int
	}{
		{rootCount: 1, procs: 1},
		{rootCount: 3, procs: 1},
		{rootCount: 3, procs: 4},
	} {
		t.Run(fmt.Sprintf("%d roots with GOMAXPROCS=%d", tc.rootCount, tc.procs), func(t *testing.T) {
			previousProcs := runtime.GOMAXPROCS(tc.procs)
			t.Cleanup(func() { runtime.GOMAXPROCS(previousProcs) })
			rootCount := tc.rootCount

			repo := t.TempDir()
			files := make(model.FileMetadatas, 0, rootCount)
			var panicFile string
			for i := range rootCount {
				root := filepath.Join(repo, fmt.Sprintf("root-%d", i))
				require.NoError(t, os.MkdirAll(root, 0o755))
				content := `resource "aws_s3_bucket" "example" { bucket = "example" }`
				path := filepath.Join(root, "main.tf")
				require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
				files = append(files, &model.FileMetadata{
					ID: fmt.Sprintf("root-%d", i), FilePath: path, Kind: model.KindTerraform,
					Platform: "terraform", OriginalData: content,
				})
				if i == 0 {
					panicFile = filepath.Join(root, "terraform.tfvars")
					require.NoError(t, os.WriteFile(panicFile, []byte("value = true"), 0o600))
				}
			}
			v2 := model.QueryMetadata{
				Query: "panic-v2", Platform: "terraform", Source: model.QuerySourceDefault,
				Metadata: map[string]any{"id": "panic-v2", "queryName": "Panic v2", "severity": "HIGH", "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    result := dd_output.format(bucket, {})
}`,
			}
			legacy := model.QueryMetadata{
				Query: "panic-legacy", Platform: "terraform",
				Metadata: map[string]any{"id": "panic-legacy", "queryName": "Panic legacy", "severity": "HIGH", "platform": "Terraform"},
				Content:  displayNameAclRule,
			}
			var logs bytes.Buffer
			ctx := zerolog.New(&logs).Level(zerolog.DebugLevel).WithContext(context.Background())
			ins := newTestInspector(t, inspectorOpts{
				queries: []model.QueryMetadata{v2, legacy}, repoPath: repo,
				vb: DefaultVulnerabilityBuilder, needsLog: true,
				fsys: panicReadFS{FS: vfs.DiskFS{}, panicFile: panicFile},
			})
			sink := &recordingInventorySink{}
			ins.SetInventory(sink)
			_, err := ins.Inspect(ctx, "mixed-panic", files, []string{"terraform"})
			require.NoError(t, err)
			require.Equal(t, inventory.FailureTerraformPanic, sink.failure)
			require.Contains(t, logs.String(), "recovered from panic")
			require.Equal(t, rootCount, ins.ContractV2RunStats().RootsFailed,
				"every root skipped after a mixed-mode panic must contribute to Contract v2 statistics")
		})
	}
}

func TestContractV2BrokenCompanionKeepsMixedRootIncomplete(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		name := "pure-v2"
		if mixed {
			name = "mixed"
		}
		t.Run(name, func(t *testing.T) {
			repo := t.TempDir()
			mainPath := filepath.Join(repo, "main.tf")
			companionPath := filepath.Join(repo, "versioning.tf")
			main := `resource "aws_s3_bucket" "b" { bucket = "target" }`
			companion := `resource "aws_s3_bucket_versioning" "v" { bucket = aws_s3_bucket.b.id }
{{ broken }}`
			require.NoError(t, os.WriteFile(mainPath, []byte(main), 0o600))
			require.NoError(t, os.WriteFile(companionPath, []byte(companion), 0o600))
			files := model.FileMetadatas{
				&model.FileMetadata{ID: "main", FilePath: mainPath, Kind: model.KindTerraform, Platform: "terraform", OriginalData: main},
				&model.FileMetadata{ID: "companion", FilePath: companionPath, Kind: model.KindTerraform, Platform: "terraform", OriginalData: companion},
			}
			v2 := model.QueryMetadata{
				Query: "broken-companion-v2", Platform: "terraform", Source: model.QuerySourceDefault,
				Metadata: map[string]any{"id": "broken-companion-v2", "queryName": "Broken companion", "severity": "HIGH", "platform": "Terraform"},
				Content: `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    iac.no_related(bucket, "aws_s3_bucket_versioning", "bucket")
    result := dd_output.format(bucket, {})
}`,
			}
			queries := []model.QueryMetadata{v2}
			if mixed {
				queries = append(queries, model.QueryMetadata{
					Query: "legacy-companion", Platform: "terraform", Metadata: map[string]any{"id": "legacy-companion", "platform": "Terraform"}, Content: displayNameAclRule,
				})
			}
			ins := newTestInspector(t, inspectorOpts{queries: queries, repoPath: repo, vb: DefaultVulnerabilityBuilder})
			vulns, err := ins.Inspect(context.Background(), name, files, []string{"terraform"})
			require.NoError(t, err)
			for _, vuln := range vulns {
				require.NotEqual(t, "broken-companion-v2", vuln.QueryID, "incomplete Terraform input cannot prove absence")
			}
			require.Equal(t, 1, ins.ContractV2RunStats().RootsScopeIncomplete)
		})
	}
}

func TestContractV2InvalidFindingPathDoesNotAbortBatch(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, "main.tf")
	content := `resource "aws_s3_bucket" "example" {
  bucket = "target"
  acl    = "public-read"
}
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	ins := newTestInspector(t, inspectorOpts{repoPath: repo, vb: DefaultVulnerabilityBuilder})
	file := &model.FileMetadata{
		ID: "file", FilePath: path, Kind: model.KindTerraform, Platform: "terraform",
		OriginalData: content, LinesOriginalData: utils.SplitLines(content),
	}
	query := &contractV2Rule{meta: model.QueryMetadata{
		Query: "invalid-path-batch", Platform: "terraform", Source: model.QuerySourceDefault,
		Metadata: map[string]interface{}{
			"id": "invalid-path-batch", "queryName": "Invalid path batch", "severity": "HIGH", "platform": "Terraform",
		},
	}}
	resource := &policy.Resource{
		ID: "resource:1", Kind: "resource", Type: "aws_s3_bucket", ResourceKey: "aws_s3_bucket",
		Name: "example", Address: "aws_s3_bucket.example", File: path,
		Attributes: map[string]any{"bucket": "target", "acl": "public-read"},
		Source:     &policy.SourceMapping{BlockSpan: policy.SourceSpan{File: path, StartLine: 1, StartCol: 1, EndLine: 4, EndCol: 1}},
	}
	runner := &contractV2Runner{
		c: ins, scanID: "invalid-path-batch", findings: newFindingSet(false, nil),
		filesByPath: map[string]*model.FileMetadata{contractPathKey(path, repo, ins.fsys): file},
		callers:     map[string]*model.FileMetadata{},
	}
	items := []interface{}{
		map[string]any{"_dd_id": resource.ID, "path": 42},
		map[string]any{"_dd_id": resource.ID, "path": []any{"acl"}},
	}
	runner.decodeContractV2RuleItems(context.Background(), query, items, map[string]*policy.Resource{resource.ID: resource}, 0, false)
	findings := runner.findings.findings()
	require.Len(t, findings, 1, "only the valid output item becomes a finding")
	require.Equal(t, "aws_s3_bucket.example.acl", findings[0].SearchKey, "the malformed path is never treated as a resource-level result")
	failures := ins.GetFailedQueries()
	require.Contains(t, failures, query.meta.Query)
	require.ErrorContains(t, failures[query.meta.Query], "contract/invalid-path")
	require.Equal(t, QueryFailure{Kind: QueryFailureEvaluate, Source: model.QuerySourceDefault}, ins.GetQueryFailures()[query.meta.Query])
}

func TestProjectContractV2ChunkReusesRootProjection(t *testing.T) {
	makeUnit := func(id, resourceID, resourceType string, complete bool) *policy.Unit {
		return &policy.Unit{
			ID: id, Platform: contractV2PlatformTerraform, ScopeComplete: complete,
			Resources: []*policy.Resource{{
				ID: resourceID, Kind: "resource", Type: resourceType, Name: id,
				Address: resourceType + "." + id, File: id + ".tf",
				Attributes: map[string]any{"name": id},
				State:      policy.ValueState{Written: map[string]bool{"name": true}},
			}},
		}
	}
	first := makeUnit("root-a", "r:a", "aws_s3_bucket", true)
	second := makeUnit("root-b", "r:b", "aws_s3_bucket", false)
	uncached := makeUnit("root-c", "r:c", "aws_s3_bucket_policy", true)
	uncached.Resources[0].Relations = &policy.ResourceRelations{
		Targets: map[string]policy.RelationList{"bucket": {IDs: []string{"r:target"}, Complete: true}},
	}
	filtered := makeUnit("root-filtered", "r:d", "aws_instance", true)
	units := []*policy.Unit{first, second, uncached, filtered}
	allowed := map[string]bool{"aws_s3_bucket": true, "aws_s3_bucket_policy": true}
	rootOptions := policy.ProjectOptions{IncludeRelations: true, IncludeByID: true, AllowedTypes: allowed}
	_, firstCached := policy.ProjectUnitsWithResourceCache(contractV2PlatformTerraform, []*policy.Unit{first}, rootOptions)
	_, secondCached := policy.ProjectUnitsWithResourceCache(contractV2PlatformTerraform, []*policy.Unit{second}, rootOptions)
	cached := map[*policy.Unit]ast.Object{first: firstCached, second: secondCached}
	want := policy.ProjectUnits(contractV2PlatformTerraform, units, policy.ProjectOptions{
		IncludeRelations: true, AllowedTypes: allowed,
	})
	got := projectContractV2Chunk(units, cached, allowed)
	require.True(t, reflect.DeepEqual(want, got), "cached and newly projected resource terms must preserve the complete input")

	withRelations := makeUnit("root-relations", "r:rel", "aws_s3_bucket", true)
	withRelations.Resources[0].Relations = &policy.ResourceRelations{Targets: map[string]policy.RelationList{"acl": {IDs: []string{"r:target"}, Complete: true}}}
	rootWithRelations, cachedRelations := policy.ProjectUnitsWithResourceCache(contractV2PlatformTerraform, []*policy.Unit{withRelations}, policy.ProjectOptions{
		IncludeRelations: true, IncludeByID: true, AllowedTypes: allowed,
	})
	rootResources := rootWithRelations.(ast.Object).Get(ast.StringTerm("resources")).Value.(ast.Object)
	rootResource := rootResources.Get(ast.StringTerm("aws_s3_bucket")).Value.(*ast.Array).Elem(0).Value.(ast.Object)
	require.NotNil(t, rootResource.Get(ast.StringTerm("relations")), "root-scoped input retains demanded relations")
	resourceInput := projectContractV2Chunk([]*policy.Unit{withRelations}, map[*policy.Unit]ast.Object{
		withRelations: cachedRelations,
	}, allowed).(ast.Object)
	wantResourceInput := policy.ProjectUnits(contractV2PlatformTerraform, []*policy.Unit{withRelations}, policy.ProjectOptions{
		IncludeRelations: true, AllowedTypes: allowed,
	})
	require.True(t, reflect.DeepEqual(wantResourceInput, resourceInput), "relation-enabled cached resource terms must equal a fresh resource-scoped projection")
	require.Nil(t, resourceInput.Get(ast.StringTerm("by_id")), "resource-scoped input keeps its normal top-level contract")
	resourceArray := resourceInput.Get(ast.StringTerm("resources")).Value.(ast.Object).Get(ast.StringTerm("aws_s3_bucket")).Value.(*ast.Array)
	chunkResource := resourceArray.Elem(0).Value.(ast.Object)
	require.NotNil(t, chunkResource.Get(ast.StringTerm("relations")), "resource chunks retain each resource's relations")
	require.True(t, reflect.DeepEqual(rootResource, chunkResource), "root and resource chunks expose identical resource terms")
	freshChunk := projectContractV2Chunk([]*policy.Unit{withRelations}, nil, allowed)
	require.True(t, reflect.DeepEqual(resourceInput, freshChunk), "cached and uncached resource chunks expose identical resource terms")

	wantConcurrent := projectContractV2Chunk(units, cached, allowed)
	results := make(chan ast.Value, 8)
	for range 8 {
		go func() { results <- projectContractV2Chunk(units, cached, allowed) }()
	}
	for range 8 {
		require.True(t, reflect.DeepEqual(wantConcurrent, <-results), "read-only cached terms must be safe for concurrent use")
	}
}

func TestContractV2ResourceRuleInputDoesNotDependOnUnrelatedRelationRule(t *testing.T) {
	ctx := context.Background()
	sourceText := `
resource "example_trail" "audit" {
  bucket_id = example_bucket.logs.id
}
resource "example_bucket" "logs" {
  name = "audit-logs"
}
resource "example_bucket_acl" "public" {
  bucket = example_bucket.logs.id
  acl    = "public-read"
}
`
	makeRule := func(id, content string) model.QueryMetadata {
		return model.QueryMetadata{
			Query: id, Platform: "terraform", Aggregation: 1, Content: content,
			Metadata: map[string]interface{}{"id": id, "queryName": id, "severity": model.SeverityHigh, "platform": "Terraform"},
		}
	}
	// The key allowlist verifies that resource-scoped rules see the same
	// resource contract, including relations, regardless of loaded rules.
	resourceRule := makeRule("resource-rule", `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.example_bucket
    every key, _ in bucket {
        key in {"id", "kind", "type", "name", "address", "file", "scope_complete", "attributes", "state", "derived", "platform", "relations"}
    }
    result := dd_output.format(bucket, {"path": ["name"]})
}`)
	relationReadRule := makeRule("resource-rule", `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.example_bucket
    count(object.get(bucket, ["relations", "referrers"], {})) == 0
    result := dd_output.format(bucket, {"path": ["name"]})
}`)
	rootRelationRule := makeRule("root-relation-rule", `package datadog
import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
results contains result if {
    some trail in input.resources.example_trail
    some bucket in iac.targets(trail, "bucket_id")
    some acl in iac.related(bucket, "example_bucket_acl", "bucket")
    iac.get(acl, ["acl"]) == "private"
    result := dd_output.format(acl, {"path": ["acl"]})
}`)
	run := func(sourceFiles map[string]string, rules ...model.QueryMetadata) int {
		fsFiles := make(map[string][]byte, len(sourceFiles))
		files := make(model.FileMetadatas, 0, len(sourceFiles))
		for name, content := range sourceFiles {
			path := "/repo/" + name
			fsFiles[path] = []byte(content)
			files = append(files, &model.FileMetadata{
				ID: "file-" + name, FilePath: path, Kind: model.KindTerraform,
				Platform: "terraform", OriginalData: content,
			})
		}
		fs := vfs.NewMemFS(fsFiles)
		inspector, err := NewInspector(ctx, &mockQueriesSource{queries: rules},
			DefaultVulnerabilityBuilder, &tracker.CITracker{}, &source.QueryInspectorParameters{}, nil,
			"/repo", false, true, 1, nil, fs, false)
		require.NoError(t, err)
		findings, err := inspector.Inspect(ctx, "resource-projection-independence", files, []string{"terraform"})
		require.NoError(t, err)
		require.Empty(t, inspector.GetFailedQueries())
		count := 0
		for _, finding := range findings {
			if finding.QueryID == "resource-rule" {
				count++
			}
		}
		return count
	}

	resourceSpec, ok := analyzeContractV2Rule(&resourceRule)
	require.True(t, ok)
	require.False(t, resourceSpec.scopeRoot)
	rootSpec, ok := analyzeContractV2Rule(&rootRelationRule)
	require.True(t, ok)
	require.True(t, rootSpec.scopeRoot)
	require.True(t, rootSpec.needsRelations)

	alone := run(map[string]string{"main.tf": sourceText}, resourceRule)
	withUnrelatedRootRule := run(map[string]string{"main.tf": sourceText}, resourceRule, rootRelationRule)
	require.Equal(t, 1, alone)
	require.Equal(t, alone, withUnrelatedRootRule, "a resource-scoped rule's findings must not depend on which other rules are loaded")

	relationReadSpec, ok := analyzeContractV2Rule(&relationReadRule)
	require.True(t, ok)
	require.False(t, relationReadSpec.scopeRoot, "an object.get relation read is resource-scoped")
	require.True(t, relationReadSpec.needsRelations)
	relationReadAlone := run(map[string]string{"main.tf": sourceText}, relationReadRule)
	require.Equal(t, 0, relationReadAlone, "the bucket has referrers, so a relation read that sees relations finds nothing")
	require.Equal(t, relationReadAlone, run(map[string]string{"main.tf": sourceText}, relationReadRule, rootRelationRule), "a relation-reading rule's findings must not depend on which other rules are loaded")

	twoRootSources := map[string]string{
		"root-a/main.tf": `resource "example_trail" "audit" {
  bucket_id = example_bucket.logs.id
}
resource "example_bucket" "logs" {
  name = "audit-logs"
}
resource "example_bucket_acl" "private" {
  bucket = example_bucket.logs.id
  acl    = "private"
}
`,
		"root-b/main.tf": `resource "example_bucket" "logs" {
  name = "other-logs"
}
resource "example_bucket_acl" "private" {
  bucket = example_bucket.logs.id
  acl    = "private"
}
`,
	}
	aloneAcrossRoots := run(twoRootSources, relationReadRule)
	withRootRuleOnOneRoot := run(twoRootSources, relationReadRule, rootRelationRule)
	require.Zero(t, aloneAcrossRoots, "both buckets have ACL referrers")
	require.Equal(t, aloneAcrossRoots, withRootRuleOnOneRoot, "a root rule matching only one root must not alter uncached resource inputs")
}

func TestContractV2ModuleRelationsDoNotDependOnStaticRuleDemand(t *testing.T) {
	ctx := context.Background()
	hclSource := `resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
module "consumer" {
  source = "./consumer"
  id     = aws_s3_bucket.logs.id
}
`
	planSource := `{
  "format_version": "1.2",
  "planned_values": {"root_module": {"resources": [{
    "address": "aws_s3_bucket.logs", "mode": "managed", "type": "aws_s3_bucket", "name": "logs",
    "values": {"bucket": "logs"}
  }]}},
  "configuration": {"root_module": {
    "resources": [{
      "address": "aws_s3_bucket.logs", "expressions": {"bucket": {"constant_value": "logs"}}
    }],
    "module_calls": {"consumer": {
      "source": "./consumer",
      "expressions": {"id": {"references": ["aws_s3_bucket.logs.id"]}},
      "module": {"variables": {"id": {"default": null}}}
    }}
  }}
}`

	makeRule := func(id, imports, body string) model.QueryMetadata {
		content := `package datadog
import rego.v1
import data.datadog.output as dd_output
` + imports + `
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    ` + body + `
    result := dd_output.format(bucket, {})
}
`
		return model.QueryMetadata{
			Query: id, Platform: "terraform", Aggregation: 1, Content: content,
			Metadata: map[string]interface{}{"id": id, "queryName": id, "severity": model.SeverityHigh, "platform": "Terraform"},
		}
	}
	directReadRule := makeRule("direct-relation-read", "", `count(object.get(bucket, ["relations", "referrers", "id", "ids"], [])) == 0`)
	facadeReadRule := makeRule("facade-relation-read", "import data.datadog.iac as iac", `iac.no_referrers(bucket, ["id"])`)
	unrelatedVariableRule := model.QueryMetadata{
		Query: "unrelated-variable", Platform: "terraform", Aggregation: 1,
		Metadata: map[string]interface{}{"id": "unrelated-variable", "queryName": "unrelated-variable", "severity": model.SeverityHigh, "platform": "Terraform"},
		Content: `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
    some v in input.resources.variable
    v.name == "never-matches"
    result := dd_output.format(v, {})
}`,
	}

	run := func(t *testing.T, filename string, kind model.FileKind, content string, rules ...model.QueryMetadata) []model.Vulnerability {
		t.Helper()
		path := "/repo/" + filename
		fs := vfs.NewMemFS(map[string][]byte{path: []byte(content)})
		inspector, err := NewInspector(ctx, &mockQueriesSource{queries: rules}, DefaultVulnerabilityBuilder,
			&tracker.CITracker{}, &source.QueryInspectorParameters{}, nil, "/repo", false, true, 1, nil, fs, false)
		require.NoError(t, err)
		files := model.FileMetadatas{{
			ID: "file-" + filename, FilePath: path, Kind: kind, Platform: "terraform", OriginalData: content,
		}}
		findings, err := inspector.Inspect(ctx, "module-relations", files, []string{"terraform"})
		require.NoError(t, err)
		require.Empty(t, inspector.GetFailedQueries())
		return findings
	}

	for _, tc := range []struct {
		name     string
		filename string
		kind     model.FileKind
		content  string
	}{
		{name: "hcl module argument", filename: "main.tf", kind: model.KindTerraform, content: hclSource},
		{name: "plan module call", filename: "plan.json", kind: model.KindTerraformPlan, content: planSource},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, rule := range []model.QueryMetadata{directReadRule, facadeReadRule} {
				alone := run(t, tc.filename, tc.kind, tc.content, rule)
				withUnrelated := run(t, tc.filename, tc.kind, tc.content, rule, unrelatedVariableRule)
				require.Empty(t, alone, "the module argument references the bucket, so relations are present")
				require.Equal(t, alone, withUnrelated, "module relations must not depend on static-rule demand")
			}
		})
	}
}

func TestContractV2RemediationReceivesRelations(t *testing.T) {
	ctx := context.Background()
	content := `resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
module "consumer" {
  source = "./consumer"
  id     = aws_s3_bucket.logs.id
}
`
	rule := model.QueryMetadata{
		Query: "relation-remediation", Platform: "terraform", Aggregation: 1,
		Metadata: map[string]interface{}{"id": "relation-remediation", "queryName": "relation-remediation", "severity": model.SeverityHigh, "platform": "Terraform"},
		Content: `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    result := dd_output.format(bucket, {})
}
remediate(bucket, _) := {"remediation": sprintf("referrers=%d", [count(object.get(bucket, ["relations", "referrers", "id", "ids"], []))]), "remediationType": "replacement"} if {
    count(object.get(bucket, ["relations", "referrers", "id", "ids"], [])) == 1
}`,
	}
	path := "/repo/main.tf"
	fs := vfs.NewMemFS(map[string][]byte{path: []byte(content)})
	inspector, err := NewInspector(ctx, &mockQueriesSource{queries: []model.QueryMetadata{rule}}, DefaultVulnerabilityBuilder,
		&tracker.CITracker{}, &source.QueryInspectorParameters{}, nil, "/repo", false, true, 1, nil, fs, false)
	require.NoError(t, err)
	findings, err := inspector.Inspect(ctx, "relation-remediation", model.FileMetadatas{{
		ID: "file-main.tf", FilePath: path, Kind: model.KindTerraform, Platform: "terraform", OriginalData: content,
	}}, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, inspector.GetFailedQueries())
	require.Len(t, findings, 1)
	require.Equal(t, "referrers=1", findings[0].Remediation, "remediate receives resource.relations")
}

func TestFlushContractV2ChunkInvalidatesProjectionCache(t *testing.T) {
	unit := &policy.Unit{Resources: []*policy.Resource{{ID: "r:1"}}}
	runner := &contractV2Runner{
		chunk:                   []*policy.Unit{unit},
		chunkProjectedResources: map[*policy.Unit]ast.Object{unit: ast.NewObject()},
		chunkResCount:           1,
	}
	require.NoError(t, runner.flushChunk(context.Background()))
	require.Empty(t, runner.chunk)
	require.Nil(t, runner.chunkProjectedResources)
	require.Zero(t, runner.chunkResCount)
}

func TestContractV2PlanFindingUsesRawPlanPositions(t *testing.T) {
	minified := []byte(`{"format_version":"1.2","planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.plan","mode":"managed","type":"aws_s3_bucket","name":"plan","values":{"bucket":"plan-bucket"}}]}},"configuration":{"root_module":{"resources":[{"address":"aws_s3_bucket.plan","expressions":{"bucket":{"constant_value":"plan-bucket"}}}]}}}`)
	var indented bytes.Buffer
	require.NoError(t, json.Indent(&indented, minified, "", "  "))

	rule := model.QueryMetadata{
		Query: "contract-v2-plan", Platform: "terraform", Aggregation: 1,
		Metadata: map[string]interface{}{
			"id": "contract-v2-plan", "queryName": "Plan bucket", "severity": "HIGH", "platform": "Terraform",
		},
		Content: `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    result := dd_output.format(bucket, {"path": ["bucket"]})
}`,
	}

	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{name: "minified", raw: minified},
		{name: "indented", raw: indented.Bytes()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			path := filepath.Join(repo, "tfplan.json")
			require.NoError(t, os.WriteFile(path, tc.raw, 0o600))
			jp := &terraformJSONParser.Parser{}
			parsed, err := jp.ParsePlan(context.Background(), tc.raw, path, false, 15)
			require.NoError(t, err)
			content, err := jp.StringifyContent(tc.raw)
			require.NoError(t, err)
			files := model.FileMetadatas{&model.FileMetadata{
				ID: "plan", FilePath: path, Kind: model.KindTerraformPlan, Platform: "terraform",
				OriginalData: content,
				Document:     parsed.Documents[0], LineInfoDocument: parsed.Documents[0],
			}}
			ins := newTestInspector(t, inspectorOpts{queries: []model.QueryMetadata{rule}, repoPath: repo, vb: DefaultVulnerabilityBuilder})
			vulns, err := ins.Inspect(context.Background(), "plan-position", files, []string{"terraform"})
			require.NoError(t, err)
			require.Empty(t, ins.GetFailedQueries())
			require.Len(t, vulns, 1)

			bucketOffset := bytes.Index(tc.raw, []byte(`"bucket"`))
			require.NotEqual(t, -1, bucketOffset)
			wantLine := bytes.Count(tc.raw[:bucketOffset], []byte("\n")) + 1
			lineStart := bytes.LastIndex(tc.raw[:bucketOffset], []byte("\n")) + 1
			wantColumn := bucketOffset - lineStart + 1
			require.Equal(t, wantLine, vulns[0].VulnerabilityLocation.Start.Line)
			require.Equal(t, wantColumn, vulns[0].VulnerabilityLocation.Start.Col)
			require.Equal(t, (*utils.SplitLines(string(tc.raw)))[wantLine-1], vulns[0].LineWithVulnerability, "plan finding text comes from raw plan lines")
		})
	}
}

func TestContractV2SameProviderConfigFacade(t *testing.T) {
	queryMeta := model.QueryMetadata{
		Query:    "provider-config-demand",
		Platform: "terraform",
		Content: `package datadog
import rego.v1
import data.datadog.terraform as tf
import data.datadog.output as dd_output
results contains result if {
    some resource in input.resources.aws_s3_bucket
    tf.same_provider_config(resource, resource)
    result := dd_output.format(resource, {})
}`,
	}
	spec, ok := analyzeContractV2Rule(&queryMeta)
	require.True(t, ok)
	require.True(t, spec.needsProviders, "same_provider_config needs Terraform provider metadata")
	require.True(t, spec.scopeRoot, "provider-scoped rules must stay root-scoped")

	ctx := context.Background()
	libs, err := contractlibs.Modules()
	require.NoError(t, err)
	query := `matched := count({true | data.datadog.terraform.same_provider_config(input.a, input.b)}) > 0
matched == input.expected`
	opts := []func(*rego.Rego){rego.Query(query)}
	for _, module := range libs {
		opts = append(opts, rego.ParsedModule(module))
	}
	prepared, err := rego.New(opts...).PrepareForEval(ctx)
	require.NoError(t, err)

	providerResource := func(providerID string) map[string]any {
		return map[string]any{"platform": map[string]any{"terraform": map[string]any{"provider_id": providerID}}}
	}
	ambientResource := map[string]any{"platform": map[string]any{"terraform": map[string]any{}}}
	for _, tc := range []struct {
		name     string
		a, b     map[string]any
		expected bool
	}{
		{name: "same configured provider", a: providerResource("aws.default"), b: providerResource("aws.default"), expected: true},
		{name: "different configured providers", a: providerResource("aws.default"), b: providerResource("aws.secondary"), expected: false},
		{name: "two ambient default providers", a: ambientResource, b: ambientResource, expected: true},
		{name: "ambient and explicit provider", a: ambientResource, b: providerResource("aws.default"), expected: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results, evalErr := prepared.Eval(ctx, rego.EvalInput(map[string]any{
				"a": tc.a, "b": tc.b, "expected": tc.expected,
			}))
			require.NoError(t, evalErr)
			require.Len(t, results, 1, "provider equality should match the expected result")
		})
	}

	nestedQuery := `nested := data.datadog.iac.blocks(input.a, "spec")[0]
data.datadog.terraform.same_provider_config(nested, input.b)`
	nestedOpts := []func(*rego.Rego){rego.Query(nestedQuery)}
	for _, module := range libs {
		nestedOpts = append(nestedOpts, rego.ParsedModule(module))
	}
	nestedPrepared, err := rego.New(nestedOpts...).PrepareForEval(ctx)
	require.NoError(t, err)
	nestedResults, err := nestedPrepared.Eval(ctx, rego.EvalInput(map[string]any{
		"a": map[string]any{
			"attributes": map[string]any{"spec": []any{map[string]any{}}},
			"platform":   map[string]any{"terraform": map[string]any{"provider_id": "aws.default"}},
			"state":      map[string]any{},
		},
		"b": providerResource("aws.default"),
	}))
	require.NoError(t, err)
	require.Len(t, nestedResults, 1, "nested views must resolve provider identity through their root resource")

	facadeQuery := `result := {
  "unset": count({true | data.datadog.iac.is_unset(input.r, input.path)}) > 0,
  "absent": count({true | data.datadog.iac.is_absent(input.r, input.path)}) > 0,
  "not_equals": count({true | data.datadog.iac.not_equals(input.r, input.path, "other")}) > 0,
  "not_in": count({true | data.datadog.iac.not_in(input.r, input.path, ["other"])}) > 0,
}
result == input.expected`
	facadeOpts := []func(*rego.Rego){rego.Query(facadeQuery)}
	for _, module := range libs {
		facadeOpts = append(facadeOpts, rego.ParsedModule(module))
	}
	facadePrepared, err := rego.New(facadeOpts...).PrepareForEval(ctx)
	require.NoError(t, err)
	for _, tc := range []struct {
		name string
		r    map[string]any
		want bool
	}{
		{
			name: "incomplete ancestor with absent child",
			r: map[string]any{
				"attributes": map[string]any{},
				"state":      map[string]any{"incomplete_collections": map[string]any{"tags": true}},
			},
			want: false,
		},
		{
			name: "incomplete ancestor with known child",
			r: map[string]any{
				"attributes": map[string]any{"tags": map[string]any{"Owner": "team"}},
				"state":      map[string]any{"incomplete_collections": map[string]any{"tags": true}},
			},
			want: false,
		},
		{
			name: "complete absent child",
			r:    map[string]any{"attributes": map[string]any{}, "state": map[string]any{}},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results, evalErr := facadePrepared.Eval(ctx, rego.EvalInput(map[string]any{
				"r": tc.r, "path": []any{"tags", "Owner"},
				"expected": map[string]any{"unset": tc.want, "absent": tc.want, "not_equals": tc.want, "not_in": tc.want},
			}))
			require.NoError(t, evalErr)
			require.Len(t, results, 1, "absence and exemption helpers should follow collection completeness")
		})
	}

	truthQuery := `result := {
  "is_true": count({true | data.datadog.iac.is_true(input.r, ["value"])}) > 0,
  "is_false": count({true | data.datadog.iac.is_false(input.r, ["value"])}) > 0,
}
result == input.expected`
	truthOpts := []func(*rego.Rego){rego.Query(truthQuery)}
	for _, module := range libs {
		truthOpts = append(truthOpts, rego.ParsedModule(module))
	}
	truthPrepared, err := rego.New(truthOpts...).PrepareForEval(ctx)
	require.NoError(t, err)
	for _, tc := range []struct {
		value   any
		isTrue  bool
		isFalse bool
	}{
		{value: true, isTrue: true},
		{value: false, isFalse: true},
		{value: "true", isTrue: true},
		{value: "false", isFalse: true},
		{value: "1", isTrue: true},
		{value: "0", isFalse: true},
		{value: "yes"},
		{value: "on"},
		{value: "TRUE"},
	} {
		results, evalErr := truthPrepared.Eval(ctx, rego.EvalInput(map[string]any{
			"r":        map[string]any{"attributes": map[string]any{"value": tc.value}, "state": map[string]any{}},
			"expected": map[string]any{"is_true": tc.isTrue, "is_false": tc.isFalse},
		}))
		require.NoError(t, evalErr, "value: %#v", tc.value)
		require.Len(t, results, 1, "only Terraform boolean values should be accepted: %#v", tc.value)
	}

	reservedKeys := []string{"documentId", "resourceType", "resourceName", "searchKey", "id", "queryName", "severity", "platform", "category", "descriptionID", "cloudProvider"}
	formatQuery := `result := data.datadog.output.format(input.resource, input.details)
result.path == input.expected_path
result._dd_id == input.resource.id
every key in input.reserved { not key in result }`
	formatOpts := []func(*rego.Rego){rego.Query(formatQuery)}
	for _, module := range libs {
		formatOpts = append(formatOpts, rego.ParsedModule(module))
	}
	formatPrepared, err := rego.New(formatOpts...).PrepareForEval(ctx)
	require.NoError(t, err)
	for _, tc := range []struct {
		name string
		path any
		want any
	}{
		{name: "absent path", want: []any{}},
		{name: "empty path", path: "", want: []any{}},
		{name: "string path", path: "acl", want: []any{"acl"}},
		{name: "array path", path: []any{"ingress", 0}, want: []any{"ingress", 0}},
		{name: "null path remains invalid", path: nil, want: nil},
		{name: "number path remains invalid", path: 42, want: 42},
		{name: "object path remains invalid", path: map[string]any{}, want: map[string]any{}},
		{name: "boolean path remains invalid", path: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			details := map[string]any{"after": "replacement", "_dd_id": "rule-authored identity override"}
			if tc.name != "absent path" {
				details["path"] = tc.path
			}
			for _, key := range reservedKeys {
				details[key] = "rule-authored identity override"
			}
			results, evalErr := formatPrepared.Eval(ctx, rego.EvalInput(map[string]any{
				"resource": map[string]any{"id": "resource-1"}, "details": details,
				"expected_path": tc.want, "reserved": reservedKeys,
			}))
			require.NoError(t, evalErr)
			require.Len(t, results, 1, "output.format must preserve invalid path values for Go validation")
		})
	}
}
