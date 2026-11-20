/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
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
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"

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
		vfs.DiskFS{},
		opts.useRulesCache,
	)
	require.NoError(t, err)
	return ins
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
	got := expandModuleFindings(vulns, nil)
	require.Equal(t, vulns, got)
}

func TestExpandModuleFindings_ClonesPerExtraCaller(t *testing.T) {
	primaryID := "primary\x00stack-a|module.app\x00this"
	extraID := "extra\x00stack-b|module.app\x00this"
	extras := map[string][]extraCallerInfo{
		primaryID: {{callChain: "stack-b|module.app", docID: extraID}},
	}
	vulns := []model.Vulnerability{{
		FileID:    primaryID,
		FileName:  "modules/app/main.tf",
		Line:      5,
		QueryName: "rule-a",
	}}
	got := expandModuleFindings(vulns, extras)
	require.Len(t, got, 2)
	require.Equal(t, primaryID, got[0].FileID)
	require.Equal(t, extraID, got[1].FileID)
	require.Equal(t, "stack-b|module.app", got[1].ModuleCallChain)
	require.Equal(t, got[0].Line, got[1].Line)
	require.Equal(t, got[0].FileName, got[1].FileName)
	require.Equal(t, got[0].QueryName, got[1].QueryName)
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

func TestEntityPolicyScalarReads(t *testing.T) {
	const source = `package datadog
import rego.v1
import data.iac
DatadogPolicy contains iac.finding(e,["acl"],{}) if {some e in iac.targets("resource","bucket");iac.raw(e,["acl"])=="public"}
DatadogPolicy contains iac.finding(e,["encrypted"],{}) if {some e in iac.targets("resource","bucket");not iac.nonnull(e,["encrypted"])}
`
	programs, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
	program := programs["policy"]
	require.NoError(t, err)
	for _, test := range []struct {
		name                string
		acl, encrypted      cty.Value
		count               int
		symbolic, uncertain bool
	}{
		{"known", cty.StringVal("public"), cty.True, 1, false, false},
		{"private", cty.StringVal("private"), cty.True, 0, false, false},
		{"null", cty.StringVal("private"), cty.NullVal(cty.Bool), 1, false, false},
		{"false is present", cty.StringVal("private"), cty.False, 0, false, false},
		{"unknown required", cty.UnknownVal(cty.String), cty.True, 0, true, true},
		{"known witness and unknown other predicate", cty.StringVal("public"), cty.UnknownVal(cty.Bool), 1, true, true},
		{"nonnull refinement", cty.StringVal("private"), cty.UnknownVal(cty.Bool).RefineNotNull(), 0, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{"opaque:1": {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"acl": test.acl, "encrypted": test.encrypted, "unrelated": cty.DynamicVal})}}, true)
			var gotFindings []EntityFinding

			got, err := program.Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: reader}, Emit: func(f EntityFinding) error {
				gotFindings = append(gotFindings, f)
				return nil
			}})
			require.NoError(t, err)
			require.Len(t, gotFindings, test.count)
			require.Equal(t, test.symbolic, got.Symbolic)
			require.Equal(t, test.uncertain, got.Indeterminate)
			for _, finding := range gotFindings {
				require.Equal(t, "opaque:1", finding.Subject)
			}
		})
	}
	t.Run("absence", func(t *testing.T) {
		reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{"opaque:1": {Kind: "resource", Type: "bucket", Value: cty.EmptyObjectVal}}, true)
		var gotFindings []EntityFinding

		got, err := program.Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: reader}, Emit: func(f EntityFinding) error {
			gotFindings = append(gotFindings, f)
			return nil
		}})
		require.NoError(t, err)
		require.Len(t, gotFindings, 1)
		require.False(t, got.Symbolic)
	})
	t.Run("producer error preserves completed progress", func(t *testing.T) {
		reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{
			"a": {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"acl": cty.StringVal("public"), "encrypted": cty.True})},
			"b": {Kind: "resource", Type: "bucket", Err: fmt.Errorf("native evaluation failed")},
		}, true)
		emitted := 0
		result, err := program.Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: reader}, BatchSize: 1, Emit: func(EntityFinding) error { emitted++; return nil }})
		require.ErrorContains(t, err, "native evaluation failed")
		require.Equal(t, 1, result.Confirmed)
		require.Equal(t, 1, emitted)
	})
	t.Run("open inventory", func(t *testing.T) {
		_, err := program.Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: tfeval.NewValueReader(nil, false)}, Emit: func(f EntityFinding) error {
			return nil
		}})
		require.ErrorContains(t, err, "open Terraform inventory")
	})
}

func TestEntityPolicyReadContract(t *testing.T) {
	for _, body := range []string{
		`not e.acl`,
		`count(object.keys(e))==0`,
		`input.__dd_symbols.x`,
		`data.__dd_entity_rules.q0.expected=="public"`,
		`iac.raw(e,["acl"]) with input.arguments as {}`,
		`dd.describe("opaque",["acl"])`,
	} {
		t.Run(body, func(t *testing.T) {
			source := `package datadog
import rego.v1
import data.iac
DatadogPolicy contains iac.finding(e,[],{}) if {some e in iac.targets("resource","bucket");` + body + `}`
			_, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
			require.Error(t, err)
		})
	}
	for _, namespace := range []string{"iac", "__dd_entity_partial", "__dd_entity_rules.q0"} {
		t.Run("reserved library/"+namespace, func(t *testing.T) {
			source := `package datadog
import rego.v1
import data.iac
DatadogPolicy contains iac.finding(e,[],{}) if {some e in iac.targets("resource","bucket")}`
			_, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, map[string]string{"library.rego": "package " + namespace + "\nvalue := true"})
			require.ErrorContains(t, err, "engine-owned policy namespace")
		})
	}
	t.Run("concurrent reusable program", func(t *testing.T) {
		source := `package datadog
import rego.v1
import data.iac
DatadogPolicy contains iac.finding(e,["acl"],{}) if {some e in iac.targets("resource","bucket");iac.raw(e,["acl"])=="public"}`
		programs, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
		program := programs["policy"]
		require.NoError(t, err)
		for _, test := range []struct {
			name, id string
			acl      cty.Value
			want     int
			symbolic bool
		}{
			{"known public", "shared-id", cty.StringVal("public"), 1, false},
			{"known private", "shared-id", cty.StringVal("private"), 0, false},
			{"unknown nullable", "first-id", cty.UnknownVal(cty.String), 0, true},
			{"unknown nonnull", "second-id", cty.UnknownVal(cty.String).RefineNotNull(), 0, true},
		} {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()
				reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{test.id: {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"acl": test.acl})}}, true)
				var findings []EntityFinding
				result, err := program.Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: reader}, Emit: func(f EntityFinding) error { findings = append(findings, f); return nil }})
				require.NoError(t, err)
				require.Len(t, findings, test.want)
				require.Equal(t, test.symbolic, result.Symbolic)
				require.Equal(t, test.symbolic, result.Indeterminate)
			})
		}
	})
	t.Run("reporting metadata belongs to the scanner", func(t *testing.T) {
		for _, field := range []string{"documentId", "searchKey", "resourceType", "resourceName"} {
			source := fmt.Sprintf(`package datadog
import rego.v1
import data.iac
DatadogPolicy contains iac.finding(e,[],{%q:"author-supplied"}) if {some e in iac.targets("resource","bucket")}`, field)
			programs, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
			require.NoError(t, err)
			reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{"subject": {Kind: "resource", Type: "bucket", Value: cty.EmptyObjectVal}}, true)
			_, err = programs["policy"].Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: reader}, Emit: func(EntityFinding) error { t.Fatal("invalid reporting metadata emitted"); return nil }})
			require.ErrorContains(t, err, field)
		}
	})
}

func TestEntityPolicyHelperBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, helper, body string
		wantError          bool
	}{
		{"explicit read helper", `secure(e) if {iac.raw(e,["acl"])=="private"}`, `not secure(e)`, false},
		{"ordered fallback helper", `secure(x):=true if {iac.raw(x,["acl"])=="private"} else:=false`, `secure(e)==false`, true},
		{"default helper", `default secure(_):=false
secure(x):=true if {iac.raw(x,["acl"])=="private"}`, `secure(e)==false`, true},
		{"ordered helper with failing builtin", `secure(x):=true if {to_number(iac.raw(x,["acl"]))>0} else:=false`, `secure(e)==false`, true},
		{"unreachable ordered helper", `unused(x):=true if x else:=false`, `iac.raw(e,["acl"])=="public"`, false},
		{"private helper import alias", `import data.iac._present as hidden`, `peer:=iac.raw(e,["peer"]);not hidden(peer,["acl"])`, true},
		{"private iac helper", ``, `peer:=iac.raw(e,["peer"]);not iac._present(peer,["acl"])`, true},
		{"private iac qualified helper", ``, `peer:=iac.raw(e,["peer"]);not data.iac._present(peer,["acl"])`, true},
		{"literal read subject", ``, `iac.raw("not-a-handle",["acl"])=="public"`, true},
		{"configured read subject", ``, `peer:=iac.raw(e,["peer"]);iac.raw(peer,["acl"])=="public"`, true},
		{"mixed helper subject roles", `read(x):=iac.raw(x,["acl"])`, `read(e)=="public";read("not-a-handle")=="public"`, true},
		{"entity collection helper", `public(xs) if {some x in xs;iac.raw(x,["acl"])=="public"}`, `public(iac.entities("resource","bucket"))`, false},
		{"literal collection helper", `public(xs) if {some x in xs;iac.raw(x,["acl"])=="public"}`, `public(iac.entities("resource","bucket"));public(["b"])`, true},
		{"configured collection helper", `public(xs) if {some x in xs;iac.raw(x,["acl"])=="public"}`, `peer:=iac.raw(e,["peer"]);public(iac.entities("resource","bucket"));public([peer])`, true},
		{"negative equality is not a binding", ``, `peer:=iac.raw(e,["peer"]);not peer==e;iac.raw(peer,["acl"])=="public"`, true},
		{"negative helper equality is not a binding", `same(x,y) if x==y`, `peer:=iac.raw(e,["peer"]);not same(peer,e);iac.raw(peer,["acl"])=="public"`, true},
		{"negative membership is not a binding", ``, `peer:=iac.raw(e,["peer"]);not peer in iac.entities("resource","protector");iac.raw(peer,["acl"])=="public"`, true},
		{"scalar equality cannot mint a subject", ``, `peer:=iac.raw(e,["peer"]);peer==e;iac.raw(peer,["acl"])=="public"`, true},
		{"mixed entity and scalar result", `pick(x):=x if iac.raw(x,["which"])=="self"
pick(x):=iac.raw(x,["peer"]) if iac.raw(x,["which"])=="other"`, `iac.raw(pick(e),["acl"])=="public"`, true},
		{"mixed entity and literal result", `pick(x):=x if input.arguments.pick
pick(x):="b" if not input.arguments.pick`, `iac.raw(pick(e),["acl"])=="public"`, true},
		{"mixed inventory and literal result", `pick:=iac.entities("resource","bucket") if input.arguments.pick
pick:=["b"] if not input.arguments.pick`, `some peer in pick;iac.raw(peer,["acl"])=="public"`, true},
		{"conditional entity result", `pick(x):=x if iac.raw(x,["which"])=="self"`, `iac.raw(pick(e),["acl"])=="public"`, false},
		{"conditional entity collection result", `pick(xs):=xs if input.arguments.pick
public(xs) if {some x in xs;iac.raw(x,["acl"])=="public"}`, `public(pick(iac.entities("resource","bucket")))`, false},
		{"unreachable qualified helper", `unused.hidden(x) if data.iac._present(x,["acl"])`, `iac.raw(e,["acl"])=="public"`, false},
		{"qualified default helper", `default util.secure(_):=false
util.secure(v):=true if v=="private"`, `util.secure(iac.raw(e,["acl"]))==false`, true},
		{"qualified private helper", `util.hidden(x) if data.iac._present(x,["acl"])`, `not util.hidden(iac.raw(e,["peer"]))`, true},
		{"qualified untyped subject helper", `util.read(x):=iac.raw(x,["acl"])`, `util.read("not-a-handle")=="public"`, true},
		{"qualified comprehension helper", `util.values(x):=[v | some v in x]`, `count(util.values([true]))==1`, true},
		{"negated field in a polymorphic helper", `missing(x) if not x.acl`, `missing(e)`, true},
		{"polymorphic object helper", `valid(x,k) if {is_object(x);x[k]!=null}`, `not valid(e,"acl")`, true},
		{"helper through alias", `valid(x,k) if {is_object(x);x[k]!=null}
wrapper(x) if {copy:=x;valid(copy,"acl")}`, `not wrapper(e)`, true},
		{"opaque collection helper patterns", `missing([x]) if not x.acl`, `missing(iac.entities("resource","bucket"))`, true},
		{"opaque container escape", `wrapped(x):={"value":x}`, `object.get(wrapped(e),"acl",null)==null`, true},
		{"derived partial set", `publics contains x if {some x in iac.entities("resource","bucket");iac.raw(x,["acl"])=="public"}`, `count(publics)==1`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := `package datadog
import rego.v1
import data.iac
` + test.helper + `
DatadogPolicy contains iac.finding(e,[],{}) if {some e in iac.targets("resource","bucket");` + test.body + `}`
			_, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
			if test.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEntityPolicyUnknownLogic(t *testing.T) {
	for _, test := range []struct {
		name, body string
		uncertain  bool
	}{
		{"read implies presence", `iac.raw(e,["acl"])=="public";not iac.present(e,["acl"])`, false},
		{"nonnull implies presence", `iac.nonnull(e,["acl"]);not iac.present(e,["acl"])`, false},
		{"non-null value cannot equal null", `iac.value(e,["acl"])==null`, false},
		{"Boolean data view", `iac.valid_key(e,["acl"])==false`, true},
		{"Boolean data contradiction", `iac.valid_key(e,["acl"])==true;not iac.present(e,["acl"])`, false},
		{"unknown equality", `iac.raw(e,["acl"])=="public"`, true},
		{"unknown negation", `not iac.nonnull(e,["acl"])`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := `package datadog
import rego.v1
import data.iac
DatadogPolicy contains iac.finding(e,["acl"],{}) if {some e in iac.targets("resource","bucket");` + test.body + `}`
			programs, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
			program := programs["policy"]
			require.NoError(t, err)
			reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{"opaque": {Kind: "resource", Type: "bucket", Value: cty.UnknownVal(cty.Map(cty.String))}}, true)
			var gotFindings []EntityFinding

			got, err := program.Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: reader}, Emit: func(f EntityFinding) error {
				gotFindings = append(gotFindings, f)
				return nil
			}})
			require.NoError(t, err)
			require.Empty(t, gotFindings)
			require.Equal(t, test.uncertain, got.Indeterminate)
			require.True(t, got.Symbolic)
		})
	}
	t.Run("public Boolean read forms", func(t *testing.T) {
		reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{
			"a": {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"acl": cty.StringVal("public")})},
			"b": {Kind: "resource", Type: "bucket", Value: cty.UnknownVal(cty.Map(cty.String))},
			"c": {Kind: "resource", Type: "bucket", Value: cty.EmptyObjectVal},
			"d": {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"acl": cty.NullVal(cty.String)})},
			"e": {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"acl": cty.False})},
			"f": {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"acl": cty.UnknownVal(cty.String).RefineNotNull()})},
			"g": {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"acl": cty.UnknownVal(cty.String)})},
		}, true)
		for _, helper := range []struct {
			name               string
			positive, negative []string
		}{
			{"iac.present_value", []string{"a", "d", "e", "f", "g"}, []string{"c"}},
			{"has_acl", []string{"a", "d", "e", "f", "g"}, []string{"c"}},
			{"iac.valid_key", []string{"a", "e", "f"}, []string{"c", "d"}},
			{"valid_acl", []string{"a", "e", "f"}, []string{"c", "d"}},
		} {
			call := helper.name + `(e,["acl"])`
			for _, form := range []struct {
				body string
				want []string
			}{{call, helper.positive}, {call + "==true", helper.positive}, {call + "==false", helper.negative}, {"not " + call, helper.negative}} {
				t.Run(form.body, func(t *testing.T) {
					source := `package datadog
import rego.v1
import data.iac
import data.iac.present_value as has_acl
import data.iac.valid_key as valid_acl
DatadogPolicy contains iac.finding(e,["acl"],{}) if {some e in iac.targets("resource","bucket");` + form.body + `}`
					programs, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
					require.NoError(t, err)
					for _, size := range []int{1, 2, 0} {
						var subjects []string
						result, err := programs["policy"].Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: reader}, BatchSize: size, Emit: func(f EntityFinding) error { subjects = append(subjects, f.Subject); return nil }})
						require.NoError(t, err)
						require.ElementsMatch(t, form.want, subjects)
						require.True(t, result.Indeterminate)
					}
				})
			}
		}
	})
}

func TestEntityPolicySharedPreparation(t *testing.T) {
	for _, namespace := range []string{"output", "datadog.output"} {
		t.Run(namespace, func(t *testing.T) {
			for _, reference := range []string{"expected", "data.datadog.expected", "self.expected", "data.datadog.__entity_q0"} {
				t.Run(reference, func(t *testing.T) {
					source := func(want string) string {
						return `package datadog
		import rego.v1
		import data.iac
		import data.datadog as self
		import data.` + namespace + ` as output
		expected := "` + want + `"
		__entity_q0 := expected
		local_check(self) if self.expected=="public"
		DatadogPolicy contains iac.finding(e,["acl"],output.details) if {some e in iac.targets("resource","bucket");iac.raw(e,["acl"])==` + reference + `;local_check({"expected":"public"})}`
					}
					sources := map[string]string{"public": source("public"), "private": source("private")}
					libraries := map[string]string{"output.rego": "package " + namespace + `
		import rego.v1
		details := {"remediation": "restrict acl"}`, "shared.rego": `package datadog
		import rego.v1
		expected := "shared"`}
					programs, err := PrepareEntityPolicies(context.Background(), sources, libraries)
					sources["public"] = "invalid after preparation"
					sources["private"] = "invalid after preparation"
					require.NoError(t, err)
					require.Same(t, programs["public"].symbolic, programs["private"].symbolic)
					require.Nil(t, programs["public"].symbolic.programs)
					uncertain := tfeval.NewValueReader(map[string]tfeval.ValueSubject{"opaque": {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"acl": cty.UnknownVal(cty.String)})}}, true)
					summary, err := programs["public"].Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: uncertain}, Emit: func(EntityFinding) error { return nil }})
					require.NoError(t, err)
					require.True(t, summary.Indeterminate)
					require.Len(t, programs["public"].symbolic.programs, 2)
					reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{"opaque": {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"acl": cty.StringVal("public")})}}, true)
					for id, program := range programs {
						t.Run(id, func(t *testing.T) {
							t.Parallel()
							var resultFindings []EntityFinding
							_, err := program.Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: reader}, Emit: func(f EntityFinding) error {
								resultFindings = append(resultFindings, f)
								return nil
							}})
							require.NoError(t, err)
							want := 0
							if id == "public" {
								want = 1
							}
							require.Len(t, resultFindings, want)
							for _, finding := range resultFindings {
								require.Equal(t, "restrict acl", finding.Details["remediation"])
							}
						})
					}
				})
			}
		})
	}
}

func TestEntityPolicyTypedFindingPaths(t *testing.T) {
	source := `package datadog
import rego.v1
import data.iac
DatadogPolicy contains iac.finding(e,["0",0,1.0,"with.dot[0]"],{"_dd_id":"unregistered","path":["forged"]}) if {some e in iac.targets("resource","bucket")}`
	programs, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
	program := programs["policy"]
	require.NoError(t, err)
	reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{"opaque": {Kind: "resource", Type: "bucket", Value: cty.EmptyObjectVal}}, true)
	var resultFindings []EntityFinding
	_, err = program.Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: reader}, Emit: func(f EntityFinding) error {
		resultFindings = append(resultFindings, f)
		return nil
	}})
	require.NoError(t, err)
	require.Len(t, resultFindings, 1)
	require.Empty(t, resultFindings[0].Details, "identity/path belong to typed fields, not business details")
	key, property := resultFindings[0].Path[0].Property()
	require.True(t, property)
	require.Equal(t, "0", key)
	index, indexed := resultFindings[0].Path[1].Position()
	require.True(t, indexed)
	require.EqualValues(t, 0, index)
	index, indexed = resultFindings[0].Path[2].Position()
	require.True(t, indexed)
	require.EqualValues(t, 1, index)
	key, property = resultFindings[0].Path[3].Property()
	require.True(t, property)
	require.Equal(t, "with.dot[0]", key)
	t.Run("location descriptors do not gate the security proof", func(t *testing.T) {
		for _, path := range []string{`input.arguments.path`, `["items",iac.raw(e,["index"])]`} {
			query := `package datadog
import rego.v1
import data.iac
DatadogPolicy contains iac.finding(e,` + path + `,{}) if {some e in iac.targets("resource","bucket")}`
			_, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": query}, nil)
			require.ErrorContains(t, err, "ground typed descriptors")
		}
	})
}

func TestEntityPolicyFindingDescriptors(t *testing.T) {
	for _, test := range []struct {
		name, helper, details string
		valid                 bool
	}{
		{"literal", ``, `{"remediation":"enabled = true","remediationType":"addition"}`, true},
		{"JSON encoding", ``, `{"remediation":json.marshal({"before":"false","after":"true"}),"remediationType":"replacement"}`, true},
		{"JSON encoding of constant", `base:={"enabled":true}`, `{"remediation":json.marshal(base)}`, true},
		{"JSON encoding through constant aliases", `base:={"enabled":true}
 alias:=base
 encoded:=json.marshal(alias)`, `{"remediation":encoded}`, true},
		{"conditional argument to constant function", `missing:="value" if false
 fix(x):={"remediation":"enabled = true"}`, `fix(missing)`, false},
		{"constant helper", `fix := {"remediation":"enabled = true"}`, `fix`, true},
		{"pattern-matched descriptor helper", `fix({"allowed":true}):={"remediation":"enabled = true"}`, `fix({"allowed":false})`, false},
		{"conditional helper", `fix := {"remediation":"enabled = true"} if false`, `fix`, false},
		{"unknown dependent helper", `fix(e):={"remediation":"enabled = true"} if iac.nonnull(e,["other"])`, `fix(e)`, false},
		{"value formatting", ``, `{"remediation":json.marshal({"before":iac.raw(e,["other"]),"after":"true"})}`, false},
		{"optional argument", ``, `{"remediation":input.arguments.text}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := `package datadog
import rego.v1
import data.iac
` + test.helper + `
DatadogPolicy contains iac.finding(e,["acl"],` + test.details + `) if {
 some e in iac.targets("resource","bucket")
 iac.raw(e,["acl"])=="public"
}`
			programs, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
			program := programs["policy"]
			if !test.valid {
				require.ErrorContains(t, err, "ground declarative")
				return
			}
			require.NoError(t, err)
			reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{"opaque": {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"acl": cty.StringVal("public"), "other": cty.DynamicVal})}}, true)
			var resultFindings []EntityFinding

			result, err := program.Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: reader}, Emit: func(f EntityFinding) error {
				resultFindings = append(resultFindings, f)
				return nil
			}})
			require.NoError(t, err)
			require.Len(t, resultFindings, 1)
			require.False(t, result.Symbolic)
			require.NotEmpty(t, resultFindings[0].Details["remediation"])
		})
	}
}

func TestEntityPolicyTargetScopes(t *testing.T) {
	const source = `package datadog
import rego.v1
import data.iac
linked(e) if {
 peer:=iac.raw(e,["peer"])
 some other in iac.entities("resource","bucket")
 other==peer
 iac.raw(other,["public"])==true
}
DatadogPolicy contains iac.finding(e,["peer"],{}) if {
 some e in iac.targets("resource","bucket")
 not linked(e)
}`
	programs, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
	require.NoError(t, err)
	for _, test := range []struct {
		name      string
		public    cty.Value
		count     int
		uncertain bool
	}{
		{"known protection outside focus", cty.True, 1, false},
		{"known unprotected peers", cty.False, 2, false},
		{"known violation beside unknown protection", cty.UnknownVal(cty.Bool), 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{
				"a": {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"peer": cty.StringVal("b"), "public": cty.False})},
				"b": {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"peer": cty.StringVal("a"), "public": test.public})},
			}, true)
			var baseline []EntityFinding
			for _, size := range []int{1, 2, 8, 0} {
				var findings []EntityFinding
				result, err := programs["policy"].Evaluate(context.Background(), EntityEvaluationRequest{
					Unit: entityUnitFixture{reader: reader}, BatchSize: size, Emit: func(f EntityFinding) error { findings = append(findings, f); return nil },
				})
				require.NoError(t, err)
				require.Equal(t, test.count, result.Confirmed)
				require.Equal(t, test.uncertain, result.Indeterminate)
				require.Len(t, findings, test.count)
				if size == 1 {
					baseline = findings
				} else {
					require.ElementsMatch(t, baseline, findings)
				}
			}
		})
	}
}

func TestEntityPolicyExecutionLifecycle(t *testing.T) {
	const source = `package datadog
import rego.v1
import data.iac
DatadogPolicy contains iac.finding(copy,[],{}) if {some e in iac.targets("resource","bucket");copy:=e}`
	programs, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
	require.NoError(t, err)
	reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{
		"a": {Kind: "resource", Type: "bucket", Value: cty.EmptyObjectVal},
		"b": {Kind: "resource", Type: "bucket", Value: cty.EmptyObjectVal},
		"c": {Kind: "resource", Type: "bucket", Value: cty.EmptyObjectVal},
	}, true)
	t.Run("emitter failure retains accepted progress", func(t *testing.T) {
		failure := errors.New("finding sink failed")
		calls := 0
		result, err := programs["policy"].Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: reader}, BatchSize: 1, Emit: func(EntityFinding) error {
			calls++
			if calls == 2 {
				return failure
			}
			return nil
		}})
		require.ErrorIs(t, err, failure)
		require.Equal(t, 1, result.Confirmed)
		require.Equal(t, 2, calls)
	})
	t.Run("cancellation retains accepted progress", func(t *testing.T) {
		for _, cancelAt := range []int{1, 3} {
			for _, size := range []int{1, 0} {
				ctx, cancel := context.WithCancel(context.Background())
				accepted := 0
				result, err := programs["policy"].Evaluate(ctx, EntityEvaluationRequest{Unit: entityUnitFixture{reader: reader}, BatchSize: size, Emit: func(EntityFinding) error {
					accepted++
					if accepted == cancelAt {
						cancel()
					}
					return nil
				}})
				cancel()
				require.ErrorIs(t, err, context.Canceled)
				require.Equal(t, cancelAt, result.Confirmed)
			}
		}
	})
	t.Run("empty authoritative inventory", func(t *testing.T) {
		result, err := programs["policy"].Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: tfeval.NewValueReader(nil, true)}, Emit: func(EntityFinding) error { t.Fatal("unexpected finding"); return nil }})
		require.NoError(t, err)
		require.Zero(t, result)
	})
	t.Run("inventory ownership", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			ids   []string
			valid bool
		}{
			{"unordered inventory", []string{"c", "a", "b"}, true},
			{"duplicate registered subject", []string{"a", "b", "a"}, false},
			{"unregistered subject", []string{"a", "missing"}, false},
		} {
			t.Run(test.name, func(t *testing.T) {
				original := append([]string{}, test.ids...)
				var emitted []string
				result, err := programs["policy"].Evaluate(context.Background(), EntityEvaluationRequest{
					Unit: entityUnitFixture{reader: entityReaderFixture{Reader: reader, ids: test.ids}}, BatchSize: 1,
					Emit: func(f EntityFinding) error { emitted = append(emitted, f.Subject); return nil },
				})
				require.Equal(t, original, test.ids)
				if test.valid {
					require.NoError(t, err)
					require.Equal(t, []string{"a", "b", "c"}, emitted)
					require.Equal(t, 3, result.Confirmed)
				} else {
					require.Error(t, err)
					require.Empty(t, emitted)
				}
			})
		}
	})
}

type entityReaderFixture struct {
	policy.Reader
	ids    []string
	symbol string
}

func (r entityReaderFixture) Entities(kind, typ string) ([]string, error) {
	if r.ids == nil {
		return r.Reader.Entities(kind, typ)
	}
	return slices.Clone(r.ids), nil
}

func (r entityReaderFixture) Read(subject string, path policy.Path) (policy.Read, error) {
	read, err := r.Reader.Read(subject, path)
	if read.State == policy.Unknown || read.MaybeAbsent {
		read.Symbol = r.symbol
	}
	return read, err
}

func TestEntityPolicyFocusDomain(t *testing.T) {
	for _, test := range []struct{ name, helper, body, owner string }{
		{"global owner", ``, `some e in iac.targets("resource","bucket");some other in iac.entities("resource","bucket")`, `other`},
		{"target index selection", ``, `e:=iac.targets("resource","bucket")[0]`, `e`},
		{"target position observation", ``, `some i,e in iac.targets("resource","bucket");i==0`, `e`},
		{"target inventory observation", ``, `xs:=iac.targets("resource","bucket");some e in xs;count(xs)>0`, `e`},
		{"multiple target iterators", ``, `some e in iac.targets("resource","bucket");some other in iac.targets("resource","bucket");iac.present(other,[])`, `e`},
		{"helper target inventory", `chosen:=iac.targets("resource","bucket")`, `some e in chosen`, `e`},
		{"helper owner alias", `identity(x):=x`, `some e in iac.targets("resource","bucket");copy:=identity(e)`, `copy`},
		{"negated alias", ``, `some e in iac.targets("resource","bucket");some other in iac.entities("resource","bucket");not other==e`, `other`},
		{"missing primary selector", ``, `some e in iac.entities("resource","bucket")`, `e`},
		{"dynamic primary selector", ``, `some e in iac.targets("resource",input.arguments.type)`, `e`},
		{"decision namespace observation", ``, `some e in iac.targets("resource","bucket");count(data.datadog)>0`, `e`},
		{"nondeterministic security predicate", ``, `some e in iac.targets("resource","bucket");time.now_ns()>0`, `e`},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := `package datadog
import rego.v1
import data.iac
` + test.helper + `
DatadogPolicy contains iac.finding(` + test.owner + `,[],{}) if {` + test.body + `}`
			_, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
			require.Error(t, err)
		})
	}
	t.Run("library namespaces cannot hide focus dependencies", func(t *testing.T) {
		library := `package lookup
import rego.v1
import data.iac
public if {some x in iac.targets("resource","bucket");iac.raw(x,["public"])==true}`
		for _, body := range []string{`object.get(data.lookup,input.arguments.key,false)==false`, `not data.lookup[input.arguments.key]`} {
			source := `package datadog
import rego.v1
import data.iac
DatadogPolicy contains iac.finding(e,[],{}) if {some e in iac.targets("resource","bucket");` + body + `}`
			_, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, map[string]string{"lookup.rego": library})
			require.Error(t, err)
		}
	})
}

func TestEntityPolicySelectorUnion(t *testing.T) {
	reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{
		"a": {Kind: "resource", Type: "bucket", Value: cty.EmptyObjectVal},
		"b": {Kind: "resource", Type: "bucket", Value: cty.EmptyObjectVal},
	}, true)
	for _, test := range []struct {
		name, path string
		count      int
	}{
		{"same witness through overlapping selectors", `[]`, 2},
		{"distinct paths through overlapping selectors", `["other"]`, 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := `package datadog
import rego.v1
import data.iac
DatadogPolicy contains iac.finding(e,[],{}) if {some e in iac.targets("resource","left")}
DatadogPolicy contains iac.finding(e,` + test.path + `,{}) if {some e in iac.targets("resource","right")}`
			programs, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
			require.NoError(t, err)
			for _, size := range []int{1, 2, 0} {
				var findings []EntityFinding
				result, err := programs["policy"].Evaluate(context.Background(), EntityEvaluationRequest{
					Unit: entityUnitFixture{reader: entityReaderFixture{Reader: reader, ids: []string{"b", "a"}}}, BatchSize: size,
					Emit: func(f EntityFinding) error { findings = append(findings, f); return nil },
				})
				require.NoError(t, err)
				require.Equal(t, test.count, result.Confirmed)
				require.Len(t, findings, test.count)
			}
		})
	}
}

func TestEntityPolicyCorrelatedObservations(t *testing.T) {
	for _, test := range []struct {
		name, condition string
		left, right     cty.Value
		count           int
		uncertain       bool
	}{
		{"shared value with independent optional attributes", `iac.raw(e,["acl"])=="public";not iac.present(other,["acl"])`, cty.UnknownVal(cty.Map(cty.String)), cty.UnknownVal(cty.Map(cty.String)), 0, true},
		{"shared value with required peer attribute", `iac.raw(e,["acl"])=="public";not iac.present(other,["acl"])`, cty.UnknownVal(cty.Map(cty.String)), cty.ObjectVal(map[string]cty.Value{"acl": cty.UnknownVal(cty.String)}), 0, false},
		{"shared value with absent peer attribute", `iac.raw(e,["acl"])=="public";not iac.present(other,["acl"])`, cty.UnknownVal(cty.Map(cty.String)), cty.EmptyObjectVal, 0, true},
		{"known witness with absent peer attribute", `iac.raw(e,["acl"])=="public";not iac.present(other,["acl"])`, cty.ObjectVal(map[string]cty.Value{"acl": cty.StringVal("public")}), cty.EmptyObjectVal, 1, false},
		{"same present unknown value preserves equality correlation", `iac.raw(e,["acl"])=="public";not iac.raw(other,["acl"])=="public"`, cty.ObjectVal(map[string]cty.Value{"acl": cty.UnknownVal(cty.String)}), cty.ObjectVal(map[string]cty.Value{"acl": cty.UnknownVal(cty.String)}), 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := `package datadog
import rego.v1
import data.iac
DatadogPolicy contains iac.finding(e,["acl"],{}) if {
 some e in iac.targets("resource","bucket")
 some other in iac.entities("resource","peer")
 ` + test.condition + `
}`
			programs, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
			require.NoError(t, err)
			reader := entityReaderFixture{Reader: tfeval.NewValueReader(map[string]tfeval.ValueSubject{
				"a": {Kind: "resource", Type: "bucket", Value: test.left},
				"b": {Kind: "resource", Type: "peer", Value: test.right},
			}, true), symbol: "shared-value-origin"}
			for _, size := range []int{1, 0} {
				var findings []EntityFinding
				result, err := programs["policy"].Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: reader}, BatchSize: size, Emit: func(f EntityFinding) error { findings = append(findings, f); return nil }})
				require.NoError(t, err)
				require.Len(t, findings, test.count)
				require.Equal(t, test.count, result.Confirmed)
				require.Equal(t, test.uncertain, result.Indeterminate)
			}
		})
	}
}

func TestEntityPolicyFindingSetSemantics(t *testing.T) {
	const source = `package datadog
import rego.v1
import data.iac
DatadogPolicy contains iac.finding(e,[1],{"value":1}) if {some e in iac.targets("resource","bucket")}
DatadogPolicy contains iac.finding(e,[1.0],{"value":1.0}) if {some e in iac.targets("resource","bucket")}
DatadogPolicy contains iac.finding(e,[2],{}) if {some e in iac.targets("resource","bucket");iac.raw(e,["public"])==true}
`
	programs, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
	require.NoError(t, err)
	for _, test := range []struct {
		name      string
		public    cty.Value
		count     int
		uncertain bool
	}{
		{"known", cty.True, 4, false},
		{"mixed", cty.UnknownVal(cty.Bool), 3, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{
				"a": {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"public": cty.True})},
				"b": {Kind: "resource", Type: "bucket", Value: cty.ObjectVal(map[string]cty.Value{"public": test.public})},
			}, true)
			for _, size := range []int{1, 2, 0} {
				count := 0
				result, err := programs["policy"].Evaluate(context.Background(), EntityEvaluationRequest{Unit: entityUnitFixture{reader: reader}, BatchSize: size, Emit: func(EntityFinding) error { count++; return nil }})
				require.NoError(t, err)
				require.Equal(t, test.count, count)
				require.Equal(t, test.count, result.Confirmed)
				require.Equal(t, test.uncertain, result.Indeterminate)
			}
		})
	}
}

func TestEntityPolicyNativeEvaluationOutcomes(t *testing.T) {
	const source = `package datadog
import rego.v1
import data.iac
DatadogPolicy contains iac.finding(e,["acl"],{}) if {some e in iac.targets("resource","aws_s3_bucket");iac.raw(e,["acl"])=="public"}
DatadogPolicy contains iac.finding(e,["flag"],{}) if {some e in iac.targets("resource","aws_s3_bucket");iac.raw(e,["flag"])==true}
`
	programs, err := PrepareEntityPolicies(context.Background(), map[string]string{"policy": source}, nil)
	require.NoError(t, err)
	for _, test := range []struct {
		name, declaration     string
		inputs                map[string]cty.Value
		resources             bool
		confirmed             int
		indeterminate, failed bool
	}{
		{"valid conformed bool", `type=bool`, map[string]cty.Value{"input": cty.True}, true, 2, false, false},
		{"invalid concrete input is not a witness", `type=number`, map[string]cty.Value{"input": cty.True}, true, 1, true, true},
		{"valid number is not a bool", `type=number`, map[string]cty.Value{"input": cty.NumberIntVal(2)}, true, 1, false, false},
		{"missing runtime input stays unknown", `type=bool`, nil, true, 1, true, false},
		{"unknown runtime input stays unknown", `type=bool`, map[string]cty.Value{"input": cty.UnknownVal(cty.Bool)}, true, 1, true, false},
		{"nullable null stays null", `type=bool`, map[string]cty.Value{"input": cty.NullVal(cty.Bool)}, true, 1, false, false},
		{"valid null default fallback", "type=bool\nnullable=false\ndefault=false", map[string]cty.Value{"input": cty.NullVal(cty.Bool)}, true, 1, false, false},
		{"invalid explicit null", "type=bool\nnullable=false", map[string]cty.Value{"input": cty.NullVal(cty.Bool)}, true, 1, true, true},
		{"failed variable with no target inventory", `type=number`, map[string]cty.Value{"input": cty.True}, false, 0, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			source := "variable \"input\" {\n" + test.declaration + "\n}\n"
			if test.resources {
				source += `resource "aws_s3_bucket" "dependent" {flag=var.input}
resource "aws_s3_bucket" "independent" {acl="public"}`
			}
			require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(source), 0600))
			evaluation, err := tfeval.New().EvaluateModule(context.Background(), dir, test.inputs)
			require.NoError(t, err)
			subjects := map[string]tfeval.ValueSubject{}
			for _, resource := range evaluation.Resources {
				subjects[resource.Name] = tfeval.ValueSubject{Kind: "resource", Type: resource.Type, Value: cty.ObjectVal(resource.Attributes)}
			}
			emitted := 0
			result, err := programs["policy"].Evaluate(context.Background(), EntityEvaluationRequest{
				Unit: evaluation.PolicyUnit(tfeval.NewValueReader(subjects, true)),
				Emit: func(EntityFinding) error { emitted++; return nil },
			})
			require.Equal(t, test.confirmed, emitted)
			require.Equal(t, test.confirmed, result.Confirmed)
			require.Equal(t, test.indeterminate, result.Indeterminate)
			if test.failed {
				var diagnostic *tfeval.EvaluationDiagnostic
				require.ErrorAs(t, err, &diagnostic)
				require.Equal(t, "Invalid variable value", diagnostic.Summary)
			} else {
				require.NoError(t, err)
			}
		})
	}

	t.Run("aborted producer cannot become a clean empty policy result", func(t *testing.T) {
		producerCtx, cancel := context.WithCancel(context.Background())
		cancel()
		evaluation, err := tfeval.New().EvaluateModule(producerCtx, t.TempDir(), nil)
		require.ErrorIs(t, err, context.Canceled)
		result, err := programs["policy"].Evaluate(context.Background(), EntityEvaluationRequest{
			Unit: evaluation.PolicyUnit(tfeval.NewValueReader(nil, true)),
			Emit: func(EntityFinding) error { t.Fatal("aborted producer emitted a finding"); return nil },
		})
		require.ErrorIs(t, err, context.Canceled)
		require.Zero(t, result.Confirmed)
	})

	for _, test := range []struct {
		name, source  string
		file, invalid string
		child         bool
		confirmed     int
	}{
		{"invalid local computation without target inventory", `data "aws_iam_policy_document" "invalid" {source_json="private-invalid-policy"}`, "", "", false, 0},
		{"invalid local computation preserves independent witness", `data "google_iam_policy" "invalid" {
 binding {
 role={}
 members=["allUsers"]
 }
}
resource "aws_s3_bucket" "dependent" {flag=length(keys(jsondecode(data.google_iam_policy.invalid.policy_data).bindings[0]))==1}
resource "aws_s3_bucket" "independent" {acl="public"}`, "", "", false, 1},
		{"failed output without resource inventory", `output "invalid" {value=tonumber("invalid")}`, "", "", false, 0},
		{"failed child without resource inventory", `module "child" {source="./child"}`, "", "", true, 0},
		{"failed child preserves independent witness", `module "child" {source="./child"}
resource "aws_s3_bucket" "example" {acl="public"}`, "", "", true, 1},
		{"invalid resource expansion without inventory", `resource "aws_s3_bucket" "invalid" {
count=-1
acl="public"
}`, "", "", false, 0},
		{"invalid expansion preserves independent witness", `resource "aws_s3_bucket" "invalid" {
count=null
acl="public"
}
resource "aws_s3_bucket" "known" {acl="public"}`, "", "", false, 1},
		{"invalid module expansion without inventory", `module "invalid" {
source="./"
count=-1
}`, "", "", false, 0},
		{"invalid HCL without resource inventory", "", "invalid.tf", `resource "aws_s3_bucket" "broken" {`, false, 0},
		{"invalid JSON without resource inventory", "", "invalid.tf.json", `{"resource":`, false, 0},
		{"invalid HCL preserves independent witness", `resource "aws_s3_bucket" "example" {acl="public"}`, "invalid.tf", `resource "aws_s3_bucket" "broken" {`, false, 1},
		{"invalid JSON preserves independent witness", `resource "aws_s3_bucket" "example" {acl="public"}`, "invalid.tf.json", `{"resource":`, false, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(test.source), 0600))
			if test.file != "" {
				require.NoError(t, os.WriteFile(filepath.Join(dir, test.file), []byte(test.invalid), 0600))
			}
			if test.child {
				require.NoError(t, os.Mkdir(filepath.Join(dir, "child"), 0700))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "child", "main.tf"), []byte(`output "name" {value="unused"}`), 0600))
			}
			evaluator := tfeval.New()
			if test.child {
				evaluator = tfeval.NewWithFS(directoryFailureFS{FS: vfs.DiskFS{}, dir: filepath.Join(dir, "child")})
			}
			evaluation, err := evaluator.EvaluateModule(context.Background(), dir, nil)
			require.NoError(t, err)
			subjects := map[string]tfeval.ValueSubject{}
			for _, resource := range evaluation.Resources {
				subjects[resource.Name] = tfeval.ValueSubject{Kind: "resource", Type: resource.Type, Value: cty.ObjectVal(resource.Attributes)}
			}
			emitted := 0
			result, err := programs["policy"].Evaluate(context.Background(), EntityEvaluationRequest{
				Unit: evaluation.PolicyUnit(tfeval.NewValueReader(subjects, true)),
				Emit: func(EntityFinding) error { emitted++; return nil },
			})
			require.Equal(t, test.confirmed, result.Confirmed)
			require.Equal(t, test.confirmed, emitted)
			var diagnostic *tfeval.EvaluationDiagnostic
			require.ErrorAs(t, err, &diagnostic)
			if test.file != "" {
				require.Equal(t, filepath.Join(dir, test.file), diagnostic.Subject.Filename)
			}
			if test.child {
				require.Equal(t, "module.child", diagnostic.ModuleAddress)
			}
		})
	}

	for _, test := range []struct {
		name, flag, other             string
		confirmed                     int
		indeterminate, failed, cancel bool
	}{
		{"known", `false`, `"unused"`, 1, false, false, false},
		{"known violations", `true`, `"unused"`, 2, false, false, false},
		{"irrelevant unknown stays silent", `false`, `var.input`, 1, false, false, false},
		{"relevant unknown stays indeterminate", `var.input`, `"unused"`, 1, true, false, false},
		{"unrelated producer failure preserves witness", `false`, `tonumber("invalid")`, 1, false, true, false},
		{"failed predicate is not a successful unknown", `tonumber("invalid")`, `"unused"`, 1, true, true, false},
		{"producer failure and cancellation both survive", `false`, `tonumber("invalid")`, 1, false, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			nativeSource := fmt.Sprintf(`variable "input" {type=bool}
resource "aws_s3_bucket" "example" {
 acl="public"
 flag=%s
 other=%s
}`, test.flag, test.other)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(nativeSource), 0600))
			evaluation, err := tfeval.New().EvaluateModule(context.Background(), dir, nil)
			require.NoError(t, err)
			require.Len(t, evaluation.Resources, 1)
			reader := tfeval.NewValueReader(map[string]tfeval.ValueSubject{"entity": {Kind: "resource", Type: evaluation.Resources[0].Type, Value: cty.ObjectVal(evaluation.Resources[0].Attributes)}}, true)
			diagnostics := evaluation.Diagnostics()
			originalSummary := ""
			if len(diagnostics) > 0 {
				originalSummary = diagnostics[0].Summary
				diagnostics[0].Summary = "caller changed the inspection snapshot"
			}
			unit := evaluation.PolicyUnit(reader)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var findings []EntityFinding
			result, err := programs["policy"].Evaluate(ctx, EntityEvaluationRequest{Unit: unit, Emit: func(f EntityFinding) error {
				findings = append(findings, f)
				if test.cancel {
					cancel()
				}
				return nil
			}})
			require.Len(t, findings, test.confirmed)
			require.Equal(t, test.confirmed, result.Confirmed)
			require.Equal(t, test.indeterminate, result.Indeterminate)
			if test.failed {
				var diagnostic *tfeval.EvaluationDiagnostic
				require.ErrorAs(t, err, &diagnostic)
				require.Equal(t, originalSummary, diagnostic.Summary)
			} else {
				require.NoError(t, err)
			}
			if test.cancel {
				require.ErrorIs(t, err, context.Canceled)
			}
		})
	}
}

type entityUnitFixture struct{ reader policy.Reader }

func (u entityUnitFixture) Reader() policy.Reader { return u.reader }
func (u entityUnitFixture) Failure() error        { return nil }

type directoryFailureFS struct {
	vfs.FS
	dir string
}

func (f directoryFailureFS) ReadDir(dir string) ([]fs.DirEntry, error) {
	if filepath.Clean(dir) == filepath.Clean(f.dir) {
		return nil, fs.ErrPermission
	}
	return f.FS.ReadDir(dir)
}
