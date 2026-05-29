/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-iac-scanner/internal/pathutil"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"

	"github.com/open-policy-agent/opa/cover"
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
	queries             []model.QueryMetadata
	querySource         source.QueriesSource
	queryParameters     *source.QueryInspectorParameters
	excludeResults      map[string]bool
	repoPath            string
	queryTimeout        int
	useOldSeverities    bool
	needsLog            bool
	numWorkers          int
	kicsComputeNewSimID bool
	vb                  VulnerabilityBuilder
	tracker             Tracker
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
	if opts.excludeResults == nil {
		opts.excludeResults = map[string]bool{}
	}
	if opts.repoPath == "" {
		opts.repoPath = "."
	}
	if opts.queryTimeout == 0 {
		opts.queryTimeout = 60
	}
	if opts.numWorkers == 0 {
		opts.numWorkers = 1
	}
	if opts.vb == nil {
		opts.vb = func(_ context.Context, _ *QueryContext, _ Tracker, _ interface{},
			_ *detector.DetectLine, _ bool, _ bool, _ time.Duration) (*model.Vulnerability, error) {
			return &model.Vulnerability{}, nil
		}
	}
	if opts.tracker == nil {
		opts.tracker = &tracker.CITracker{}
	}

	ins, err := NewInspector(
		context.Background(),
		opts.querySource,
		opts.vb,
		opts.tracker,
		opts.queryParameters,
		opts.excludeResults,
		nil,
		opts.repoPath,
		opts.queryTimeout,
		opts.useOldSeverities,
		opts.needsLog,
		opts.numWorkers,
		opts.kicsComputeNewSimID,
		featureflags.NewLocalEvaluator(),
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
		queries:             queries,
		tracker:             track,
		needsLog:            true,
		kicsComputeNewSimID: true,
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

func TestEngine_LenQueriesByPlat(t *testing.T) {
	queries := []model.QueryMetadata{
		{Query: "tf_rule_a", Content: "package tf_rule_a\n", InputData: "{}", Platform: "terraform", Aggregation: 1},
		{Query: "tf_rule_b", Content: "package tf_rule_b\n", InputData: "{}", Platform: "terraform", Aggregation: 1},
		{Query: "k8s_rule", Content: "package k8s_rule\n", InputData: "{}", Platform: "kubernetes", Aggregation: 1},
	}
	ins := newTestInspector(t, inspectorOpts{queries: queries, kicsComputeNewSimID: true})

	require.Equal(t, 2, ins.LenQueriesByPlat([]string{"terraform"}))
	require.Equal(t, 1, ins.LenQueriesByPlat([]string{"kubernetes"}))
	require.Equal(t, 3, ins.LenQueriesByPlat([]string{"terraform", "kubernetes"}))
	require.Equal(t, 0, ins.LenQueriesByPlat([]string{"cloudformation"}))
}

func TestEngine_GetFailedQueries(t *testing.T) {
	ins := newTestInspector(t, inspectorOpts{kicsComputeNewSimID: true})
	const nrFailedQueries = 5
	for idx := 0; idx < nrFailedQueries; idx++ {
		ins.failedQueries[fmt.Sprint(idx)] = nil
	}
	require.Equal(t, nrFailedQueries, len(ins.GetFailedQueries()))
}

func TestShouldSkipFile(t *testing.T) {
	type args struct {
		commands      model.CommentsCommands
		queryID       string
		legacyQueryID string
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldSkipVulnerability(tt.args.commands, tt.args.queryID, tt.args.legacyQueryID)
			require.Equal(t, tt.expected, got)
		})
	}
}

// TestGetVulnerabilitiesFromQuery_SuppressionPaths covers the three
// suppression gates (`disable:<queryID>`, `ignore-line`, similarity-id
// exclusion) plus the non-suppressed baseline.
func TestGetVulnerabilitiesFromQuery_SuppressionPaths(t *testing.T) {
	const (
		fileID        = "file-1"
		queryID       = "platform-provider-rule"
		legacyQueryID = "legacy-id"
		similarityID  = "sim-1"
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
			SimilarityID:  similarityID,
			Line:          matchingLine,
		}
	}

	cases := []struct {
		name                  string
		file                  *model.FileMetadata
		excludeResults        map[string]bool
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
		{
			name:                  "excluded_by_similarity_id",
			file:                  baseFile(),
			excludeResults:        map[string]bool{similarityID: true},
			expectSuppressed:      true,
			expectSuppressionKind: model.SuppressionKindExternal,
			expectJustification:   model.SuppressionJustificationExcludeResults,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			built := buildVulnerability()
			ins := newTestInspector(t, inspectorOpts{
				excludeResults: tc.excludeResults,
				vb: func(_ context.Context, _ *QueryContext, _ Tracker, _ interface{},
					_ *detector.DetectLine, _ bool, _ bool, _ time.Duration) (*model.Vulnerability, error) {
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
			_ *detector.DetectLine, _ bool, _ bool, _ time.Duration) (*model.Vulnerability, error) {
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
		similarityID = "sim-1"
		matchingLine = 11
	)

	file := &model.FileMetadata{
		ID:          fileID,
		FilePath:    "main.tf",
		Commands:    model.CommentsCommands{"disable": queryID},
		LinesIgnore: []int{matchingLine},
	}

	built := &model.Vulnerability{
		FileID:       fileID,
		QueryID:      queryID,
		QueryName:    "rule",
		SimilarityID: similarityID,
		Line:         matchingLine,
	}

	ins := newTestInspector(t, inspectorOpts{
		excludeResults: map[string]bool{similarityID: true},
		vb: func(_ context.Context, _ *QueryContext, _ Tracker, _ interface{},
			_ *detector.DetectLine, _ bool, _ bool, _ time.Duration) (*model.Vulnerability, error) {
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
	c := newTestInspector(t, inspectorOpts{kicsComputeNewSimID: true})

	queryContext := newQueryContext(ctx)

	// Pass a context that is already expired so DecodeQueryResults must short-circuit
	// on its cancellation branch and return no results.
	expiredCtx, cancel := context.WithTimeout(ctx, 0)
	defer cancel()
	result, err := c.DecodeQueryResults(ctx, &queryContext, expiredCtx, newResultset(), 57)
	assert.Nil(t, err, "Error not as expected")
	assert.Equal(t, 0, len(result), "Array size is not as expected")
}

func newResultset() rego.ResultSet {
	myValue := make(map[string]interface{})
	myValue["documentId"] = "3a3be8f7-896e-4ef8-9db3-d6c19e60510b"
	myValue["issueType"] = "IncorrectValue"
	myValue["keyActualValue"] = "COPY --from referencesthe current FROM alias"
	myValue["keyExpectedValue"] = "COPY --from should not references the current FROM alias"
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
		// When SplatExpr is dispatched, we get source[*]. Until then we get __UNSUPPORTED_EXPR__.
		got := val.String()
		if got != `"var.list[*]"` && got != `"__UNSUPPORTED_EXPR__"` {
			t.Errorf("expressionToAST = %s", got)
		}
	})
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

func TestMatchesPath(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		file    string
		want    bool
	}{
		{"exact match", "/repo/src/main.tf", "/repo/src/main.tf", true},
		{"directory prefix", "/repo/src", "/repo/src/main.tf", true},
		{"directory prefix no trailing sep", "/repo/src", "/repo/src/nested/main.tf", true},
		{"no match different dir", "/repo/test", "/repo/src/main.tf", false},
		{"no partial prefix match", "/repo/s", "/repo/src/main.tf", false},
		{"glob star", "/repo/src/*.tf", "/repo/src/main.tf", true},
		{"glob star no match", "/repo/src/*.tf", "/repo/src/main.go", false},
		{"glob question mark", "/repo/src/mai?.tf", "/repo/src/main.tf", true},
		// double-star (**) glob
		{"doublestar all tf files", "/repo/**/*.tf", "/repo/src/main.tf", true},
		{"doublestar nested", "/repo/**/*.tf", "/repo/src/nested/deep/main.tf", true},
		{"doublestar no match ext", "/repo/**/*.tf", "/repo/src/main.go", false},
		{"doublestar prefix any subdir", "**/terraform/**", "infra/terraform/main.tf", true},
		{"doublestar prefix no match", "**/terraform/**", "infra/k8s/main.yaml", false},
		{"doublestar matches zero segments", "a/**/b.tf", "a/b.tf", true},
		{"doublestar matches one segment", "a/**/b.tf", "a/x/b.tf", true},
		{"doublestar matches many segments", "a/**/b.tf", "a/x/y/z/b.tf", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, pathutil.MatchesPath(tt.pattern, tt.file))
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
