/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestModuleAttributionSerializationContract(t *testing.T) {
	attribution := &ModuleAttribution{
		CallSite: SourceLocation{Filename: "infra/main.tf", LineStart: 1, LineEnd: 4},
	}

	// Vulnerability is the content-push wire type: the IDE anchors instantiated
	// findings on the call-site declaration, so the attribution must serialize.
	vulnerabilityJSON, err := json.Marshal(Vulnerability{ModuleAttribution: attribution})
	require.NoError(t, err)
	require.Contains(t, string(vulnerabilityJSON), "moduleAttribution")
	require.Contains(t, string(vulnerabilityJSON), "call_site")

	// VulnerableFile is the report-side type: SARIF exposes the attribution as a
	// dedicated properties payload (ModuleAttributionForSARIF), never inline.
	summaryFileJSON, err := json.Marshal(VulnerableFile{ModuleAttribution: attribution})
	require.NoError(t, err)
	require.NotContains(t, string(summaryFileJSON), "module_attribution")
}

// Every file of a packaged dependency is reported at its one declaration, so
// two dependencies naming a resource alike would share a fingerprint if it were
// computed from where they are reported.
func TestCreateSummary_ReportedFindingsKeepTheirIdentity(t *testing.T) {
	declaration := &ReportedLocation{Path: "/repo/web/Chart.yaml", Line: 5, LineText: "- name: pkg"}
	finding := func(detected string) Vulnerability {
		v := Vulnerability{
			FileName: detected, QueryID: "q", QueryName: "q", Severity: SeverityHigh, Platform: "Kubernetes",
			ResourceType: "Deployment", ResourceName: "dd-helm", LineWithVulnerability: "  privileged: true",
		}
		declaration.Apply(&v)
		return v
	}
	summary := CreateSummary(context.Background(), Counters{}, []Vulnerability{
		finding("/repo/web/charts/pkg/templates/deploy.yaml"),
		finding("/repo/web/charts/cache/templates/deploy.yaml"),
	}, "scan", nil, "/repo", SCIInfo{})

	files := summary.Queries[0].Files
	require.Len(t, files, 2)
	require.Equal(t, filepath.FromSlash("web/Chart.yaml"), files[0].FileName)
	require.Equal(t, filepath.FromSlash("web/Chart.yaml"), files[1].FileName)
	require.NotEqual(t, files[0].Fingerprint, files[1].Fingerprint)
	require.Equal(t, GetDatadogFingerprintHash(SCIInfo{}, filepath.FromSlash("web/charts/pkg/templates/deploy.yaml"),
		"Kubernetes", "Deployment", "dd-helm", "q", "  privileged: true", ""), files[0].Fingerprint,
		"the fingerprint stays the detected file's and line's, so it is the one main computes")
	require.Equal(t, "- name: pkg", files[0].LineWithVulnerability)
}

// TestCreateSummary tests the functions [CreateSummary()] and all the methods called by them
func TestCreateSummary(t *testing.T) {
	vulnerabilities := []Vulnerability{
		{
			ID:        1,
			ScanID:    "scanID",
			FileID:    "fileId",
			FileName:  "fileName",
			QueryID:   "QueryID",
			CWE:       "22",
			QueryName: "query_name",
			Severity:  SeverityHigh,
			Line:      1,
			SearchKey: "searchKey",
		},
	}

	counter := Counters{
		ScannedFiles:           2,
		ParsedFiles:            3,
		FailedToExecuteQueries: 0,
		TotalQueries:           0,
		FailedToScanFiles:      0,
	}

	pathExtractionMap := map[string]ExtractedPathObject{}

	ctx := context.Background()
	t.Run("create_summary_empty", func(t *testing.T) {
		summary := CreateSummary(ctx, counter, []Vulnerability{}, "scanID", pathExtractionMap, "", SCIInfo{})
		require.Equal(t, summary, Summary{
			Counters: counter,
			SeveritySummary: SeveritySummary{
				ScanID: "scanID",
				SeverityCounters: map[Severity]int{
					SeverityTrace:    0,
					SeverityInfo:     0,
					SeverityLow:      0,
					SeverityMedium:   0,
					SeverityHigh:     0,
					SeverityCritical: 0,
				},
			},
			Bom:          []QueryResult{},
			Queries:      []QueryResult{},
			ScannedPaths: []string{},
			FilePaths:    make(map[string]string),
		})
	})

	t.Run("create_summary", func(t *testing.T) {
		filePaths := make(map[string]string)
		filePaths["fileName"] = "fileName"
		summary := CreateSummary(ctx, counter, vulnerabilities, "scanID", pathExtractionMap, "", SCIInfo{})
		require.Equal(t, summary, Summary{
			Counters: counter,
			SeveritySummary: SeveritySummary{
				ScanID: "scanID",
				SeverityCounters: map[Severity]int{
					SeverityTrace:    0,
					SeverityInfo:     0,
					SeverityLow:      0,
					SeverityMedium:   0,
					SeverityHigh:     1,
					SeverityCritical: 0,
				},
				TotalCounter: 1,
			},
			Bom: []QueryResult{},
			Queries: []QueryResult{
				{
					QueryName: "query_name",
					QueryID:   "QueryID",
					Severity:  SeverityHigh,
					CWE:       "22",
					Files: []VulnerableFile{
						{
							FileName:    "fileName",
							Fingerprint: GetDatadogFingerprintHash(SCIInfo{}, "fileName", "", "", "", "QueryID", "", ""),
							Line:        1,
							SearchKey:   "searchKey",
							Value:       nil,
						},
					},
				},
			},
			ScannedPaths: []string{},
			FilePaths:    filePaths,
		})
	})
}

func TestModel_resolvePath(t *testing.T) {
	pwd, err := os.Getwd()
	if err != nil {
		t.Errorf("failed to get working dir: %v", err)
	}

	type args struct {
		filePath          string
		pathExtractionMap map[string]ExtractedPathObject
		downloadDir       string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test_with_query_params_local",
			args: args{
				filePath: filepath.FromSlash("/tmp/file/vuln"),
				pathExtractionMap: map[string]ExtractedPathObject{
					filepath.FromSlash("/tmp"): {
						Path:      filepath.FromSlash("https//test/relativepath/testing?paramKey=paramVal"),
						LocalPath: false,
					},
				},
				downloadDir: "/tmp",
			},
			want: filepath.FromSlash("https//test/relativepath/testing/file/vuln"),
		},
		{
			name: "test_with_query_mult_params_local",
			args: args{
				filePath: filepath.FromSlash("/tmp/file/vuln"),
				pathExtractionMap: map[string]ExtractedPathObject{
					filepath.FromSlash("/tmp"): {
						Path:      filepath.FromSlash("https//test/relativepath/testing?paramKey=paramVal&paramKey2=paramVal2"),
						LocalPath: false,
					},
				},
				downloadDir: "/tmp",
			},
			want: filepath.FromSlash("https//test/relativepath/testing/file/vuln"),
		},
		{
			name: "test_with_query_local",
			args: args{
				filePath: filepath.Join(pwd, filepath.FromSlash("assets/queries/dockerfile/image_version_not_explicit/test/negative.dockerfile")),
				pathExtractionMap: map[string]ExtractedPathObject{
					filepath.FromSlash("/tmp"): {
						Path:      filepath.Join(pwd, filepath.FromSlash("/assets/queries/dockerfile")),
						LocalPath: true,
					},
				},
				downloadDir: pwd,
			},
			want: filepath.FromSlash("assets/queries/dockerfile/image_version_not_explicit/test/negative.dockerfile"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolvePath(tt.args.filePath, tt.args.pathExtractionMap, tt.args.downloadDir)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestResolvePathForRemoteModuleFiles(t *testing.T) {
	modules := map[string]ExtractedPathObject{
		filepath.FromSlash("/cache/pkg"): {
			Path: "git::https://github.com/org/repo?ref=0.12.4-rc.1",
		},
		filepath.FromSlash("/cache/pkg/azure"): {
			Path: "git::https://github.com/org/repo//azure?ref=0.12.4-rc.1",
		},
		filepath.FromSlash("/cache/pk"): {
			Path: "git::https://github.com/org/other?ref=v1",
		},
	}
	tests := []struct {
		name, file, want string
	}{
		{
			name: "the most specific module directory names the file",
			file: "/cache/pkg/azure/modules/vnet/main.tf",
			want: "git::https://github.com/org/repo//azure/modules/vnet/main.tf",
		},
		{
			name: "a ref with dots is removed whole",
			file: "/cache/pkg/main.tf",
			want: "git::https://github.com/org/repo/main.tf",
		},
		{
			name: "a directory is not matched by a sibling sharing its prefix",
			file: "/cache/pkgs/main.tf",
			want: "/cache/pkgs/main.tf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for range 200 {
				require.Equal(t, filepath.FromSlash(tt.want), replaceIfTemporaryPath(filepath.FromSlash(tt.file), modules),
					"the same file must always get the same name")
			}
		})
	}
}

func TestRemoveURLCredentials(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test_with_url_credentials",
			args: args{
				url: "https://user:password@test.git.com/test.git",
			},
			want: "https://test.git.com/test.git",
		},
		{
			name: "test_with_url_no_credentials",
			args: args{
				url: "https://test.git.com/test.git",
			},
			want: "https://test.git.com/test.git",
		},
		{
			name: "test_http_with_url_credentials",
			args: args{
				url: "http://test:password@test.git.com/test",
			},
			want: "http://test.git.com/test",
		},
		{
			name: "test_https_with_url_token",
			args: args{
				url: "https://myTOken123a12e@test.git.com:8080/test",
			},
			want: "https://test.git.com:8080/test",
		},
		{
			name: "test_redacts_credentials_in_error_message",
			args: args{
				url: "clone failed for git::https://user:secret@example.com/repo.git",
			},
			want: "clone failed for git::https://example.com/repo.git",
		},
		{
			name: "test_ssh_with_url_credentials",
			args: args{
				url: "ssh://git:secret@test.git.com/test.git",
			},
			want: "ssh://test.git.com/test.git",
		},
		{
			// The failure mode that motivated redacting logged errors: the
			// Ansible INI parser quotes the offending line of the scanned file.
			name: "test_postgres_credentials_in_parse_error",
			args: args{
				url: "bad key=value pair supplied: postgres://user:pass@localhost:5432/dogdata",
			},
			want: "bad key=value pair supplied: postgres://localhost:5432/dogdata",
		},
		{
			name: "test_postgresql_with_url_credentials",
			args: args{
				url: "postgresql://user:pass@db.internal:5432/app?sslmode=require",
			},
			want: "postgresql://db.internal:5432/app?sslmode=require",
		},
		{
			name: "test_mysql_with_url_credentials",
			args: args{
				url: "mysql://root:hunter2@127.0.0.1:3306/app",
			},
			want: "mysql://127.0.0.1:3306/app",
		},
		{
			name: "test_mongodb_with_url_credentials",
			args: args{
				url: "mongodb://admin:secret@mongo:27017/admin",
			},
			want: "mongodb://mongo:27017/admin",
		},
		{
			name: "test_mongodb_srv_with_url_credentials",
			args: args{
				url: "mongodb+srv://admin:secret@cluster0.example.mongodb.net/db",
			},
			want: "mongodb+srv://cluster0.example.mongodb.net/db",
		},
		{
			name: "test_redis_with_url_credentials",
			args: args{
				url: "redis://:secret@redis:6379/0",
			},
			want: "redis://redis:6379/0",
		},
		{
			name: "test_rediss_with_url_credentials",
			args: args{
				url: "rediss://user:secret@redis:6380/0",
			},
			want: "rediss://redis:6380/0",
		},
		{
			name: "test_amqp_with_url_credentials",
			args: args{
				url: "amqp://guest:guest@rabbit:5672/vhost",
			},
			want: "amqp://rabbit:5672/vhost",
		},
		{
			name: "test_amqps_with_url_credentials",
			args: args{
				url: "amqps://guest:guest@rabbit:5671/vhost",
			},
			want: "amqps://rabbit:5671/vhost",
		},
		{
			name: "test_scheme_matching_is_case_insensitive",
			args: args{
				url: "Postgres://user:pass@localhost:5432/dogdata",
			},
			want: "Postgres://localhost:5432/dogdata",
		},
		// A driver-qualified scheme puts `+driver` before `://`, which no
		// enumeration of bare scheme names can match. These are the canonical
		// SQLAlchemy/JDBC spellings and are exactly what a .ini or .env holds.
		{
			name: "test_driver_qualified_postgres_scheme",
			args: args{
				url: "postgresql+psycopg2://user:secret@db/app",
			},
			want: "postgresql+psycopg2://db/app",
		},
		{
			name: "test_driver_qualified_mysql_scheme",
			args: args{
				url: "mysql+pymysql://user:secret@db/app",
			},
			want: "mysql+pymysql://db/app",
		},
		{
			name: "test_jdbc_prefixed_scheme",
			args: args{
				url: "jdbc:postgresql://user:secret@db:5432/app",
			},
			want: "jdbc:postgresql://db:5432/app",
		},
		// Schemes nobody enumerated: userinfo is a credential whatever the
		// scheme, so redaction must not depend on a curated list.
		{
			name: "test_unenumerated_scheme",
			args: args{
				url: "clickhouse://user:secret@ch:9000/default",
			},
			want: "clickhouse://ch:9000/default",
		},
		{
			name: "test_unenumerated_scheme_with_query",
			args: args{
				url: "sqlserver://sa:secret@mssql:1433?database=app",
			},
			want: "sqlserver://mssql:1433?database=app",
		},
		{
			name: "test_multiple_urls_in_one_message",
			args: args{
				url: "failed: postgres://u:p@db:5432/x and redis://u:p@cache:6379",
			},
			want: "failed: postgres://db:5432/x and redis://cache:6379",
		},
		{
			name: "test_database_url_without_credentials_untouched",
			args: args{
				url: "postgres://localhost:5432/dogdata",
			},
			want: "postgres://localhost:5432/dogdata",
		},
		{
			name: "test_unrelated_text_untouched",
			args: args{
				url: "bad key=value pair supplied: user:pass@localhost",
			},
			want: "bad key=value pair supplied: user:pass@localhost",
		},
		// An `@` past the authority is not userinfo. Matching userinfo as
		// `\S+@` would swallow host and path up to the last `@` on the line
		// and corrupt these credential-free values.
		{
			name: "test_at_in_path_is_not_userinfo",
			args: args{
				url: "postgres://db.internal/app@tenant",
			},
			want: "postgres://db.internal/app@tenant",
		},
		{
			name: "test_git_ref_suffix_is_not_userinfo",
			args: args{
				url: "https://github.com/org/repo.git@main",
			},
			want: "https://github.com/org/repo.git@main",
		},
		{
			name: "test_at_in_query_is_not_userinfo",
			args: args{
				url: "postgres://db:5432/app?user=a@b",
			},
			want: "postgres://db:5432/app?user=a@b",
		},
		{
			name: "test_trailing_email_after_url_untouched",
			args: args{
				url: "see https://docs.example.com/x then mail admin@corp.com",
			},
			want: "see https://docs.example.com/x then mail admin@corp.com",
		},
		{
			// Authority with no path, so nothing bounds the scan but
			// whitespace: the email must still survive.
			name: "test_bare_authority_then_email_untouched",
			args: args{
				url: "redis://cache and admin@corp.com",
			},
			want: "redis://cache and admin@corp.com",
		},
		{
			// Malformed authority: redact through the last `@` of the
			// authority. Over-redacting is the safe direction.
			name: "test_multiple_at_in_authority_over_redacts",
			args: args{
				url: "postgres://a@b@c/d",
			},
			want: "postgres://c/d",
		},
		{
			name: "test_empty_string",
			args: args{
				url: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, removeURLCredentials(tt.args.url))
		})
	}
}

// TestRedactCredentials covers the credentials parser error messages quote
// from scanned files. Token-shaped inputs are assembled at run time so that
// no credential-looking literal lives in the repository.
func TestRedactCredentials(t *testing.T) {
	jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ed25519-nkey"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"fixture","nats":{"type":"operator"}}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("not-a-signature"))
	dockerConfig := base64.StdEncoding.EncodeToString([]byte(`{"auths":{"registry.example.com":{"auth":"dXNlcjpwYXNz"}}}`))

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			// The line the Ansible config parser quoted from a NATS server config.
			name: "jwt_in_quoted_line",
			in:   "missing section header: 2 operator: " + jwt,
			want: "missing section header: 2 operator: [REDACTED]",
		},
		{
			name: "jwt_in_backquotes",
			in:   "cannot unmarshal !!str `" + jwt + "` into map[string]interface {}",
			want: "cannot unmarshal !!str `[REDACTED]` into map[string]interface {}",
		},
		{
			name: "base64_json",
			in:   "invalid value: .dockerconfigjson: " + dockerConfig,
			want: "invalid value: .dockerconfigjson: [REDACTED]",
		},
		{
			name: "ini_password",
			in:   "missing section header: 1 db_password = hunter2",
			want: "missing section header: 1 db_password = [REDACTED]",
		},
		{
			name: "json_quoted_value_with_spaces",
			in:   `{"client_secret": "a b c", "user": "bob"}`,
			want: `{"client_secret": [REDACTED], "user": "bob"}`,
		},
		{
			name: "truncated_quoted_value",
			in:   `password: "hunter 2`,
			want: `password: [REDACTED]`,
		},
		{
			name: "env_assignment",
			in:   "bad line: AWS_SECRET_ACCESS_KEY=" + strings.Repeat("x", 40),
			want: "bad line: AWS_SECRET_ACCESS_KEY=[REDACTED]",
		},
		{
			name: "camel_case_key",
			in:   "apiKey: abc123 and accessToken:abc123",
			want: "apiKey: [REDACTED] and accessToken:[REDACTED]",
		},
		{
			name: "dotted_key",
			in:   "spring.datasource.password=s3cr3t",
			want: "spring.datasource.password=[REDACTED]",
		},
		{
			name: "authorization_bearer",
			in:   "Authorization: Bearer " + strings.Repeat("t", 24),
			want: "Authorization: Bearer [REDACTED]",
		},
		{
			name: "authorization_basic",
			in:   "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("user:password")),
			want: "Authorization: Basic [REDACTED]",
		},
		{
			name: "bearer_without_key",
			in:   `header "Bearer ` + strings.Repeat("t", 24) + `" not allowed`,
			want: `header "Bearer [REDACTED]" not allowed`,
		},
		{
			name: "pem_private_key_block",
			in:   "bad value: -----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY----- here",
			want: "bad value: [REDACTED] here",
		},
		{
			name: "truncated_pem_private_key_block",
			in:   "missing section header: 1 -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk",
			want: "missing section header: 1 [REDACTED]",
		},
		{
			name: "nats_seed_block",
			in:   "creds: -----BEGIN USER NKEY SEED-----\nseed\n-----END USER NKEY SEED-----\nend",
			want: "creds: [REDACTED]\nend",
		},
		{
			name: "aws_access_key_id",
			in:   "unknown field: AKIA" + strings.Repeat("Q", 16),
			want: "unknown field: [REDACTED]",
		},
		{
			name: "source_control_and_chat_tokens",
			in: "ghp_" + strings.Repeat("a", 36) + " github_pat_" + strings.Repeat("b", 22) +
				" glpat-" + strings.Repeat("c", 20) + " xoxb-" + strings.Repeat("1", 12),
			want: "[REDACTED] [REDACTED] [REDACTED] [REDACTED]",
		},
		{
			name: "google_api_key",
			in:   "key AIza" + strings.Repeat("d", 35),
			want: "key [REDACTED]",
		},
		{
			name: "nats_seed",
			in:   "seed SU" + strings.Repeat("A", 56),
			want: "seed [REDACTED]",
		},
		{
			name: "url_userinfo_and_query_token",
			in:   "bad key=value pair supplied: postgres://u:p@localhost:5432/dogdata?token=abc",
			want: "bad key=value pair supplied: postgres://localhost:5432/dogdata?token=[REDACTED]",
		},
		// Messages without credentials must survive intact for triage.
		{
			name: "yaml_syntax_error_untouched",
			in:   "yaml: line 3: did not find expected key",
			want: "yaml: line 3: did not find expected key",
		},
		{
			name: "helm_error_on_secret_template_untouched",
			in: `template: chart/templates/secret.yaml:12:3: executing "chart/templates/secret.yaml" ` +
				`at <.Values.token>: nil pointer evaluating interface {}.token`,
			want: `template: chart/templates/secret.yaml:12:3: executing "chart/templates/secret.yaml" ` +
				`at <.Values.token>: nil pointer evaluating interface {}.token`,
		},
		{
			name: "hcl_argument_name_untouched",
			in:   `Unsupported argument; An argument named "password" is not expected here.`,
			want: `Unsupported argument; An argument named "password" is not expected here.`,
		},
		{
			name: "antlr_token_error_untouched",
			in:   "token recognition error at: '$'",
			want: "token recognition error at: '$'",
		},
		{
			name: "commit_sha_untouched",
			in:   "ref 0123456789abcdef0123456789abcdef01234567 not found",
			want: "ref 0123456789abcdef0123456789abcdef01234567 not found",
		},
		{
			name: "empty_string",
			in:   "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, RedactCredentials(tt.in))
		})
	}
}

// TestSummary_WithoutSuppressed verifies that the filtered copy used by
// non-SARIF reports drops every suppressed VulnerableFile, prunes queries that
// become empty, and leaves the original Summary untouched so SARIF reporting
// can still surface them under `suppressions[]`.
func TestSummary_WithoutSuppressed(t *testing.T) {
	original := &Summary{
		Queries: QueryResultSlice{
			{
				QueryID: "mixed",
				Files: []VulnerableFile{
					{FileName: "active.tf", Line: 10},
					{FileName: "suppressed.tf", Line: 20, IsSuppressed: true},
				},
			},
			{
				QueryID: "all-suppressed",
				Files: []VulnerableFile{
					{FileName: "suppressed.tf", Line: 30, IsSuppressed: true},
				},
			},
			{
				QueryID: "all-active",
				Files: []VulnerableFile{
					{FileName: "active.tf", Line: 40},
				},
			},
		},
		Bom: QueryResultSlice{
			{
				QueryID: "bom",
				Files: []VulnerableFile{
					{FileName: "bom-active.tf", Line: 1},
					{FileName: "bom-suppressed.tf", Line: 2, IsSuppressed: true},
				},
			},
		},
	}

	filtered := original.WithoutSuppressed()

	require.Len(t, filtered.Queries, 2)
	require.Equal(t, "mixed", filtered.Queries[0].QueryID)
	require.Len(t, filtered.Queries[0].Files, 1)
	require.Equal(t, "active.tf", filtered.Queries[0].Files[0].FileName)
	require.Equal(t, "all-active", filtered.Queries[1].QueryID)

	require.Len(t, filtered.Bom, 1)
	require.Len(t, filtered.Bom[0].Files, 1)
	require.Equal(t, "bom-active.tf", filtered.Bom[0].Files[0].FileName)

	// Original is untouched so SARIF can still emit suppressions.
	require.Len(t, original.Queries, 3)
	require.Len(t, original.Queries[0].Files, 2)
	require.True(t, original.Queries[0].Files[1].IsSuppressed)
	require.Len(t, original.Bom[0].Files, 2)
}

func TestRemoveAllURLCredentials(t *testing.T) {
	input := []struct {
		pathExtractionMap map[string]ExtractedPathObject
		want              map[string]string
	}{
		{
			pathExtractionMap: map[string]ExtractedPathObject{
				"/tmp/file/vuln": {
					Path:      "https://user:password@git1.url.com/test.git",
					LocalPath: false,
				},
				"/tmp/file/vuln2": {
					Path:      "https://myToken123@my2.domain/test.git",
					LocalPath: false,
				},
			},
			want: map[string]string{
				"/tmp/file/vuln":  "https://git1.url.com/test.git",
				"/tmp/file/vuln2": "https://my2.domain/test.git",
			},
		},
		{
			pathExtractionMap: map[string]ExtractedPathObject{
				"/tmp/file/vuln": {
					Path:      "/user/archive.zip",
					LocalPath: true,
				},
			},
			want: map[string]string{
				"/tmp/file/vuln": "/user/archive.zip",
			},
		},
	}
	for _, tt := range input {
		got := removeAllURLCredentials(tt.pathExtractionMap)
		for key := range tt.pathExtractionMap {
			require.Contains(t, got, tt.want[key])
		}
	}
}
