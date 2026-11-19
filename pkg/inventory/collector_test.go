/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
)

func testMetadata() *Metadata {
	return &Metadata{
		ScanID:           "scan",
		ScannerVersion:   "development",
		ScannedAt:        time.Date(2026, 11, 19, 10, 0, 0, 0, time.FixedZone("CET", 3600)),
		Repository:       Repository{URL: "https://example.invalid/repo.git", CommitSHA: "abc", Branch: "main"},
		PlatformsScanned: []string{"terraform", "kubernetes", "terraform"},
	}
}

// requireValid checks inv against the published schema.
func requireValid(t *testing.T, inv *Inventory) {
	t.Helper()
	doc, err := json.Marshal(inv)
	require.NoError(t, err)
	result, err := gojsonschema.Validate(gojsonschema.NewBytesLoader(Schema), gojsonschema.NewBytesLoader(doc))
	require.NoError(t, err)
	require.Truef(t, result.Valid(), "schema errors: %v", result.Errors())
}

func TestBuildEmpty(t *testing.T) {
	inv := NewCollector(t.TempDir()).Build(testMetadata())

	require.Equal(t, SchemaVersion, inv.SchemaVersion)
	require.Equal(t, StatusComplete, inv.Status)
	require.Equal(t, time.UTC, inv.ScannedAt.Location())
	require.Equal(t, []string{"kubernetes", "terraform"}, inv.PlatformsScanned)
	requireValid(t, inv)

	doc, err := json.Marshal(inv)
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(doc, &raw))
	for _, key := range []string{"files", "unresolved_sources", "resources", "finding_links"} {
		require.Equalf(t, []any{}, raw[key], "%s must be an empty list, not null", key)
	}
}

func TestRecordFileMergesAttempts(t *testing.T) {
	tests := []struct {
		name     string
		attempts [][3]string // platform, status, reason
		want     File
	}{
		{
			name:     "one success wins over failures",
			attempts: [][3]string{{"kubernetes", FileFailed, "parse_error"}, {"kubernetes", FileScanned, ""}},
			want:     File{Path: "a.yaml", Platform: "kubernetes", Status: FileScanned},
		},
		{
			name:     "failures keep the first reason in sort order",
			attempts: [][3]string{{"", FileFailed, "parse_error"}, {"", FileFailed, "no_documents"}},
			want:     File{Path: "a.yaml", Status: FileFailed, Reason: "no_documents"},
		},
		{
			name:     "a known platform replaces an unknown one",
			attempts: [][3]string{{"", FileFailed, "parse_error"}, {"dockercompose", FileFailed, "parse_error"}},
			want:     File{Path: "a.yaml", Platform: "dockercompose", Status: FileFailed, Reason: "parse_error"},
		},
		{
			name:     "a scanned file has no reason",
			attempts: [][3]string{{"kubernetes", FileScanned, "ignored"}},
			want:     File{Path: "a.yaml", Platform: "kubernetes", Status: FileScanned},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Both orders give the same outcome.
			for _, reversed := range []bool{false, true} {
				c := NewCollector(t.TempDir())
				for i := range tt.attempts {
					a := tt.attempts[i]
					if reversed {
						a = tt.attempts[len(tt.attempts)-1-i]
					}
					c.RecordFile("a.yaml", a[0], a[1], a[2])
				}
				inv := c.Build(testMetadata())
				require.Equal(t, []File{tt.want}, inv.Files)
			}
		})
	}
}

func TestBuildStatus(t *testing.T) {
	c := NewCollector(t.TempDir())
	c.RecordFile("main.tf", "terraform", FileScanned, "")
	require.Equal(t, StatusComplete, c.Build(testMetadata()).Status)

	c.AddUnresolvedSource(UnresolvedSource{Platform: "terraform", Source: "git::https://example.invalid/m.git", Reason: "git_repo_not_found"})
	inv := c.Build(testMetadata())
	require.Equal(t, StatusPartial, inv.Status)
	require.Zero(t, inv.Stats.FilesFailed)

	c = NewCollector(t.TempDir())
	c.RecordFile("broken.yaml", "", FileFailed, "parse_error")
	inv = c.Build(testMetadata())
	require.Equal(t, StatusPartial, inv.Status)
	require.Equal(t, 1, inv.Stats.FilesFailed)
}

func TestBuildIsSortedAndDeduplicated(t *testing.T) {
	c := NewCollector(t.TempDir())
	rows := []Resource{
		{ResourceRef: "b.yaml|v1/Service//web", ResourcePath: "v1/Service//web", Platform: "kubernetes",
			ResourceType: "Service", ResourceName: "web", File: "b.yaml", LineStart: 1, Completeness: CompletenessComplete},
		{ResourceRef: ".|aws_s3_bucket.b", ResourcePath: "aws_s3_bucket.b", Platform: "terraform",
			ResourceType: "aws_s3_bucket", ResourceName: "b", File: "main.tf", LineStart: 9, Completeness: CompletenessComplete},
		{ResourceRef: ".|aws_s3_bucket.a", ResourcePath: "aws_s3_bucket.a", Platform: "terraform",
			ResourceType: "aws_s3_bucket", ResourceName: "a", File: "main.tf", LineStart: 1, Completeness: CompletenessComplete},
	}
	for i := range rows {
		c.AddResource(&rows[i])
	}
	c.AddFindingLink(FindingLink{FindingFingerprint: "f2", ResourceRef: ".|aws_s3_bucket.a"})
	c.AddFindingLink(FindingLink{FindingFingerprint: "f1", ResourceRef: ".|aws_s3_bucket.b"})
	c.AddFindingLink(FindingLink{FindingFingerprint: "f1", ResourceRef: ".|aws_s3_bucket.b"})
	c.AddUnresolvedSource(UnresolvedSource{Platform: "terraform", Source: "s", Reason: "timeout"})
	c.AddUnresolvedSource(UnresolvedSource{Platform: "terraform", Source: "s", Reason: "timeout"})
	c.AddFindingsUnlinked(2)
	c.AddFindingsUnlinked(1)

	inv := c.Build(testMetadata())

	// By file, then by line.
	require.Equal(t, []string{"b.yaml|v1/Service//web", ".|aws_s3_bucket.a", ".|aws_s3_bucket.b"},
		[]string{inv.Resources[0].ResourceRef, inv.Resources[1].ResourceRef, inv.Resources[2].ResourceRef})
	require.Equal(t, []FindingLink{
		{FindingFingerprint: "f1", ResourceRef: ".|aws_s3_bucket.b"},
		{FindingFingerprint: "f2", ResourceRef: ".|aws_s3_bucket.a"},
	}, inv.FindingLinks)
	require.Len(t, inv.UnresolvedSources, 1)
	require.Equal(t, Stats{Resources: 3, FindingsUnlinked: 3}, inv.Stats)
	requireValid(t, inv)
}

func TestRelPath(t *testing.T) {
	root := t.TempDir()
	c := NewCollector(root)

	rel, ok := c.RelPath(filepath.Join(root, "envs", "prod", "main.tf"))
	require.True(t, ok)
	require.Equal(t, "envs/prod/main.tf", rel)

	rel, ok = c.RelPath(filepath.Join("charts", "api", "values.yaml"))
	require.True(t, ok)
	require.Equal(t, "charts/api/values.yaml", rel)

	rel, ok = c.RelPath(root)
	require.True(t, ok)
	require.Equal(t, ".", rel)

	_, ok = c.RelPath(filepath.Join(filepath.Dir(root), "elsewhere", "main.tf"))
	require.False(t, ok)
}

func TestRelPathThroughSymlinkedRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	real := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(real, "k8s"), 0o755))
	file := filepath.Join(real, "k8s", "web.yaml")
	require.NoError(t, os.WriteFile(file, []byte("kind: Service\n"), 0o600))
	alias := filepath.Join(t.TempDir(), "alias")
	require.NoError(t, os.Symlink(real, alias))

	// The root was found through the symlink, the file was not.
	rel, ok := NewCollector(alias).RelPath(file)
	require.True(t, ok)
	require.Equal(t, "k8s/web.yaml", rel)

	// And the reverse.
	rel, ok = NewCollector(real).RelPath(filepath.Join(alias, "k8s", "web.yaml"))
	require.True(t, ok)
	require.Equal(t, "k8s/web.yaml", rel)
}

func TestSchemaAcceptsAFullRow(t *testing.T) {
	c := NewCollector(t.TempDir())
	c.RecordFile("infra/main.tf", "terraform", FileScanned, "")
	c.RecordFile("k8s/worker.yaml", "", FileFailed, "parse_error")
	c.AddResource(&Resource{
		ResourceRef:          `infra|module.logging["prod"].aws_s3_bucket.this`,
		ResourcePath:         `module.logging["prod"].aws_s3_bucket.this`,
		Platform:             "terraform",
		ResourceType:         "aws_s3_bucket",
		ResourceName:         "this",
		Provider:             "aws",
		File:                 "infra/modules/logging/main.tf",
		LineStart:            5,
		LineEnd:              7,
		ColumnStart:          1,
		ColumnEnd:            2,
		ModuleCall:           `module.logging["prod"]`,
		ModuleSource:         "infra/modules/logging",
		ModuleSourceType:     "local",
		ModuleDependencyType: "direct",
		CallSiteFile:         "infra/main.tf",
		CallSiteLineStart:    16,
		CallSiteLineEnd:      20,
		ModulePath:           `[{"name":"logging","source":"infra/modules/logging","source_type":"local"}]`,
		Completeness:         CompletenessComplete,
	})
	c.AddResource(&Resource{
		ResourceRef:        "charts/api/templates/deployment.yaml|apps/v1/Deployment//dd-helm-api",
		ResourcePath:       "apps/v1/Deployment//dd-helm-api",
		Platform:           "kubernetes",
		ResourceType:       "Deployment",
		ResourceName:       "dd-helm-api",
		File:               "charts/api/templates/deployment.yaml",
		LineStart:          1,
		Completeness:       CompletenessComplete,
		OriginGenerator:    "helm",
		OriginChartPath:    "charts/api",
		OriginChartName:    "api",
		OriginChartVersion: "0.1.0",
		OriginTemplate:     "templates/deployment.yaml",
	})
	requireValid(t, c.Build(testMetadata()))
}
