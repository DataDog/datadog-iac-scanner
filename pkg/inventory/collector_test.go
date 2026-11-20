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

	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"

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

	c = NewCollector(t.TempDir())
	c.RecordFile("main.tf", "terraform", FileScanned, "")
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

func TestBuildIsFinal(t *testing.T) {
	c := NewCollector(t.TempDir())
	for _, row := range []struct {
		line     int
		document string
	}{{1, "first"}, {8, "second"}} {
		c.AddResource(&Resource{ResourcePath: "v1/ConfigMap//cm", Platform: platforms.Kubernetes, ResourceType: "ConfigMap",
			ResourceName: "cm", File: "k8s/dup.yaml", LineStart: row.line, Completeness: CompletenessComplete,
			DocumentID: row.document, ownsDocument: true})
	}
	// Kept with the second document, raised at the first one's line.
	c.AddFinding(&Finding{Fingerprint: "kept-once", DocumentID: "second", Line: 1})

	first := c.Build(testMetadata())
	require.Equal(t, []FindingLink{{FindingFingerprint: "kept-once", ResourceRef: "k8s/dup.yaml|v1/ConfigMap//cm"}}, first.FindingLinks)

	c.AddResource(&Resource{ResourcePath: "v1/Secret//late", Platform: platforms.Kubernetes, File: "k8s/late.yaml",
		LineStart: 1, Completeness: CompletenessComplete})
	again := c.Build(testMetadata())
	require.Equal(t, []FindingLink{{FindingFingerprint: "kept-once", ResourceRef: "k8s/dup.yaml|v1/ConfigMap//cm"}}, again.FindingLinks,
		"building again does not move the link")
	require.Same(t, first, again, "a collector builds once")
	require.Len(t, again.Resources, 2, "a row added after Build is not in the inventory")
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
	c.AddFinding(&Finding{Fingerprint: "f2", File: "main.tf", BlockStart: 1})
	c.AddFinding(&Finding{Fingerprint: "f1", File: "main.tf", BlockStart: 9})
	c.AddFinding(&Finding{Fingerprint: "f1", File: "main.tf", BlockStart: 9})
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

func TestBuildMakesReferencesUnique(t *testing.T) {
	row := func(line, documentIndex int, document string) *Resource {
		return &Resource{ResourcePath: "v1/ConfigMap//cm", Platform: "kubernetes", ResourceType: "ConfigMap",
			ResourceName: "cm", File: "k8s/dup.yaml", LineStart: line, Completeness: CompletenessComplete,
			DocumentID: document, documentIndex: documentIndex, ownsDocument: true}
	}
	c := NewCollector(t.TempDir())
	c.AddResource(row(8, 1, "second"))
	c.AddResource(row(15, 2, "third"))
	c.AddResource(row(1, 0, "first"))
	// A reference that already ends like a suffix is not reused.
	taken := row(20, 3, "taken")
	taken.ResourceRef = "k8s/dup.yaml|v1/ConfigMap//cm#2"
	c.AddResource(taken)
	// Rows equal but for their document keep the order of the documents.
	c.AddResource(&Resource{ResourcePath: "v1/ConfigMap//same", Platform: "kubernetes", ResourceType: "ConfigMap",
		ResourceName: "same", File: "chart/templates/cm.yaml", LineStart: 1, Completeness: CompletenessComplete,
		DocumentID: "loop-1", documentIndex: 1, ownsDocument: true})
	c.AddResource(&Resource{ResourcePath: "v1/ConfigMap//same", Platform: "kubernetes", ResourceType: "ConfigMap",
		ResourceName: "same", File: "chart/templates/cm.yaml", LineStart: 1, Completeness: CompletenessComplete,
		DocumentID: "loop-0", documentIndex: 0, ownsDocument: true})
	for document, line := range map[string]int{"first": 1, "second": 8, "third": 15, "taken": 20, "loop-0": 1, "loop-1": 1} {
		c.AddFinding(&Finding{Fingerprint: document, DocumentID: document, Line: line})
	}
	// The scan raised one finding on every document and kept it with the
	// third: it belongs to the row holding its line.
	c.AddFinding(&Finding{Fingerprint: "kept-once", DocumentID: "third", Line: 1})
	// No row holds it: the first.
	c.AddFinding(&Finding{Fingerprint: "no-line", DocumentID: "second"})

	inv := c.Build(testMetadata())

	var refs []string
	for i := range inv.Resources {
		refs = append(refs, inv.Resources[i].ResourceRef)
	}
	require.Equal(t, []string{
		"chart/templates/cm.yaml|v1/ConfigMap//same",
		"chart/templates/cm.yaml|v1/ConfigMap//same#2",
		"k8s/dup.yaml|v1/ConfigMap//cm",
		"k8s/dup.yaml|v1/ConfigMap//cm#3",
		"k8s/dup.yaml|v1/ConfigMap//cm#4",
		"k8s/dup.yaml|v1/ConfigMap//cm#2",
	}, refs)
	require.Equal(t, []FindingLink{
		{FindingFingerprint: "first", ResourceRef: "k8s/dup.yaml|v1/ConfigMap//cm"},
		{FindingFingerprint: "kept-once", ResourceRef: "k8s/dup.yaml|v1/ConfigMap//cm"},
		// Rows with the same lines cannot be told apart: the first.
		{FindingFingerprint: "loop-0", ResourceRef: "chart/templates/cm.yaml|v1/ConfigMap//same"},
		{FindingFingerprint: "loop-1", ResourceRef: "chart/templates/cm.yaml|v1/ConfigMap//same"},
		{FindingFingerprint: "no-line", ResourceRef: "k8s/dup.yaml|v1/ConfigMap//cm"},
		{FindingFingerprint: "second", ResourceRef: "k8s/dup.yaml|v1/ConfigMap//cm#3"},
		{FindingFingerprint: "taken", ResourceRef: "k8s/dup.yaml|v1/ConfigMap//cm#2"},
		{FindingFingerprint: "third", ResourceRef: "k8s/dup.yaml|v1/ConfigMap//cm#4"},
	}, inv.FindingLinks, "a finding links to the repeated row holding its line, whichever document the scan kept")
	requireValid(t, inv)
	require.Equal(t, refs[2:], func() []string {
		var again []string
		for _, r := range c.Build(testMetadata()).Resources {
			again = append(again, r.ResourceRef)
		}
		return again[2:]
	}(), "building again keeps the references")
}
