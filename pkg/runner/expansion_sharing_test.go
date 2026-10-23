/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package runner

import (
	"context"
	"reflect"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

// sanitizeScanDocumentInPlace strips _dd_lines and resolves JSON filters in
// place, avoiding prepareScanDocument's JSON round-trip deep copy (the dominant
// heap/CPU cost). Shared children must belong to this file; lazy line info
// is reparsed independently.
// Cycles are rejected with errCyclicDocument, as json.Marshal would.
func sanitizeScanDocumentInPlace(body map[string]interface{}, kind model.FileKind) (map[string]interface{}, error) {
	sanitizer := newScanDocumentSanitizer(kind)
	return sanitizer.sanitize(body)
}

func TestSinkExpandedDocumentsPreserveSharing(t *testing.T) {
	for _, ext := range []string{"tf", "tf.json"} {
		t.Run(ext, func(t *testing.T) {
			ctx := context.Background()
			path := "main." + ext
			source := expandedBenchmarkConfig(t, ext, 4)
			fsys := vfs.NewMemFS(map[string][]byte{path: source})
			parsers, err := parser.NewBuilder(ctx).WithFS(fsys).
				Add(terraformParser.NewDefaultWithParams(fsys, "", model.SCIInfo{})).Build([]string{"terraform"}, []string{""})
			require.NoError(t, err)
			p := parsers[0]
			parsed, err := p.Parse(ctx, path, source, false, false, 15)
			require.NoError(t, err)
			require.Len(t, parsed.Docs, 4)
			expected := make([]map[string]interface{}, len(parsed.Docs))
			for i, doc := range parsed.Docs {
				expected[i], err = prepareScanDocument(doc, parsed.Kind)
				require.NoError(t, err)
			}
			svc := &Service{Parser: p, Tracker: noopTracker{}, Storage: nopLineInfoStorage{}, Platforms: []string{"terraform"}}
			require.NoError(t, svc.sinkContent(ctx, path, "scan", &Content{Content: &source}, nil, false, 15))
			require.Len(t, svc.files, len(expected))
			for i, file := range svc.files {
				require.Equal(t, expected[i], map[string]interface{}(file.Document), "complete rule input, layer %d", i)
				require.Equal(t, i, file.ExpansionLayer)
			}
			block := func(file *model.FileMetadata, name string) map[string]interface{} {
				return file.Document["resource"].(map[string]interface{})["aws_s3_bucket"].(map[string]interface{})[name].(map[string]interface{})
			}
			for _, file := range svc.files[1:] {
				require.Equal(t, reflect.ValueOf(block(svc.files[0], "static0")).Pointer(), reflect.ValueOf(block(file, "static0")).Pointer())
				require.NotEqual(t, reflect.ValueOf(block(svc.files[0], "expanded")).Pointer(), reflect.ValueOf(block(file, "expanded")).Pointer())
			}
			// Per-layer bookkeeping must remain isolated despite shared children.
			svc.files.Combine(ctx, false)
			for _, file := range svc.files {
				require.Equal(t, file.ID, file.Document["id"])
				// Lazy evidence trees are reparsed independently of sanitized payloads.
				require.NoError(t, file.EnsureLineInfoDocument(ctx))
				require.Contains(t, file.LineInfoDocument, "_dd_lines")
				require.NotContains(t, file.Document, "_dd_lines")
				require.NotEqual(t, reflect.ValueOf(file.Document).Pointer(), reflect.ValueOf(file.LineInfoDocument).Pointer())
				asMap := func(value interface{}) map[string]interface{} {
					if doc, ok := value.(model.Document); ok {
						return doc
					}
					return value.(map[string]interface{})
				}
				resources := asMap(file.LineInfoDocument["resource"])
				buckets := asMap(resources["aws_s3_bucket"])
				asMap(buckets["static0"])["acl"] = "line-info-only"
				for _, other := range svc.files {
					require.Equal(t, "public-read", block(other, "static0")["acl"], "evidence mutation must not reach a shared scan block")
				}
			}
		})
	}
}

func TestSanitizeNamedDocumentCycle(t *testing.T) {
	doc := model.Document{}
	doc["self"] = doc
	_, err := sanitizeScanDocumentInPlace(doc, model.KindTerraform)
	require.ErrorIs(t, err, errCyclicDocument)
}

func TestSanitizeSharedNamedDocuments(t *testing.T) {
	shared := model.Document{
		"count":     2,
		"pattern":   `{ $.eventName = "ConsoleLogin" }`,
		"tags":      []model.Document{{"nested": 3}},
		"_dd_lines": map[string]int{"count": 1},
	}
	roots := []model.Document{{"resource": shared}, {"resource": shared}}
	expected, err := prepareScanDocument(roots[0], model.KindTerraform)
	require.NoError(t, err)
	sanitizer := newScanDocumentSanitizer(model.KindTerraform)
	for _, root := range roots {
		got, err := sanitizer.sanitize(root)
		require.NoError(t, err)
		require.Equal(t, expected, got)
		require.Equal(t, reflect.ValueOf(shared).Pointer(), reflect.ValueOf(got["resource"]).Pointer())
	}
	// A completed sibling does not mask an active cycle or poison a later root.
	cyclic := model.Document{}
	cyclic["self"] = cyclic
	_, err = sanitizer.sanitize(model.Document{"resource": shared, "cycle": cyclic})
	require.ErrorIs(t, err, errCyclicDocument)
	_, err = sanitizer.sanitize(model.Document{"resource": shared, "other": 4})
	require.NoError(t, err)
}

func TestSanitizerMemoLifetimeAndKind(t *testing.T) {
	for _, kind := range []model.FileKind{model.KindTerraformPlan, model.KindYAML} {
		sanitizer := newScanDocumentSanitizer(kind)
		named := model.Document{"value": 1}
		doc := map[string]interface{}{"value": 1, "named": named}
		_, err := sanitizer.sanitize(doc)
		require.NoError(t, err)
		require.Equal(t, 1, named["value"], "other kinds must retain their copying normalization path")
		require.Equal(t, map[string]interface{}{"value": float64(1)}, doc["named"])
		require.Empty(t, sanitizer.maps, "only Terraform config layers memoize completed visits")
		doc["value"] = 2
		_, err = sanitizer.sanitize(doc)
		require.NoError(t, err)
		require.Equal(t, float64(2), doc["value"])
	}
	doc := map[string]interface{}{"value": 1}
	_, err := sanitizeScanDocumentInPlace(doc, model.KindTerraform)
	require.NoError(t, err)
	doc["value"] = 2
	_, err = sanitizeScanDocumentInPlace(doc, model.KindTerraform)
	require.NoError(t, err)
	require.Equal(t, float64(2), doc["value"], "fresh sanitizers must revisit maps after mutation")
}
