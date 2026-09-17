/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package runner

import (
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/stretchr/testify/require"
)

// TestNormalizeDocumentValue verifies that non-canonical document values are
// converted to exactly the shapes prepareScanDocument's JSON round-trip used
// to produce, and that already-canonical values pass through untouched.
func TestNormalizeDocumentValue(t *testing.T) {
	now := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	tests := []struct {
		name     string
		in       interface{}
		want     interface{}
		changed  bool
		identity bool // when true, want must be the same Go value (pointer-equal for maps)
	}{
		{name: "canonical string", in: "x", want: "x", changed: false},
		{name: "canonical float64", in: 1.5, want: 1.5, changed: false},
		{name: "canonical map", in: map[string]interface{}{"a": "b"}, want: nil, changed: false, identity: true},
		{name: "canonical slice", in: []interface{}{"a"}, want: nil, changed: false, identity: true},
		{name: "nil", in: nil, want: nil, changed: false},
		{name: "int", in: 3, want: float64(3), changed: true},
		{name: "int64", in: int64(-9), want: float64(-9), changed: true},
		{name: "uint32", in: uint32(7), want: float64(7), changed: true},
		{name: "float32 keeps shortest repr", in: float32(0.1), want: 0.1, changed: true},
		{name: "json.Number", in: json.Number("42"), want: float64(42), changed: true},
		{name: "bytes become base64", in: []byte("hello"), want: "aGVsbG8=", changed: true},
		{name: "time becomes RFC3339", in: now, want: now.Format(time.RFC3339Nano), changed: true},
		{name: "string slice", in: []string{"a", "b"}, want: []interface{}{"a", "b"}, changed: true},
		{name: "string map", in: map[string]string{"k": "v"}, want: map[string]interface{}{"k": "v"}, changed: true},
		{
			name:    "nested string map of string maps",
			in:      map[string]map[string]string{"k": {"a": "b"}},
			want:    map[string]interface{}{"k": map[string]interface{}{"a": "b"}},
			changed: true,
		},
		{
			name:    "slice of string maps",
			in:      []map[string]string{{"a": "b"}},
			want:    []interface{}{map[string]interface{}{"a": "b"}},
			changed: true,
		},
		{
			name:    "string-keyed interface map keys convert",
			in:      map[interface{}]interface{}{"a": 1},
			want:    map[string]interface{}{"a": float64(1)},
			changed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := normalizeDocumentValue(tt.in)
			require.Equal(t, tt.changed, changed)
			if tt.identity {
				require.Equal(t, tt.in, got)
				if m, ok := tt.in.(map[string]interface{}); ok {
					require.Equal(t, reflect.ValueOf(m).Pointer(), reflect.ValueOf(got).Pointer(),
						"canonical maps must not be copied")
				}
				if sl, ok := tt.in.([]interface{}); ok {
					require.Same(t, &sl[0], &(got.([]interface{}))[0], "canonical slices must not be copied")
				}
			} else if tt.changed {
				require.Equal(t, tt.want, got)
			}
		})
	}
}

// TestNormalizeDocumentValueFloat32NoWidening guards the exact float32 rule:
// a direct float64 conversion would turn 0.1 into 0.10000000149011612 and
// change rule-visible values relative to the old JSON round-trip.
func TestNormalizeDocumentValueFloat32NoWidening(t *testing.T) {
	got, changed := normalizeDocumentValue(float32(0.1))
	require.True(t, changed)
	f, ok := got.(float64)
	require.True(t, ok)
	s := strconv.FormatFloat(f, 'g', -1, 64)
	require.Equal(t, "0.1", s)
	require.NotEqual(t, float64(float32(0.1)), f)
	require.False(t, math.IsNaN(f))
}

// TestSanitizeScanDocumentInPlaceNormalizesExoticTypes runs a Terraform-style
// document containing non-canonical nested types through the in-place
// sanitizer and verifies the tree that reaches the payload builder is
// fully canonical, matching what the removed JSON round-trip produced.
func TestSanitizeScanDocumentInPlaceNormalizesExoticTypes(t *testing.T) {
	body := map[string]interface{}{
		"resource": map[string]interface{}{
			"aws_iam_user": map[string]interface{}{
				"example": map[string]interface{}{
					"tags":     []string{"a", "b"},
					"policy":   map[string]string{"Version": "2012-10-17"},
					"embedded": map[string]map[string]string{"inner": {"k": "v"}},
					"count":    2,
					"keep":     "untouched",
				},
			},
		},
		"_dd_lines": map[string]int{":0:0": 1},
	}
	got, err := sanitizeScanDocumentInPlace(body, model.KindTerraform)
	require.NoError(t, err)
	require.Equal(t, map[string]interface{}{
		"resource": map[string]interface{}{
			"aws_iam_user": map[string]interface{}{
				"example": map[string]interface{}{
					"tags":     []interface{}{"a", "b"},
					"policy":   map[string]interface{}{"Version": "2012-10-17"},
					"embedded": map[string]interface{}{"inner": map[string]interface{}{"k": "v"}},
					"count":    float64(2),
					"keep":     "untouched",
				},
			},
		},
	}, got)
}

// TestSanitizeScanDocumentInPlaceRejectsCyclicAnchorTree keeps the JSON
// round-trip's skip-on-cyclic behavior for the in-place path.
func TestSanitizeScanDocumentInPlaceRejectsCyclicAnchorTree(t *testing.T) {
	cyclic := map[string]interface{}{"a": "b"}
	cyclic["self"] = cyclic
	_, err := sanitizeScanDocumentInPlace(cyclic, model.KindYAML)
	require.ErrorIs(t, err, errCyclicDocument)
}

// TestShareableParse verifies the sharing gate: only parses that are pure
// functions of their content are shareable across files.
func TestShareableParse(t *testing.T) {
	doc := model.Document{"kind": "Pod"}
	tfDoc := model.Document{"resource": map[string]interface{}{}}

	require.True(t, shareableParse(&parser.ParsedDocument{
		Content: "apiVersion: v1\n", Kind: model.KindYAML, Docs: []model.Document{doc},
	}))
	require.False(t, shareableParse(&parser.ParsedDocument{
		Content: "resource {}\n", Kind: model.KindTerraform, Docs: []model.Document{tfDoc},
	}), "terraform documents are mutated later by module instantiation")
	require.False(t, shareableParse(&parser.ParsedDocument{
		Content: "a: 1\n", Kind: model.KindYAML, Docs: []model.Document{doc},
		ResolvedFiles: map[string]model.ResolvedFile{"x": {}},
	}), "reference-resolving parses depend on the file path")
	require.False(t, shareableParse(&parser.ParsedDocument{
		Content: "playbooks: []\n", Kind: model.KindYAML, Docs: []model.Document{{"playbooks": []interface{}{}}},
	}), "ansible playbooks are rewritten per file path")
	require.False(t, shareableParse(&parser.ParsedDocument{
		Content: "", Kind: model.KindYAML, Docs: []model.Document{doc},
	}), "empty content")
	require.False(t, shareableParse(&parser.ParsedDocument{
		Content: "a: 1\n", Kind: model.KindYAML,
	}), "no documents")
}

// TestCloneDocumentTopLevelSharedChildren verifies the per-file copy handed
// out from the shared-parse cache: the top-level map is fresh (so Combine can
// insert the file's id/file) while child maps stay shared with the cache.
func TestCloneDocumentTopLevelSharedChildren(t *testing.T) {
	child := map[string]interface{}{"spec": "value"}
	doc := model.Document{"apiVersion": "v1", "metadata": child}
	clone := cloneDocumentTopLevel(doc)

	require.Equal(t, doc, clone)
	require.NotEqual(t, reflect.ValueOf(doc).Pointer(), reflect.ValueOf(clone).Pointer(),
		"top-level map must be a fresh copy")
	require.Equal(t, reflect.ValueOf(child).Pointer(), reflect.ValueOf(clone["metadata"]).Pointer(),
		"children must stay shared with the cached tree")

	// Combine-style per-file mutation only affects the clone.
	clone["id"] = "file-1"
	clone["metadata"] = map[string]interface{}{"replaced": true}
	require.NotContains(t, doc, "id")
	require.Equal(t, child, doc["metadata"])
}
