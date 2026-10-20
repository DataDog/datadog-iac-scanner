/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2025 Datadog, Inc.
 */
package kustomize

import (
	"testing"
)

func TestParseDocuments(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []docRef
	}{
		{
			name: "multi document",
			data: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: b\n",
			want: []docRef{
				{kind: "ConfigMap", name: "a", index: 0},
				{kind: "Service", name: "b", index: 1},
			},
		},
		{
			name: "resourceless documents keep their index",
			data: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n---\napiVersion: v1\nkind: List\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n",
			// The List has no metadata.name, so it is skipped, but c must keep
			// index 2: attribution is by document position in the file.
			want: []docRef{
				{kind: "ConfigMap", name: "a", index: 0},
				{kind: "ConfigMap", name: "c", index: 2},
			},
		},
		{
			name: "undecodable document does not hide the rest",
			data: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n---\n- just\n- a sequence\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n",
			// The middle document decodes to a type error and is consumed;
			// the documents after it must stay visible, with c at index 2.
			want: []docRef{
				{kind: "ConfigMap", name: "a", index: 0},
				{kind: "ConfigMap", name: "c", index: 2},
			},
		},
		{
			name: "namespace is captured",
			data: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  namespace: dev\n",
			want: []docRef{{kind: "ConfigMap", name: "a", namespace: "dev", index: 0}},
		},
		{
			name: "no documents",
			data: "",
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDocuments([]byte(tc.data))
			if len(got) != len(tc.want) {
				t.Fatalf("parseDocuments() = %v, want %v", got, tc.want)
			}
			for i, want := range tc.want {
				if got[i] != want {
					t.Errorf("parseDocuments()[%d] = %+v, want %+v", i, got[i], want)
				}
			}
		})
	}
}

func TestParseDocuments_TruncatedStream(t *testing.T) {
	// A stream-level failure (bad YAML syntax) cannot be recovered from: the
	// decoder cannot make progress past it, so whatever parsed before it is
	// kept and the file stops there. This pins that the loop terminates.
	data := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n---\n: : :\n  - [\n"
	got := parseDocuments([]byte(data))
	if len(got) != 1 || got[0].name != "a" {
		t.Errorf("parseDocuments(truncated) = %v, want only document a", got)
	}
}
