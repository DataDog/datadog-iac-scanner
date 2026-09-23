/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package runner

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTreeHashConsSharesIdenticalSubtrees verifies that structurally identical
// subtrees of two different sanitized documents collapse to one shared
// instance, while differing subtrees stay distinct, and that the top-level map
// is never interned (Combine mutates it per file).
func TestTreeHashConsSharesIdenticalSubtrees(t *testing.T) {
	cons := newTreeHashCons()

	docA := map[string]interface{}{
		"kind": "Pod",
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{"app": "web", "tier": "front"},
		},
		"spec": []interface{}{
			map[string]interface{}{"name": "c1", "port": float64(80)},
		},
	}
	docB := map[string]interface{}{
		"kind": "Deployment",
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{"app": "web", "tier": "front"},
		},
		"spec": []interface{}{
			map[string]interface{}{"name": "c1", "port": float64(80)},
		},
	}

	a := cons.consChildren(docA)
	b := cons.consChildren(docB)

	// Top-level maps stay distinct instances.
	require.NotEqual(t,
		reflect.ValueOf(a).Pointer(), reflect.ValueOf(b).Pointer(),
		"top-level documents must not be shared")

	// Identical label blocks and container slices are shared.
	require.Equal(t,
		reflect.ValueOf(a["metadata"].(map[string]interface{})["labels"]).Pointer(),
		reflect.ValueOf(b["metadata"].(map[string]interface{})["labels"]).Pointer(),
		"identical label blocks must be shared")
	require.Equal(t,
		reflect.ValueOf(a["spec"]).Pointer(), reflect.ValueOf(b["spec"]).Pointer(),
		"identical spec slices must be shared")

	// A third document with a different label value gets a distinct block.
	docC := map[string]interface{}{
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{"app": "web", "tier": "back"},
		},
	}
	c := cons.consChildren(docC)
	require.NotEqual(t,
		reflect.ValueOf(a["metadata"].(map[string]interface{})["labels"]).Pointer(),
		reflect.ValueOf(c["metadata"].(map[string]interface{})["labels"]).Pointer())

	// Values survive unchanged.
	require.Equal(t, map[string]interface{}{"app": "web", "tier": "front"},
		b["metadata"].(map[string]interface{})["labels"])
}

// TestTreeHashConsSkipsUncomparableValues guards the panic that originally
// crashed scans: values of uncomparable types (e.g. structs holding slices)
// must be skipped by the canonical-equality check rather than compared.
func TestTreeHashConsSkipsUncomparableValues(t *testing.T) {
	type uncomparable struct{ data []int }
	cons := newTreeHashCons()

	docA := map[string]interface{}{"x": uncomparable{data: []int{1}}, "k": "v"}
	docB := map[string]interface{}{"x": uncomparable{data: []int{2}}, "k": "v"}

	a := cons.consChildren(docA)
	b := cons.consChildren(docB)

	require.NotEqual(t, reflect.ValueOf(a).Pointer(), reflect.ValueOf(b).Pointer(),
		"documents differing only in an uncomparable value must not be shared")
	require.Equal(t, uncomparable{data: []int{1}}, a["x"])
	require.Equal(t, uncomparable{data: []int{2}}, b["x"])
}

// TestTreeHashConsKeepsOpaqueSubtreesOutOfBuckets guards the quadratic prepare
// seen on CI/CD corpora: subtrees holding non-canonical values (the parser's
// attached structs) must not accumulate in a content bucket, while their
// canonical siblings are still shared.
func TestTreeHashConsKeepsOpaqueSubtreesOutOfBuckets(t *testing.T) {
	type parsedExpr struct{ raw string }
	cons := newTreeHashCons()

	docs := make([]map[string]interface{}, 0, 100)
	for i := 0; i < 100; i++ {
		docs = append(docs, cons.consChildren(map[string]interface{}{
			"step": map[string]interface{}{
				"run":                  "echo hi",
				"_parsed_expressions_": []interface{}{parsedExpr{raw: "x"}},
			},
			"labels": map[string]interface{}{"app": "web"},
		}))
	}

	for key, bucket := range cons.byContent {
		require.LessOrEqual(t, len(bucket), 1, "bucket %v must not accumulate unshareable subtrees", key)
	}
	require.NotEmpty(t, cons.opaque)
	require.Equal(t,
		reflect.ValueOf(docs[0]["labels"]).Pointer(),
		reflect.ValueOf(docs[99]["labels"]).Pointer(),
		"canonical siblings of opaque subtrees must still be shared")
	require.NotEqual(t,
		reflect.ValueOf(docs[0]["step"]).Pointer(),
		reflect.ValueOf(docs[99]["step"]).Pointer())
}
