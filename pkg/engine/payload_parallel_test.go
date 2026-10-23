/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

func payloadDocs(n int) []model.Document {
	docs := make([]model.Document, n)
	shared := map[string]interface{}{"team": "t", "tier": "1"}
	for i := range docs {
		docs[i] = model.Document{
			"id":   fmt.Sprintf("doc-%d", i),
			"file": "modules/m/main.tf",
			"resource": map[string]interface{}{"aws_s3_bucket": map[string]interface{}{"b": map[string]interface{}{
				"bucket": fmt.Sprintf("b-%d", i%97), "acl": "private", "tags": shared,
				"rules": []interface{}{map[string]interface{}{"id": i % 3}, "jsonencode({a = 1})"},
			}}},
		}
	}
	return docs
}

// Converting documents on several workers yields the terms one worker does,
// in the same order, and releases every source tree.
func TestConvertPayloadDocuments_ParallelMatchesSerial(t *testing.T) {
	previous := parallelPayloadDocuments
	defer func() { parallelPayloadDocuments = previous }()
	ins := &Inspector{releaseDocumentsAfterPayload: true}
	convert := func(threshold int) ([]string, []model.Document) {
		parallelPayloadDocuments = threshold
		docs := payloadDocs(5000)
		all := make([]interface{}, len(docs))
		for i, d := range docs {
			all[i] = map[string]interface{}(d)
		}
		terms, err := ins.convertPayloadDocuments(context.Background(), all, nil, nil, docs)
		require.NoError(t, err)
		out := make([]string, len(terms))
		for i, term := range terms {
			out[i] = term.String()
		}
		return out, docs
	}
	serial, _ := convert(1 << 30)
	parallel, released := convert(100)
	require.Equal(t, serial, parallel)
	for i, d := range released {
		require.Nil(t, d, "document %d not released", i)
	}
}

// Parsed documents, whose nodes the runner shares, are memoized by address;
// module documents are not. Either way a document converts to the term a
// plain conversion gives.
func TestConvertPayloadDocuments_ParsedAndModuleDocumentsConvertAlike(t *testing.T) {
	ins := &Inspector{}
	want := func(docs []model.Document) []string {
		out := make([]string, len(docs))
		for i, d := range docs {
			raw, err := ast.InterfaceToValue(map[string]interface{}(d))
			require.NoError(t, err)
			out[i] = ins.TransformJsonencodeInPayload(context.Background(), raw).String()
		}
		return out
	}
	rendered := func(terms []*ast.Term) []string {
		out := make([]string, len(terms))
		for i, term := range terms {
			out[i] = term.String()
		}
		return out
	}
	docs := payloadDocs(300)
	expected := want(docs)
	all := make([]interface{}, len(docs))
	for i, d := range docs {
		all[i] = map[string]interface{}(d)
	}
	parsed, err := ins.convertPayloadDocuments(context.Background(), all, nil, docs[:150], docs[150:])
	require.NoError(t, err)
	require.Equal(t, expected, rendered(parsed))

	for i, d := range docs {
		all[i] = map[string]interface{}(d)
	}
	modules, err := ins.convertPayloadDocuments(context.Background(), all, nil, nil, docs)
	require.NoError(t, err)
	require.Equal(t, expected, rendered(modules))
}
