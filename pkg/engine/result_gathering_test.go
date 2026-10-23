/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// Results are grouped by document, keeping the order of a document's own.
func TestSortByDocument_GroupsStably(t *testing.T) {
	item := func(doc, name string) interface{} {
		return map[string]interface{}{"documentId": doc, "name": name}
	}
	items := []interface{}{item("b", "1"), item("a", "2"), item("b", "3"), "not a result", item("a", "4")}
	sortByDocument(items)
	require.Equal(t, []interface{}{
		"not a result", item("a", "2"), item("a", "4"), item("b", "1"), item("b", "3"),
	}, items)
}

// The findings of a single query are taken without a copy; gathering those of
// another after them copies both, leaving the first query's untouched.
func TestProcessResult_TakesThenAppends(t *testing.T) {
	ctx := context.Background()
	ins := &Inspector{failedQueries: map[string]error{}}
	queries := []model.QueryMetadata{{Query: "q0"}, {Query: "q1"}}
	first := make([]model.Vulnerability, 2, 4)
	first[0].QueryID, first[1].QueryID = "a", "b"
	second := []model.Vulnerability{{QueryID: "c"}}

	gathered := make([]model.Vulnerability, 0)
	moduleVulns := map[string]int{}
	processResult(ctx, &QueryResult{vulnerabilities: first}, &gathered, &moduleVulns, queries, ins)
	require.Same(t, &first[0], &gathered[0], "a single query's findings are not copied")
	processResult(ctx, &QueryResult{vulnerabilities: second, queryID: 1}, &gathered, &moduleVulns, queries, ins)
	require.Equal(t, []string{"a", "b", "c"}, []string{gathered[0].QueryID, gathered[1].QueryID, gathered[2].QueryID})
	require.Empty(t, first[:4][2].QueryID, "nothing is written past the first query's findings")
}
