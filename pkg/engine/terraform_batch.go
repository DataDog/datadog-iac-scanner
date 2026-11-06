/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"runtime"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
)

// terraformBatchDocs is how many Terraform documents a document-local rule
// is evaluated on at once. A variable so tests can batch small corpora.
var terraformBatchDocs = 4096

// terraformJoiningWorkers bounds the concurrent evaluations of joining rules:
// each one builds evaluation state over the whole corpus.
const terraformJoiningWorkers = 2

// batchLargeTerraform returns the documents of a scan whose rules are all
// Terraform rules and whose Terraform payload holds more than
// terraformBatchDocs documents, when it releases the parsed documents and
// line information and reduces findings to one per identity as they are
// decoded. Otherwise every rule is evaluated once on payloads.
func (c *Inspector) batchLargeTerraform(queries []model.QueryMetadata, payloads platformPayloads) ([]*ast.Term, bool) {
	if !c.releaseDocumentsAfterPayload || !c.discardLineInfoAfterUse || !c.compactFindingsAtDecode ||
		c.enableCoverageReport || payloads.full != nil {
		return nil, false
	}
	for i := range queries {
		if canonicalPlatformKey(queries[i].Platform) != platformTerraform {
			return nil, false
		}
	}
	docs := payloadDocuments(payloads.byPlatform[platformTerraform])
	if len(docs) <= terraformBatchDocs {
		return nil, false
	}
	return docs, true
}

// payloadDocuments returns the document terms of an assembleDocumentPayload
// payload.
func payloadDocuments(payload ast.Value) []*ast.Term {
	obj, ok := payload.(ast.Object)
	if !ok {
		return nil
	}
	term := obj.Get(ast.StringTerm("document"))
	if term == nil {
		return nil
	}
	arr, ok := term.Value.(*ast.Array)
	if !ok {
		return nil
	}
	docs := make([]*ast.Term, arr.Len())
	for i := range docs {
		docs[i] = arr.Elem(i)
	}
	return docs
}

// evalTerraformInBatches evaluates the document-local rules of run on
// batches of docs, the documents of payloads, sharing their terms, and the
// joining rules once on payloads.
func (c *Inspector) evalTerraformInBatches(
	ctx context.Context, run *queryRun, payloads platformPayloads, docs []*ast.Term,
) error {
	joining := c.terraformJoiningQueries(run.queries)
	local, joins := make(map[int]bool), make(map[int]bool)
	for i := range run.queries {
		if j, classified := joining[i]; !classified || j {
			joins[i] = true
		} else {
			local[i] = true
		}
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().Msgf("Evaluating %d document-local Terraform rules on %d documents in batches of %d, %d joining rules on all",
		len(local), len(docs), terraformBatchDocs, len(joins))

	if len(local) > 0 {
		for start := 0; start == 0 || start < len(docs); start += terraformBatchDocs {
			end := min(start+terraformBatchDocs, len(docs))
			only := make(map[int]bool, len(local))
			for i := range local {
				if !run.tally[i] {
					only[i] = true
				}
			}
			batch := assembleDocumentPayload(docs[start:end])
			err := c.executeQueries(ctx, run, terraformPayloads(batch), only, c.numWorkers)
			if err != nil {
				return err
			}
			runtime.GC()
		}
	}
	if len(joins) == 0 {
		return nil
	}
	return c.executeQueries(ctx, run, payloads, joins, min(c.numWorkers, terraformJoiningWorkers))
}

func terraformPayloads(payload ast.Value) platformPayloads {
	return platformPayloads{byPlatform: map[string]ast.Value{platformTerraform: payload}}
}
