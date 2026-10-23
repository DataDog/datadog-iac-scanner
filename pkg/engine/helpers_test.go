/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/open-policy-agent/opa/v1/ast"
)

// interfaceToPayloadValue converts one document node to its payload value.
func (c *Inspector) interfaceToPayloadValue(
	ctx context.Context,
	value interface{},
	cons *payloadHashCons,
) (ast.Value, error) {
	term, _, err := c.payloadTerm(ctx, value, cons)
	if err != nil {
		return nil, err
	}
	return term.Value, nil
}

// instantiatedDocs prepares the documents of one root and merges them.
func instantiatedDocs(
	resources []tfeval.ResolvedResource,
	byAbsPath map[string]*model.FileMetadata,
	repoPath string,
	targets *ruleTargets,
	seen map[docContentKey]string,
	extras map[string][]extraCallerInfo,
	instantiated instantiatedIndex,
	lookup moduleProvenanceLookup,
	attributions *moduleAttributionCache,
	lineInfo instanceLineInfo,
) (docs []model.Document, synthetic []*model.FileMetadata, resourceCount int) {
	prepared := prepareRootDocs(resources, byAbsPath, repoPath, targets, lookup, attributions)
	docs, synthetic = mergeRootDocs(prepared, seen, extras, instantiated, lineInfo)
	return docs, synthetic, prepared.resourceCount
}
