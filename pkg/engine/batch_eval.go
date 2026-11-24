/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/pkg/errors"
)

// queryBatch groups multiple partial-set rules that share a compiled compiler,
// store, and input payload into a single PreparedEvalQuery so OPA's
// identityVirtualCache reuses pure library calls (e.g. k8s spec_info, valid_key)
// across every rule in the batch.
type queryBatch struct {
	queryIDs []int
	prepared *rego.PreparedEvalQuery
	payload  ast.Value
}

// isPartialSetPolicy reports whether every DatadogPolicy rule in mod is a
// partial-set rule (`DatadogPolicy contains result if { ... }`) without else
// branches. A partial-set rule always evaluates to a defined set (possibly
// empty), so combining multiple such rules in one conjunction query never
// causes one rule's zero-result outcome to short-circuit another rule.
func isPartialSetPolicy(mod *ast.Module) bool {
	if mod == nil {
		return false
	}
	found := false
	for _, r := range mod.Rules {
		if r.Head != nil && r.Head.Name == policyRuleName {
			if r.Head.Key == nil || r.Else != nil {
				return false
			}
			found = true
		}
	}
	return found
}

const (
	maxBatchQueries = 16
	policyRuleName  = "DatadogPolicy"
)

type batchGroupKey struct {
	platform string
	subset   string
}

func groupBatchableQueries(
	indices []int,
	queryPath map[int]string,
	plans []ruleExecPlan,
	queries []model.QueryMetadata,
	canBatch func(int) bool,
) (map[batchGroupKey][]int, []batchGroupKey) {
	groups := make(map[batchGroupKey][]int)
	var groupOrder []batchGroupKey
	for _, i := range indices {
		if _, ok := queryPath[i]; !ok {
			continue
		}
		if i >= len(plans) || !plans[i].isPartialSet || !canBatch(i) {
			continue
		}
		gk := batchGroupKey{
			platform: canonicalPlatformKey(queries[i].Platform),
			subset:   plans[i].subsetKey,
		}
		if _, exists := groups[gk]; !exists {
			groupOrder = append(groupOrder, gk)
		}
		groups[gk] = append(groups[gk], i)
	}
	return groups, groupOrder
}

func prepareBatchChunk(
	ctx context.Context,
	compiler *ast.Compiler,
	store storage.Store,
	chunk []int,
	queryPath map[int]string,
	payload ast.Value,
) (queryBatch, bool) {
	var qb strings.Builder
	for k, qid := range chunk {
		if k > 0 {
			qb.WriteString("; ")
		}
		qb.WriteByte('r')
		qb.WriteString(strconv.Itoa(k))
		qb.WriteString(" = ")
		qb.WriteString(queryPath[qid])
	}
	pq, err := rego.New(
		rego.Query(qb.String()),
		rego.SetRegoVersion(ast.RegoV1),
		rego.Compiler(compiler),
		rego.Store(store),
		rego.UnsafeBuiltins(unsafeRegoFunctions),
	).PrepareForEval(ctx)
	if err != nil {
		return queryBatch{}, false
	}
	p := pq
	return queryBatch{queryIDs: chunk, prepared: &p, payload: payload}, true
}

// buildQueryBatches groups eligible partial-set queries that share the same
// payload into batches sized to keep all worker cores saturated while
// maximizing virtual-cache reuse across rules.
func buildQueryBatches(
	ctx context.Context,
	compiler *ast.Compiler,
	store storage.Store,
	indices []int,
	queryPath map[int]string,
	plans []ruleExecPlan,
	queries []model.QueryMetadata,
	payloads platformPayloads,
	canBatch func(queryIdx int) bool,
	numWorkers int,
) (batches []queryBatch, batched map[int]bool) {
	if len(indices) < 2 || len(plans) == 0 {
		return nil, nil
	}

	groups, groupOrder := groupBatchableQueries(indices, queryPath, plans, queries, canBatch)
	workers := max(numWorkers, 1)
	batched = make(map[int]bool)
	for _, gk := range groupOrder {
		ids := groups[gk]
		if len(ids) < 2 {
			continue
		}
		batchSize := min(max((len(ids)+workers-1)/workers, 2), maxBatchQueries)
		payload := plans[ids[0]].subsetPayload
		if payload == nil {
			payload = selectPlatformPayload(queries[ids[0]].Platform, payloads.byPlatform, payloads.full)
		}
		for start := 0; start < len(ids); start += batchSize {
			chunk := ids[start:min(start+batchSize, len(ids))]
			if len(chunk) < 2 {
				continue
			}
			batch, ok := prepareBatchChunk(ctx, compiler, store, chunk, queryPath, payload)
			if !ok {
				continue
			}
			batches = append(batches, batch)
			for _, qid := range chunk {
				batched[qid] = true
			}
		}
	}
	return batches, batched
}

func (c *Inspector) hasRuleArguments(ctx context.Context, query *model.QueryMetadata) bool {
	if len(c.ruleConfigs) == 0 {
		return false
	}
	queryID, legacyQueryID, legacyQueryIDs := queryIDsFromMetadata(ctx, query)
	rc, found := lookupRuleConfig(c.ruleConfigs, queryID, legacyQueryID, legacyQueryIDs)
	return found && rc.Arguments != nil
}

// evalQueryBatch evaluates a batch of partial-set queries in a single OPA Eval
// call sharing one identityVirtualCache, then decodes each rule's results.
// On any non-cancellation error or panic, it falls back to evaluating each
// query individually so rule-level error isolation is preserved.
func (c *Inspector) evalQueryBatch(
	ctx context.Context,
	scanID string,
	filesMap map[string]*model.FileMetadata,
	payloads platformPayloads,
	queries []model.QueryMetadata,
	batch queryBatch,
	modules []tfmodules.ParsedModule,
	baseStores map[string]storage.Store,
	baseDataHashes map[string]uint64,
	sharedQueries map[int]*rego.PreparedEvalQuery,
	routing *findingRouting,
	plans []ruleExecPlan,
	out []QueryResult,
) {
	results, evalDuration, err := evalBatchSafely(ctx, batch)
	if err != nil {
		if topdown.IsCancel(err) || ctx.Err() != nil {
			cancelErr := errors.Wrap(err, "query evaluation canceled (scan aborting)")
			for _, qid := range batch.queryIDs {
				out[qid] = QueryResult{err: cancelErr, queryID: qid}
			}
			return
		}
		// Fallback to isolated per-query evaluation so a failing rule never
		// masks or fails its batch siblings.
		for _, qid := range batch.queryIDs {
			var plan *ruleExecPlan
			if qid < len(plans) {
				plan = &plans[qid]
			}
			out[qid] = c.evalQuery(ctx, scanID, filesMap, payloads, queries, qid,
				modules, baseStores, baseDataHashes, sharedQueries, routing, plan)
		}
		return
	}

	if len(results) == 0 {
		for _, qid := range batch.queryIDs {
			c.tracker.TrackQueryExecution(queries[qid].Aggregation)
			out[qid] = QueryResult{queryID: qid}
		}
		return
	}

	perRuleDur := evalDuration / time.Duration(len(batch.queryIDs))
	bindings := results[0].Bindings
	for k, qid := range batch.queryIDs {
		raw, ok := bindings["r"+strconv.Itoa(k)]
		if !ok {
			c.tracker.TrackQueryExecution(queries[qid].Aggregation)
			out[qid] = QueryResult{queryID: qid}
			continue
		}
		items, ok := raw.([]interface{})
		if ok && len(items) == 0 {
			c.tracker.TrackQueryExecution(queries[qid].Aggregation)
			out[qid] = QueryResult{queryID: qid}
			continue
		}

		query := &PreparedQuery{Metadata: queries[qid]}
		qCtx := &QueryContext{
			Ctx:                     ctx,
			scanID:                  scanID,
			Files:                   filesMap,
			Query:                   query,
			FlagEvaluator:           c.flagEvaluator,
			discardLineInfoAfterUse: c.discardLineInfoAfterUse,
			findings:                newFindingSet(c.compactFindingsAtDecode, routing),
		}
		qCtx.findings.recordDuplicates = c.inventory != nil

		singleRS := rego.ResultSet{{Bindings: rego.Vars{"result": raw}}}
		vuls, moduleRaised, moduleSeverity, decErr := c.decodeBatchedQuerySafely(ctx, qCtx, singleRS, perRuleDur)
		if decErr == nil {
			c.tracker.TrackQueryExecution(queries[qid].Aggregation)
		}
		out[qid] = QueryResult{
			vulnerabilities:     vuls,
			moduleResultsRaised: moduleRaised,
			moduleSeverity:      moduleSeverity,
			err:                 decErr,
			queryID:             qid,
		}
	}
}

func (c *Inspector) decodeBatchedQuerySafely(
	ctx context.Context,
	qCtx *QueryContext,
	singleRS rego.ResultSet,
	perRuleDur time.Duration,
) (vuls []model.Vulnerability, raised int, severity model.Severity, err error) {
	defer func() {
		if r := recover(); r != nil {
			errMessage := fmt.Sprintf("Recovered from panic during query '%s' run. ", qCtx.Query.Metadata.Query)
			err = fmt.Errorf("panic: %v\n%s", r, string(debug.Stack()))
			contextLogger := logger.FromContext(ctx)
			contextLogger.Err(err).Msg(errMessage)
		}
	}()
	return c.DecodeQueryResults(ctx, qCtx, ctx, singleRS, perRuleDur)
}

func evalBatchSafely(ctx context.Context, batch queryBatch) (results rego.ResultSet, dur time.Duration, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during batched query eval: %v\n%s", r, string(debug.Stack()))
			contextLogger := logger.FromContext(ctx)
			contextLogger.Err(err).Msg("Recovered from panic during batched query eval")
		}
	}()
	start := time.Now()
	results, err = batch.prepared.Eval(ctx,
		rego.EvalParsedInput(batch.payload),
		rego.EvalVirtualCache(newIdentityVirtualCache()),
	)
	return results, time.Since(start), err
}
