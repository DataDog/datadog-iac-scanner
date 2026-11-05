package engine

import (
	"context"
	"runtime"
	"sort"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
)

// terraformBatchDocs is how many Terraform documents are converted and
// evaluated together. The whole corpus as one AST is what lifts peak RSS
// after module evaluation; a batch is released before the next is built.
// Each document is converted once: the literal index is read from the Go
// documents, then a root group is converted and used for both document-local
// and cross-root rules.
const terraformBatchDocs = 4096

func (c *Inspector) batchLargeTerraform(queries []model.QueryMetadata, docs int) bool {
	if docs <= terraformBatchDocs || !c.releaseDocumentsAfterPayload ||
		!c.discardLineInfoAfterUse || !c.compactFindingsAtDecode || c.enableCoverageReport {
		return false
	}
	for i := range queries {
		if canonicalPlatformKey(queries[i].Platform) != platformTerraform {
			return false
		}
	}
	return true
}

func (c *Inspector) evalTerraformInBatches(
	ctx context.Context,
	scanID string,
	filesMap map[string]*model.FileMetadata,
	combinedDocs, moduleDocs []model.Document,
	queries []model.QueryMetadata,
	evalRoots map[string][]string,
	baseStores map[string]storage.Store,
	baseDataHashes map[string]uint64,
	sharedQueries map[int]*rego.PreparedEvalQuery,
	routing *findingRouting,
	tally queryTally,
) ([]model.Vulnerability, error) {
	tfDocs := terraformDocs(filesMap, combinedDocs, moduleDocs)
	crossNames, localNames := c.terraformQuerySplit(queries)
	index := c.literalIndexObject(queries, tfDocs, len(crossNames) > 0, evalRoots)
	byRoot, roots, rootless := docsByEvalRoot(tfDocs, evalRoots)

	var local, crossed []model.Vulnerability
	if len(localNames) > 0 {
		got, err := c.evalLocalDocBatches(ctx, scanID, filesMap, rootless, queries,
			baseStores, baseDataHashes, sharedQueries, routing, localNames, tally)
		if err != nil {
			return nil, err
		}
		local = append(local, got...)
	}

	var group []string
	groupDocs := 0
	inGroup := map[string]bool{}
	flush := func() error {
		if len(group) == 0 {
			return nil
		}
		localBatch, crossBatch, err := c.evalRootGroup(ctx, scanID, filesMap, byRoot, group, index, queries,
			baseStores, baseDataHashes, sharedQueries, routing, localNames, crossNames, tally)
		if err != nil {
			return err
		}
		local = append(local, localBatch...)
		crossed = append(crossed, crossBatch...)
		group = group[:0]
		groupDocs = 0
		inGroup = map[string]bool{}
		return nil
	}
	for _, root := range roots {
		n := 0
		for _, doc := range byRoot[root] {
			if !inGroup[documentID(doc)] {
				n++
			}
		}
		if len(group) > 0 && groupDocs+n > terraformBatchDocs {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		group = append(group, root)
		for _, doc := range byRoot[root] {
			id := documentID(doc)
			if !inGroup[id] {
				inGroup[id] = true
				groupDocs++
			}
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	releaseDocuments(filesMap)
	return append(local, crossed...), nil
}

func terraformDocs(filesMap map[string]*model.FileMetadata, combinedDocs, moduleDocs []model.Document) []interface{} {
	all, buckets, _ := partitionDocsByPlatform(filesMap, combinedDocs, moduleDocs)
	tfDocs := make([]interface{}, 0, len(all))
	for i, doc := range all {
		if buckets[i] == nil || containsStr(buckets[i], platformTerraform) {
			tfDocs = append(tfDocs, doc)
		}
	}
	return tfDocs
}

func (c *Inspector) literalIndexObject(
	queries []model.QueryMetadata, docs []interface{}, cross bool, evalRoots map[string][]string,
) ast.Object {
	if !cross || !terraformIndexNeeded(queries, c.terraformRuleLibraries()...) {
		return nil
	}
	idx := make(literalIndex)
	for _, doc := range docs {
		idx.addDocument(doc, evalRoots[documentID(doc)])
	}
	return idx.object()
}

func docsByEvalRoot(
	docs []interface{}, evalRoots map[string][]string,
) (byRoot map[string][]interface{}, roots []string, rootless []interface{}) {
	byRoot = map[string][]interface{}{}
	seen := map[string]bool{}
	for _, doc := range docs {
		rs := evalRoots[documentID(doc)]
		if len(rs) == 0 {
			rootless = append(rootless, doc)
			continue
		}
		for _, root := range rs {
			byRoot[root] = append(byRoot[root], doc)
			if !seen[root] {
				seen[root] = true
				roots = append(roots, root)
			}
		}
	}
	sort.Strings(roots)
	return byRoot, roots, rootless
}

func releaseDocuments(filesMap map[string]*model.FileMetadata) {
	for _, file := range filesMap {
		if file != nil {
			file.Document = nil
		}
	}
}

func (c *Inspector) terraformQuerySplit(queries []model.QueryMetadata) (crossNames, localNames map[int]bool) {
	cross := c.terraformCrossDocumentQueries(queries)
	crossNames = map[int]bool{}
	localNames = map[int]bool{}
	for i := range queries {
		if queries[i].Platform == platformTerraform && cross[i] {
			crossNames[i] = true
			continue
		}
		localNames[i] = true
	}
	return crossNames, localNames
}

func (c *Inspector) evalLocalDocBatches(
	ctx context.Context,
	scanID string,
	filesMap map[string]*model.FileMetadata,
	docs []interface{},
	queries []model.QueryMetadata,
	baseStores map[string]storage.Store,
	baseDataHashes map[string]uint64,
	sharedQueries map[int]*rego.PreparedEvalQuery,
	routing *findingRouting,
	only map[int]bool,
	tally queryTally,
) ([]model.Vulnerability, error) {
	var vulns []model.Vulnerability
	for start := 0; start < len(docs); start += terraformBatchDocs {
		end := start + terraformBatchDocs
		if end > len(docs) {
			end = len(docs)
		}
		batch, err := c.evalLocalTerms(ctx, scanID, filesMap, docs[start:end], queries,
			baseStores, baseDataHashes, sharedQueries, routing, only, tally)
		if err != nil {
			return nil, err
		}
		vulns = append(vulns, batch...)
		runtime.GC()
	}
	return vulns, nil
}

func (c *Inspector) evalRootGroup(
	ctx context.Context,
	scanID string,
	filesMap map[string]*model.FileMetadata,
	byRoot map[string][]interface{},
	roots []string,
	index ast.Object,
	queries []model.QueryMetadata,
	baseStores map[string]storage.Store,
	baseDataHashes map[string]uint64,
	sharedQueries map[int]*rego.PreparedEvalQuery,
	routing *findingRouting,
	localNames, crossNames map[int]bool,
	tally queryTally,
) (local, crossed []model.Vulnerability, err error) {
	order, rootTerms, err := c.termsForRoots(ctx, byRoot, roots)
	if err != nil {
		return nil, nil, err
	}
	if len(localNames) > 0 {
		payload := assembleDocumentPayload(order)
		local, err = c.executeQueries(ctx, scanID, filesMap, platformPayloads{
			byPlatform: map[string]ast.Value{platformTerraform: payload},
			full:       payload,
		}, queries, baseStores, baseDataHashes, sharedQueries, routing, localNames, tally)
		if err != nil {
			return nil, nil, err
		}
	}
	if len(crossNames) > 0 {
		crossed, err = c.executeQueries(ctx, scanID, filesMap, platformPayloads{
			terraformRootDocs: rootTerms,
			terraformIndex:    index,
		}, queries, baseStores, baseDataHashes, sharedQueries, routing, crossNames, tally)
		if err != nil {
			return nil, nil, err
		}
	}
	runtime.GC()
	return local, crossed, nil
}

func (c *Inspector) evalLocalTerms(
	ctx context.Context,
	scanID string,
	filesMap map[string]*model.FileMetadata,
	docs []interface{},
	queries []model.QueryMetadata,
	baseStores map[string]storage.Store,
	baseDataHashes map[string]uint64,
	sharedQueries map[int]*rego.PreparedEvalQuery,
	routing *findingRouting,
	only map[int]bool,
	tally queryTally,
) ([]model.Vulnerability, error) {
	terms, err := c.convertDocs(ctx, docs)
	if err != nil {
		return nil, err
	}
	payload := assembleDocumentPayload(terms)
	return c.executeQueries(ctx, scanID, filesMap, platformPayloads{
		byPlatform: map[string]ast.Value{platformTerraform: payload},
		full:       payload,
	}, queries, baseStores, baseDataHashes, sharedQueries, routing, only, tally)
}

func (c *Inspector) termsForRoots(
	ctx context.Context,
	byRoot map[string][]interface{},
	roots []string,
) ([]*ast.Term, map[string][]*ast.Term, error) {
	termsByID := map[string]*ast.Term{}
	order := make([]interface{}, 0)
	for _, root := range roots {
		for _, doc := range byRoot[root] {
			id := documentID(doc)
			if _, ok := termsByID[id]; ok {
				continue
			}
			termsByID[id] = nil
			order = append(order, doc)
		}
	}
	terms, err := c.convertDocs(ctx, order)
	if err != nil {
		return nil, nil, err
	}
	unique := make([]*ast.Term, len(terms))
	for i, doc := range order {
		termsByID[documentID(doc)] = terms[i]
		unique[i] = terms[i]
	}
	rootTerms := make(map[string][]*ast.Term, len(roots))
	for _, root := range roots {
		list := make([]*ast.Term, 0, len(byRoot[root]))
		for _, doc := range byRoot[root] {
			list = append(list, termsByID[documentID(doc)])
		}
		rootTerms[root] = list
	}
	return unique, rootTerms, nil
}

func (c *Inspector) convertDocs(ctx context.Context, docs []interface{}) ([]*ast.Term, error) {
	cons := newPayloadHashCons()
	terms := make([]*ast.Term, len(docs))
	for i, doc := range docs {
		value, err := c.interfaceToPayloadValue(ctx, doc, cons)
		if err != nil {
			return nil, err
		}
		terms[i] = ast.NewTerm(value)
	}
	return terms, nil
}

func documentID(doc interface{}) string {
	m, ok := asStringMap(doc)
	if !ok {
		return ""
	}
	id, _ := m["id"].(string)
	return id
}

func containsStr(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
