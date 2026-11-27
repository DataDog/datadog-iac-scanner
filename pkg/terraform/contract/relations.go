/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package contract

import (
	"context"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/refs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// LiteralKeyMap maps companionType -> companionAttr -> targetType -> targetAttrs.
// Literal matching is strictly scoped to the same Terraform root module (never
// heuristically across independent roots/accounts).
type LiteralKeyMap map[string]map[string]map[string][]string

const (
	metaArgEach                = "each"
	metaArgKey                 = "key"
	metaArgValue               = "value"
	typeS3Bucket               = "aws_s3_bucket"
	typeIAMRole                = "aws_iam_role"
	typeIAMUser                = "aws_iam_user"
	typeIAMGroup               = "aws_iam_group"
	typeIAMPolicy              = "aws_iam_policy"
	typeIAMInstanceProfile     = "aws_iam_instance_profile"
	typeCloudWatchLogGroup     = "aws_cloudwatch_log_group"
	typeCloudWatchMetricFilter = "aws_cloudwatch_log_metric_filter"
	typeAutoscalingGroup       = "aws_autoscaling_group"
	typeSecurityGroup          = "aws_security_group"
	attrARN                    = "arn"
	attrBucket                 = "bucket"
	attrName                   = "name"
	attrUsers                  = "users"
	attrGroups                 = "groups"
	attrClusterID              = "cluster_identifier"
	attrZoneID                 = "zone_id"
	attrFunctionName           = "function_name"
	attrDomainName             = "domain_name"
	attrRole                   = "role"
	attrUser                   = "user"
	attrGroup                  = "group"
	attrPolicyARN              = "policy_arn"
	attrLogGroupName           = "log_group_name"
	attrSecurityGroups         = "security_groups"
)

// DefaultLiteralKeys covers the standard AWS/Azure/GCP/Alicloud companion
// resources that may name their parent by a known literal string instead of a
// Terraform reference.
var DefaultLiteralKeys = LiteralKeyMap{
	"aws_s3_bucket_acl":                                  {attrBucket: {typeS3Bucket: {attrBucket}}},
	"aws_s3_bucket_cors_configuration":                   {attrBucket: {typeS3Bucket: {attrBucket}}},
	"aws_s3_bucket_lifecycle_configuration":              {attrBucket: {typeS3Bucket: {attrBucket}}},
	"aws_s3_bucket_logging":                              {attrBucket: {typeS3Bucket: {attrBucket}}},
	"aws_s3_bucket_ownership_controls":                   {attrBucket: {typeS3Bucket: {attrBucket}}},
	"aws_s3_bucket_policy":                               {attrBucket: {typeS3Bucket: {attrBucket}}},
	"aws_s3_bucket_public_access_block":                  {attrBucket: {typeS3Bucket: {attrBucket}}},
	"aws_s3_bucket_server_side_encryption_configuration": {attrBucket: {typeS3Bucket: {attrBucket}}},
	"aws_s3_bucket_versioning":                           {attrBucket: {typeS3Bucket: {attrBucket}}},
	"aws_s3_bucket_website_configuration":                {attrBucket: {typeS3Bucket: {attrBucket}}},
	"aws_cloudtrail":                                     {"s3_bucket_name": {typeS3Bucket: {attrBucket}}},
	"aws_iam_role_policy":                                {attrRole: {typeIAMRole: {attrName}}},
	"aws_iam_user_policy":                                {attrUser: {typeIAMUser: {attrName}}},
	"aws_iam_group_policy":                               {attrGroup: {typeIAMGroup: {attrName}}},
	"aws_iam_role_policy_attachment": {
		attrRole:      {typeIAMRole: {attrName}},
		attrPolicyARN: {typeIAMPolicy: {attrARN}},
	},
	"aws_iam_user_policy_attachment": {
		attrUser:      {typeIAMUser: {attrName}},
		attrPolicyARN: {typeIAMPolicy: {attrARN}},
	},
	"aws_iam_group_policy_attachment": {
		attrGroup:     {typeIAMGroup: {attrName}},
		attrPolicyARN: {typeIAMPolicy: {attrARN}},
	},
	"aws_iam_policy_attachment": {
		"roles":       {typeIAMRole: {attrName}},
		attrUsers:     {typeIAMUser: {attrName}},
		attrGroups:    {typeIAMGroup: {attrName}},
		attrPolicyARN: {typeIAMPolicy: {attrARN}},
	},
	"aws_iam_group_membership": {
		attrGroup: {typeIAMGroup: {attrName}},
		attrUsers: {typeIAMUser: {attrName}},
	},
	"aws_iam_user_group_membership": {
		attrUser:   {typeIAMUser: {attrName}},
		attrGroups: {typeIAMGroup: {attrName}},
	},
	typeIAMInstanceProfile:                       {attrRole: {typeIAMRole: {attrName}}},
	"aws_kms_alias":                              {"target_key_id": {"aws_kms_key": {"key_id", attrARN}}},
	typeCloudWatchMetricFilter:                   {attrLogGroupName: {typeCloudWatchLogGroup: {attrName}}},
	"aws_cloudwatch_log_subscription_filter":     {attrLogGroupName: {typeCloudWatchLogGroup: {attrName}}},
	"aws_flow_log":                               {attrLogGroupName: {typeCloudWatchLogGroup: {attrName}}},
	"aws_ecr_repository_policy":                  {"repository": {"aws_ecr_repository": {attrName}}},
	"aws_redshift_logging":                       {attrClusterID: {"aws_redshift_cluster": {attrClusterID}}},
	"aws_route53_query_log":                      {attrZoneID: {"aws_route53_zone": {attrZoneID}}},
	"aws_lambda_permission":                      {attrFunctionName: {"aws_lambda_function": {attrFunctionName, attrARN}}},
	"aws_autoscaling_attachment":                 {"autoscaling_group_name": {typeAutoscalingGroup: {attrName}}},
	"aws_autoscaling_notification":               {"group_names": {typeAutoscalingGroup: {attrName}}},
	"azurerm_sql_active_directory_administrator": {"server_name": {"azurerm_sql_server": {attrName}}},
	"aws_elasticsearch_domain_policy":            {attrDomainName: {"aws_elasticsearch_domain": {attrDomainName}}},
	"aws_iam_access_key":                         {attrUser: {typeIAMUser: {attrName}}},
	"alicloud_actiontrail_trail":                 {"oss_bucket_name": {"alicloud_oss_bucket": {attrBucket}}},
	"aws_instance": {
		attrSecurityGroups:     {typeSecurityGroup: {attrName}},
		"iam_instance_profile": {typeIAMInstanceProfile: {attrName}},
	},
	"aws_launch_configuration": {attrSecurityGroups: {typeSecurityGroup: {attrName}}},
}

type blockIdentityKey struct {
	moduleAddr string
	kind       string
	typ        string
	name       string
}

type hclResourceMeta struct {
	res        *policy.Resource
	resolved   *tfeval.ResolvedResource
	moduleAddr string
	body       *hclsyntax.Body
	scope      *tfeval.ModuleScope
	dynCounts  tfeval.DynamicCounts
	iteration  map[string]cty.Value
	keyUnknown bool
	readPath   string
	callChain  []tfeval.CallSite
}

type relationCall struct {
	parent string
	site   tfeval.CallSite
}

type relationTrace struct {
	byBlock map[blockIdentityKey][]*hclResourceMeta
	scopes  map[string]*tfeval.ModuleScope
	calls   map[string]relationCall
}

func newRelationTrace(metas []*hclResourceMeta, instances []tfeval.ModuleInstance) *relationTrace {
	t := &relationTrace{
		byBlock: map[blockIdentityKey][]*hclResourceMeta{},
		scopes:  map[string]*tfeval.ModuleScope{},
		calls:   map[string]relationCall{},
	}
	addCallChain := func(chain []tfeval.CallSite, leafAddr string, leafScope *tfeval.ModuleScope) {
		parent := ""
		for i := range chain {
			call := chain[i]
			t.scopes[parent] = call.Caller
			child := "module." + call.ModuleName + formatInstanceKey(call.InstanceKey)
			if parent != "" {
				child = parent + "." + child
			}
			t.calls[child] = relationCall{parent: parent, site: call}
			parent = child
		}
		if leafAddr != "" {
			t.scopes[leafAddr] = leafScope
		}
	}
	for _, m := range metas {
		key := blockIdentityKey{moduleAddr: m.moduleAddr, kind: m.res.Kind, typ: m.res.Type, name: m.res.Name}
		t.byBlock[key] = append(t.byBlock[key], m)
		t.scopes[m.moduleAddr] = m.scope
		addCallChain(m.callChain, m.moduleAddr, m.scope)
	}
	for _, instance := range instances {
		addCallChain(instance.CallChain, instance.ModuleAddress, instance.Scope)
	}
	return t
}

func (c *relationCall) context() *hcl.EvalContext {
	ctx := c.site.Caller.EvalContext()
	if ctx == nil {
		ctx = &hcl.EvalContext{}
	}
	key := c.site.InstanceKey
	if key == cty.NilVal {
		return ctx
	}
	child := ctx.NewChild()
	if key.Type() == cty.Number {
		child.Variables = map[string]cty.Value{"count": cty.ObjectVal(map[string]cty.Value{"index": key})}
	} else {
		value := c.eachValue(ctx, key)
		child.Variables = map[string]cty.Value{metaArgEach: cty.ObjectVal(map[string]cty.Value{"key": key, metaArgValue: value})}
	}
	return child
}

func (c *relationCall) eachValue(ctx *hcl.EvalContext, key cty.Value) cty.Value {
	if c.site.Body == nil {
		return cty.DynamicVal
	}
	attr := c.site.Body.Attributes["for_each"]
	if attr == nil {
		return cty.DynamicVal
	}
	collection, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() || !collection.IsKnown() || collection.IsNull() {
		return cty.DynamicVal
	}
	return selectForEachValue(collection, key)
}

func selectForEachValue(collection, key cty.Value) cty.Value {
	if collection.Type().IsSetType() {
		return key
	}
	if collection.Type().IsObjectType() && key.Type() == cty.String {
		if _, ok := collection.Type().AttributeTypes()[key.AsString()]; ok {
			return collection.GetAttr(key.AsString())
		}
		return cty.DynamicVal
	}
	if collection.Type().IsMapType() || collection.Type().IsListType() || collection.Type().IsTupleType() {
		index := collection.HasIndex(key)
		if index.IsKnown() && !index.IsNull() && index.True() {
			return collection.Index(key)
		}
	}
	return cty.DynamicVal
}

// Select the referenced object field before tracing an alias, so unrelated
// siblings in a local map or module argument never create extra edges.
//
//nolint:gocyclo
func selectRelationExpr(expr hcl.Expression, path string, ctx *hcl.EvalContext) hcl.Expression {
	if path == "" {
		return expr
	}
	head, tail, _ := strings.Cut(path, ".")
	switch e := expr.(type) {
	case *hclsyntax.ParenthesesExpr:
		return selectRelationExpr(e.Expression, path, ctx)
	case *hclsyntax.ObjectConsExpr:
		for _, item := range e.Items {
			key, diags := item.KeyExpr.Value(ctx)
			if !diags.HasErrors() && key.IsKnown() && !key.IsNull() && key.Type() == cty.String && key.AsString() == head {
				return selectRelationExpr(item.ValueExpr, tail, ctx)
			}
		}
	case *hclsyntax.TupleConsExpr:
		if index, err := strconv.Atoi(head); err == nil && index >= 0 && index < len(e.Exprs) {
			return selectRelationExpr(e.Exprs[index], tail, ctx)
		}
	case *hclsyntax.ScopeTraversalExpr:
		traversal := slices.Clone(e.Traversal)
		for _, name := range strings.Split(path, ".") {
			traversal = append(traversal, hcl.TraverseAttr{Name: name})
		}
		return &hclsyntax.ScopeTraversalExpr{Traversal: traversal, SrcRange: e.SrcRange}
	}
	return nil
}

func selectRelationRef(expr hcl.Expression, ref *refs.Ref, ctx *hcl.EvalContext) (hcl.Expression, bool) {
	if expr == nil || ref == nil {
		return nil, false
	}
	key := relationRefKey(ref, ctx)
	if ref.DynamicKey && key == nil {
		return nil, false
	}
	if key != nil {
		keyPath, ok := relationKeyPath(*key)
		if !ok {
			return nil, false
		}
		expr = selectRelationExpr(expr, keyPath, ctx)
		if expr == nil {
			return nil, false
		}
	}
	if path := ref.ReadPath(); path != "" {
		expr = selectRelationExpr(expr, path, ctx)
	}
	return expr, expr != nil
}

func relationRefKey(ref *refs.Ref, ctx *hcl.EvalContext) *cty.Value {
	if ref.Key != nil || !ref.DynamicKey || ref.KeyExpr == nil || ctx == nil {
		return ref.Key
	}
	value, diags := ref.KeyExpr.Value(ctx)
	if diags.HasErrors() || !value.IsKnown() || value.IsNull() {
		return nil
	}
	return &value
}

func relationKeyPath(key cty.Value) (string, bool) {
	switch key.Type() {
	case cty.String:
		return key.AsString(), true
	case cty.Number:
		return key.AsBigFloat().Text('f', 0), true
	default:
		return "", false
	}
}

func selectRelationExprAtKey(expr hcl.Expression, key cty.Value, ctx *hcl.EvalContext) hcl.Expression {
	if expr == nil || key == cty.NilVal || !key.IsKnown() || key.IsNull() {
		return nil
	}
	keyPath, ok := relationKeyPath(key)
	if !ok {
		return nil
	}
	switch e := expr.(type) {
	case *hclsyntax.ObjectConsExpr, *hclsyntax.TupleConsExpr:
		return selectRelationExpr(expr, keyPath, ctx)
	case *hclsyntax.ScopeTraversalExpr:
		traversal := slices.Clone(e.Traversal)
		traversal = append(traversal, hcl.TraverseIndex{Key: key})
		return &hclsyntax.ScopeTraversalExpr{Traversal: traversal, SrcRange: e.SrcRange}
	default:
		return nil
	}
}

func relationResourceInstanceKey(iteration map[string]cty.Value) cty.Value {
	if count, ok := iteration[metaArgCount]; ok && count.IsKnown() && !count.IsNull() {
		if count.Type().IsObjectType() && count.Type().HasAttribute("index") {
			return count.GetAttr("index")
		}
	}
	if each, ok := iteration[metaArgEach]; ok && each.IsKnown() && !each.IsNull() {
		if each.Type().IsObjectType() && each.Type().HasAttribute(metaArgKey) {
			return each.GetAttr(metaArgKey)
		}
	}
	return cty.NilVal
}

func ensureResourceRelations(r *policy.Resource) *policy.ResourceRelations {
	if r.Relations == nil {
		r.Relations = &policy.ResourceRelations{
			Targets:   make(map[string]policy.RelationList),
			Related:   make(map[string]map[string]policy.RelationList),
			Referrers: make(map[string]policy.RelationList),
		}
	}
	return r.Relations
}

func appendRelationID(list policy.RelationList, exists bool, id string, scopeComplete, complete bool) policy.RelationList {
	if !exists {
		list.Complete = scopeComplete
	}
	list.IDs = append(list.IDs, id)
	list.Complete = list.Complete && complete
	return list
}

// sortUniqueRelationIDs preserves the sorted relation output while deferring
// duplicate elimination until construction is complete, avoiding linear scans
// of high-fan-in reverse relation lists on every append.
func sortUniqueRelationIDs(ids []string) []string {
	sort.Strings(ids)
	if len(ids) < 2 {
		return ids
	}
	unique := ids[:1]
	for _, id := range ids[1:] {
		if id != unique[len(unique)-1] {
			unique = append(unique, id)
		}
	}
	return unique
}

// relationPaths also indexes a nested attribute without concrete block indices.
// The latter is a union across all blocks, useful for attachment/absence checks.
// Escaped numeric map keys remain properties, never mistaken for array indices.
func relationPaths(path string) []string {
	var parts []string
	start, escaped := 0, false
	for i, ch := range path {
		if ch == '.' && !escaped {
			parts = append(parts, path[start:i])
			start = i + 1
		}
		if ch == '\\' && !escaped {
			escaped = true
		} else {
			escaped = false
		}
	}
	parts = append(parts, path[start:])
	out := parts[:0]
	for _, part := range parts {
		if part == "" || strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			out = append(out, part)
		}
	}
	if without := strings.Join(out, "."); without != path {
		return []string{path, without}
	}
	return []string{path}
}

func addRelationEdge(unit *policy.Unit, src, dst *policy.Resource, attrPath string, complete bool) {
	if src == nil || dst == nil || src.ID == dst.ID {
		return
	}
	sr, dr := ensureResourceRelations(src), ensureResourceRelations(dst)
	for _, path := range relationPaths(attrPath) {
		tl, exists := sr.Targets[path]
		sr.Targets[path] = appendRelationID(tl, exists, dst.ID, unit.ScopeComplete, complete)
		if dr.Related[src.BucketKey()] == nil {
			dr.Related[src.BucketKey()] = make(map[string]policy.RelationList)
		}
		rl, exists := dr.Related[src.BucketKey()][path]
		dr.Related[src.BucketKey()][path] = appendRelationID(rl, exists, src.ID, unit.ScopeComplete, complete)
		rf, exists := dr.Referrers[path]
		dr.Referrers[path] = appendRelationID(rf, exists, src.ID, unit.ScopeComplete, complete)
	}
}

func addTargetAttributeEdge(unit *policy.Unit, src, dst *policy.Resource, path, attr string, complete bool) {
	if attr == "" || src.ID == dst.ID {
		return
	}
	relations := ensureResourceRelations(src)
	if relations.TargetsVia == nil {
		relations.TargetsVia = make(map[string]map[string]policy.RelationList)
	}
	for _, key := range relationPaths(path) {
		if relations.TargetsVia[key] == nil {
			relations.TargetsVia[key] = make(map[string]policy.RelationList)
		}
		list, exists := relations.TargetsVia[key][attr]
		relations.TargetsVia[key][attr] = appendRelationID(list, exists, dst.ID, unit.ScopeComplete, complete)
	}
}

func statePathPrefixes(path string) []string {
	var prefixes []string
	escaped := false
	for i, ch := range path {
		if ch == '.' && !escaped {
			prefixes = append(prefixes, path[:i])
		}
		if ch == '\\' && !escaped {
			escaped = true
		} else {
			escaped = false
		}
	}
	prefixes = append(prefixes, path)
	return prefixes
}

func statePathContains(state map[string]bool, path string) bool {
	if state[""] {
		return true
	}
	for _, prefix := range statePathPrefixes(path) {
		if state[prefix] {
			return true
		}
	}
	return false
}

func markTargetIncomplete(src *policy.Resource, attrPath string) {
	sr := ensureResourceRelations(src)
	for _, path := range relationPaths(attrPath) {
		tl := sr.Targets[path]
		tl.Complete = false
		sr.Targets[path] = tl
	}
}

func markReverseIncomplete(dst *policy.Resource, compType, attrPath string) {
	dr := ensureResourceRelations(dst)
	if dr.Related[compType] == nil {
		dr.Related[compType] = make(map[string]policy.RelationList)
	}
	for _, path := range relationPaths(attrPath) {
		rl := dr.Related[compType][path]
		rl.Complete = false
		dr.Related[compType][path] = rl
		rf := dr.Referrers[path]
		rf.Complete = false
		dr.Referrers[path] = rf
	}
}

// Literal names identify resources only within one provider configuration.
// S3 bucket names are globally unique, so their companions are the exception.
// Explicit Terraform references are authoritative and do not use this filter.
func literalScopeMatches(src, dst *policy.Resource) bool {
	if dst.Type == typeS3Bucket {
		return true
	}
	return literalProviderID(src) == literalProviderID(dst)
}

func literalProviderID(res *policy.Resource) string {
	tf, _ := res.Platform[terraformPlatform].(map[string]any)
	id, _ := tf["provider_id"].(string)
	return id
}

type literalUncertaintyKey struct {
	sourceType, sourcePath, targetType, targetAttr, provider string
}

// A concrete source string may still name a target whose configured identity
// is unknown. Preserve uncertainty in both directions without inventing an edge.
// Reverse uncertainty depends on source type/path and provider, so memoize it
// instead of revisiting every unknown target for every source resource.
func markUnknownLiteralTargets(
	src *policy.Resource, path string, values []string, targetType, targetAttr string,
	candidates []*policy.Resource, cache map[literalUncertaintyKey]bool,
) bool {
	if len(values) == 0 || len(candidates) == 0 {
		return false
	}
	provider := literalProviderID(src)
	if targetType == typeS3Bucket {
		provider = ""
	}
	key := literalUncertaintyKey{src.BucketKey(), path, targetType, targetAttr, provider}
	incomplete, cached := cache[key]
	if !cached {
		for _, dst := range candidates {
			if !literalScopeMatches(src, dst) {
				continue
			}
			markReverseIncomplete(dst, src.BucketKey(), path)
			incomplete = true
		}
		cache[key] = incomplete
	}
	if incomplete {
		markTargetIncomplete(src, path)
	}
	return incomplete
}

func recordTargetLiteral(index map[string]map[string]map[string][]*policy.Resource, res *policy.Resource, attr string) {
	s, ok := res.Attributes[attr].(string)
	if !ok || s == "" {
		return
	}
	if index[res.Type] == nil {
		index[res.Type] = map[string]map[string][]*policy.Resource{}
	}
	if index[res.Type][attr] == nil {
		index[res.Type][attr] = map[string][]*policy.Resource{}
	}
	index[res.Type][attr][s] = append(index[res.Type][attr][s], res)
}

func propagateIncompleteCompanions(
	unit *policy.Unit,
	incompleteCompanion map[[2]string]bool,
	literalKeys LiteralKeyMap,
) {
	propagateIncompleteCompanionsContext(context.Background(), unit, incompleteCompanion, literalKeys)
}

func propagateIncompleteCompanionsContext(
	ctx context.Context,
	unit *policy.Unit,
	incompleteCompanion map[[2]string]bool,
	literalKeys LiteralKeyMap,
) {
	for pair := range incompleteCompanion {
		if ctx.Err() != nil {
			return
		}
		compType, attrPath := pair[0], pair[1]
		byTarget := literalKeys[compType][attrPath]
		narrowToTargets := len(byTarget) > 0
		for i, res := range unit.Resources {
			if i%64 == 0 && ctx.Err() != nil {
				return
			}
			if res.Kind != address.KindResource {
				continue
			}
			if narrowToTargets {
				if _, relevant := byTarget[res.Type]; !relevant {
					continue
				}
			}
			markReverseIncomplete(res, compType, attrPath)
		}
	}
}

func sortUnitRelations(unit *policy.Unit) {
	for _, r := range unit.Resources {
		if r.Relations == nil {
			continue
		}
		for k, rl := range r.Relations.Targets {
			rl.IDs = sortUniqueRelationIDs(rl.IDs)
			r.Relations.Targets[k] = rl
		}
		for _, byPath := range r.Relations.TargetsVia {
			for k, rl := range byPath {
				rl.IDs = sortUniqueRelationIDs(rl.IDs)
				byPath[k] = rl
			}
		}
		for _, byPath := range r.Relations.Related {
			for k, rl := range byPath {
				rl.IDs = sortUniqueRelationIDs(rl.IDs)
				byPath[k] = rl
			}
		}
		for k, rl := range r.Relations.Referrers {
			rl.IDs = sortUniqueRelationIDs(rl.IDs)
			r.Relations.Referrers[k] = rl
		}
	}
}

// buildIntraRootRelations resolves HCL references and same-root literal key
// matches into Targets, Related, and Referrers on each resource of unit.
// nolint:gocyclo
func buildIntraRootRelations(
	ctx context.Context,
	unit *policy.Unit,
	metas []*hclResourceMeta,
	literalKeys LiteralKeyMap,
	instances []tfeval.ModuleInstance,
) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil || unit == nil || len(metas) == 0 {
		return
	}
	if literalKeys == nil {
		literalKeys = DefaultLiteralKeys
	}

	trace := newRelationTrace(metas, instances)
	walkCache := newRelationWalkCache()
	byTargetLiteral := make(map[string]map[string]map[string][]*policy.Resource)
	unknownTargetLiteral := make(map[string]map[string][]*policy.Resource)
	uncertainLiterals := make(map[literalUncertaintyKey]bool)

	// Collect which target types/attrs participate in literal matching.
	targetAttrs := make(map[string]map[string]bool)
	for _, byPath := range literalKeys {
		for _, byTarget := range byPath {
			for tType, attrs := range byTarget {
				if targetAttrs[tType] == nil {
					targetAttrs[tType] = make(map[string]bool)
				}
				for _, a := range attrs {
					targetAttrs[tType][a] = true
				}
			}
		}
	}

	for i, m := range metas {
		if i%64 == 0 && ctx.Err() != nil {
			return
		}
		if m.res.Kind == address.KindResource {
			if wantedAttrs, ok := targetAttrs[m.res.Type]; ok {
				for attr := range wantedAttrs {
					if statePathContains(m.res.State.Unknown, policy.EscapeStep(policy.Key(attr))) {
						if unknownTargetLiteral[m.res.Type] == nil {
							unknownTargetLiteral[m.res.Type] = map[string][]*policy.Resource{}
						}
						unknownTargetLiteral[m.res.Type][attr] = append(unknownTargetLiteral[m.res.Type][attr], m.res)
						continue
					}
					recordTargetLiteral(byTargetLiteral, m.res, attr)
				}
			}
		}
	}

	// Track which (companionType, attrPath) have an unknown/untraced companion
	// in this root so target resources mark their reverse related/referrers
	// lists as Complete = false.
	incompleteCompanion := make(map[[2]string]bool)

	for i, m := range metas {
		if i%64 == 0 && ctx.Err() != nil {
			return
		}
		if m.body == nil {
			continue
		}
		eachCall := &relationCall{
			parent: m.moduleAddr,
			site: tfeval.CallSite{
				Body:        m.body,
				Caller:      m.scope,
				InstanceKey: relationResourceInstanceKey(m.iteration),
			},
		}
		var evalCtx *hcl.EvalContext
		getEvalCtx := func() *hcl.EvalContext {
			if evalCtx == nil {
				if m.scope != nil {
					evalCtx = m.scope.EvalContext()
				}
				if evalCtx == nil {
					evalCtx = &hcl.EvalContext{}
				}
				if len(m.iteration) > 0 {
					child := evalCtx.NewChild()
					child.Variables = m.iteration
					evalCtx = child
				}
			}
			return evalCtx
		}

		walkBodyAttrRefsCached(
			ctx, walkCache, m.body, m.dynCounts, "", getEvalCtx, false,
			func(attrPath string, expr hcl.Expression, exprEvalCtx func() *hcl.EvalContext, uncertainOnly bool) {
				sourceEvalCtx := exprEvalCtx
				if m.resolved != nil && expr != nil {
					sourceEvalCtx = func() *hcl.EvalContext {
						return m.resolved.EvalContextForFile(expr.Range().Filename, exprEvalCtx())
					}
				}
				matchedAny := false
				attrComplete := unit.ScopeComplete && !m.keyUnknown
				resolved, hasUntraced := resolveExprTargets(expr, m.moduleAddr, m.scope, sourceEvalCtx, trace, 0, eachCall)
				if uncertainOnly {
					// Unresolved dynamic block (n < 0): never invent definite edges,
					// but propagate uncertainty to both forward targets and reverse
					// referrers/related lists so absence helpers fail closed.
					if len(resolved) > 0 || hasUntraced || m.res.State.Unknown[attrPath] || m.res.State.IncompleteCollections[attrPath] {
						markTargetIncomplete(m.res, attrPath)
						for _, target := range resolved {
							if target.res != nil && target.res.ID != m.res.ID {
								markReverseIncomplete(target.res, m.res.BucketKey(), attrPath)
							}
						}
						if (hasUntraced || len(resolved) == 0) && m.res.Kind == address.KindResource {
							incompleteCompanion[[2]string{m.res.BucketKey(), attrPath}] = true
						}
					}
					return
				}
				// A direct resource reference (e.g. bucket = aws_s3_bucket.logs.id)
				// has an unknown runtime value until apply, yet its structural target
				// is completely resolved when len(resolved) > 0 && !hasUntraced.
				missingExplicitTarget := onlyMissingExplicitResourceRefs(expr, m.moduleAddr, sourceEvalCtx, trace)
				unresolvedUnknown := len(resolved) == 0 && (statePathContains(m.res.State.Unknown, attrPath) ||
					statePathContains(m.res.State.IncompleteCollections, attrPath))
				if hasUntraced || unresolvedUnknown {
					attrComplete = false
					if m.res.Kind == address.KindResource && (!missingExplicitTarget || hasUntraced) {
						incompleteCompanion[[2]string{m.res.BucketKey(), attrPath}] = true
					}
				}
				for i, target := range resolved {
					if i%64 == 0 && ctx.Err() != nil {
						return
					}
					matchedAny = true
					edgeComplete := attrComplete && !target.keyUnknown
					addRelationEdge(unit, m.res, target.res, attrPath, edgeComplete)
					addTargetAttributeEdge(unit, m.res, target.res, attrPath, target.readPath, edgeComplete)
				}

				// Same-root literal key matching (always runs for known literal key
				// attributes so mixed ref+literal lists link every concrete target).
				if byPath, ok := literalKeys[m.res.Type]; ok {
					if byTarget, ok := byPath[attrPath]; ok {
						vals, isUnknown := extractStringValues(m.res, attrPath)
						literalUnresolved := (isUnknown && len(resolved) == 0 && !missingExplicitTarget) ||
							hasUntraced || m.keyUnknown
						if literalUnresolved {
							incompleteCompanion[[2]string{m.res.BucketKey(), attrPath}] = true
							attrComplete = false
						}
						for tType, tAttrs := range byTarget {
							for _, tAttr := range tAttrs {
								if markUnknownLiteralTargets(
									m.res, attrPath, vals, tType, tAttr,
									unknownTargetLiteral[tType][tAttr], uncertainLiterals,
								) {
									attrComplete = false
								}
								for _, val := range vals {
									for _, dst := range byTargetLiteral[tType][tAttr][val] {
										if !literalScopeMatches(m.res, dst) {
											continue
										}
										matchedAny = true
										addRelationEdge(unit, m.res, dst, attrPath, attrComplete)
										addTargetAttributeEdge(unit, m.res, dst, attrPath, tAttr, attrComplete)
									}
								}
							}
						}
					}
				}

				if !attrComplete && (matchedAny || hasUntraced || unresolvedUnknown) {
					markTargetIncomplete(m.res, attrPath)
				} else if !matchedAny && attrComplete && statePathContains(m.res.State.Written, attrPath) &&
					!statePathContains(m.res.State.Unknown, attrPath) {
					// Written concrete attribute with no unresolved refs: record Complete = true.
					sr := ensureResourceRelations(m.res)
					if _, exists := sr.Targets[attrPath]; !exists {
						sr.Targets[attrPath] = policy.RelationList{Complete: unit.ScopeComplete}
					}
				}
			}, m.resolved)
		if ctx.Err() != nil {
			return
		}
	}

	propagateIncompleteCompanionsContext(ctx, unit, incompleteCompanion, literalKeys)
	if ctx.Err() != nil {
		return
	}
	sortUnitRelations(unit)
}

func onlyMissingExplicitResourceRefs(
	expr hcl.Expression,
	moduleAddr string,
	getEvalCtx func() *hcl.EvalContext,
	trace *relationTrace,
) bool {
	allRefs := refs.Of(expr)
	if len(allRefs) == 0 {
		return false
	}
	for i := range allRefs {
		ref := &allRefs[i]
		kind := ""
		switch ref.Kind {
		case refs.KindResource:
			kind = address.KindResource
		case refs.KindData:
			kind = address.KindData
		case refs.KindEphemeral:
			kind = address.KindEphemeral
		default:
			return false
		}
		if ref.DynamicKey {
			return false
		}
		list := trace.byBlock[blockIdentityKey{
			moduleAddr: moduleAddr,
			kind:       kind,
			typ:        ref.Type,
			name:       ref.Name,
		}]
		matched, untraced := matchRefInstances(list, ref, getEvalCtx)
		if untraced || len(matched) > 0 {
			return false
		}
	}
	return true
}

// walkNestedExprRefs emits leaf paths for literal object and tuple values
// while retaining the aggregate edge emitted for their parent attribute.
// Unknown object keys have no stable leaf path, so only the aggregate is kept.
func walkNestedExprRefs(
	cancel context.Context,
	expr hcl.Expression,
	prefix string,
	getEvalCtx func() *hcl.EvalContext,
	uncertainOnly bool,
	fn func(attrPath string, expr hcl.Expression, exprEvalCtx func() *hcl.EvalContext, uncertainOnly bool),
	depth int,
) {
	if expr == nil || depth >= maxLocalAliasDepth || cancel.Err() != nil {
		return
	}
	ctx := (*hcl.EvalContext)(nil)
	if getEvalCtx != nil {
		ctx = getEvalCtx()
	}
	switch value := expr.(type) {
	case *hclsyntax.ParenthesesExpr:
		walkNestedExprRefs(cancel, value.Expression, prefix, getEvalCtx, uncertainOnly, fn, depth+1)
	case *hclsyntax.ObjectConsExpr:
		for _, item := range value.Items {
			key, ok := knownStringObjectKey(item.KeyExpr, ctx)
			if !ok {
				continue
			}
			path := policy.JoinPathKey(prefix, policy.Key(key))
			if !walkNestedExprElement(cancel, item.ValueExpr, path, getEvalCtx, uncertainOnly, fn, depth) {
				return
			}
		}
	case *hclsyntax.TupleConsExpr:
		for i, child := range value.Exprs {
			path := policy.JoinPathKey(prefix, policy.Index(int64(i)))
			if !walkNestedExprElement(cancel, child, path, getEvalCtx, uncertainOnly, fn, depth) {
				return
			}
		}
	}
}

// knownStringObjectKey evaluates an object key that names a stable leaf path.
func knownStringObjectKey(expr hcl.Expression, ctx *hcl.EvalContext) (string, bool) {
	key, diags := expr.Value(ctx)
	if diags.HasErrors() || !key.IsKnown() || key.IsNull() || key.Type() != cty.String {
		return "", false
	}
	return key.AsString(), true
}

// walkNestedExprElement visits one object or tuple element and its leaves. It
// returns false, visiting nothing, once cancel is done.
func walkNestedExprElement(
	cancel context.Context,
	expr hcl.Expression,
	path string,
	getEvalCtx func() *hcl.EvalContext,
	uncertainOnly bool,
	fn func(attrPath string, expr hcl.Expression, exprEvalCtx func() *hcl.EvalContext, uncertainOnly bool),
	depth int,
) bool {
	if cancel.Err() != nil {
		return false
	}
	fn(path, expr, getEvalCtx, uncertainOnly)
	walkNestedExprRefs(cancel, expr, path, getEvalCtx, uncertainOnly, fn, depth+1)
	return true
}

type relationWalkEvent struct {
	attrPath string
	expr     hcl.Expression
}

type relationWalkCache struct {
	mu          sync.Mutex
	byBody      map[*hclsyntax.Body][]relationWalkEvent
	uncacheable map[*hclsyntax.Body]struct{}
}

func newRelationWalkCache() *relationWalkCache {
	return &relationWalkCache{
		byBody:      make(map[*hclsyntax.Body][]relationWalkEvent),
		uncacheable: make(map[*hclsyntax.Body]struct{}),
	}
}

// events returns body's cached static walk. It returns false when body needs
// the per-scope walker or ctx was canceled while the walk was collected; a
// canceled collection is neither cached nor marked uncacheable.
func (c *relationWalkCache) events(ctx context.Context, body *hclsyntax.Body) ([]relationWalkEvent, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if events, ok := c.byBody[body]; ok {
		return events, true
	}
	if _, ok := c.uncacheable[body]; ok {
		return nil, false
	}
	events, ok := collectStaticRelationWalk(ctx, body)
	if ctx.Err() != nil {
		return nil, false
	}
	if !ok {
		c.uncacheable[body] = struct{}{}
		return nil, false
	}
	c.byBody[body] = events
	return events, true
}

// walkBodyAttrRefsCached calls fn for every attribute of body, like
// walkBodyAttrRefs, and stops as soon as ctx is canceled.
func walkBodyAttrRefsCached(
	ctx context.Context,
	cache *relationWalkCache,
	body *hclsyntax.Body,
	dynCounts tfeval.DynamicCounts,
	prefix string,
	getEvalCtx func() *hcl.EvalContext,
	uncertainOnly bool,
	fn func(attrPath string, expr hcl.Expression, exprEvalCtx func() *hcl.EvalContext, uncertainOnly bool),
	resolved *tfeval.ResolvedResource,
) {
	if cache == nil || uncertainOnly {
		walkBodyAttrRefs(ctx, body, dynCounts, prefix, getEvalCtx, uncertainOnly, fn, resolved)
		return
	}
	events, ok := cache.events(ctx, body)
	if ctx.Err() != nil {
		return
	}
	if !ok {
		walkBodyAttrRefs(ctx, body, dynCounts, prefix, getEvalCtx, uncertainOnly, fn, resolved)
		return
	}
	for _, event := range events {
		if ctx.Err() != nil {
			return
		}
		attrPath := event.attrPath
		if prefix != "" {
			attrPath = prefix + "." + attrPath
		}
		fn(attrPath, event.expr, getEvalCtx, false)
	}
}

// collectStaticRelationWalk returns false when body needs the per-scope walker
// or ctx is canceled (callers tell them apart with ctx.Err()).
func collectStaticRelationWalk(ctx context.Context, body *hclsyntax.Body) ([]relationWalkEvent, bool) {
	var events []relationWalkEvent
	var collectBody func(*hclsyntax.Body, string) bool
	collectBody = func(current *hclsyntax.Body, prefix string) bool {
		if current == nil {
			return true
		}
		for name, attr := range current.Attributes {
			if ctx.Err() != nil {
				return false
			}
			if prefix == "" && resourceMetaArgs[name] {
				continue
			}
			attrPath := policy.JoinPathKey(prefix, policy.Key(name))
			events = append(events, relationWalkEvent{attrPath: attrPath, expr: attr.Expr})
			if !collectNestedRelationWalk(ctx, attr.Expr, attrPath, &events, 0) {
				return false
			}
		}
		idxByType := make(map[string]int)
		for _, block := range current.Blocks {
			if block.Type == blockTypeDynamic || ctx.Err() != nil {
				return false
			}
			if prefix == "" && resourceMetaArgs[block.Type] {
				continue
			}
			pos := idxByType[block.Type]
			idxByType[block.Type] = pos + 1
			nextPrefix := policy.JoinPathKey(policy.JoinPathKey(prefix, policy.Key(block.Type)), policy.Index(int64(pos)))
			if !collectBody(block.Body, nextPrefix) {
				return false
			}
		}
		return true
	}
	return events, collectBody(body, "")
}

func collectNestedRelationWalk(
	ctx context.Context,
	expr hcl.Expression,
	prefix string,
	events *[]relationWalkEvent,
	depth int,
) bool {
	if expr == nil || depth >= maxLocalAliasDepth {
		return true
	}
	switch value := expr.(type) {
	case *hclsyntax.ParenthesesExpr:
		return collectNestedRelationWalk(ctx, value.Expression, prefix, events, depth+1)
	case *hclsyntax.ObjectConsExpr:
		for _, item := range value.Items {
			key, ok := knownStringObjectKey(item.KeyExpr, nil)
			if !ok {
				return false
			}
			path := policy.JoinPathKey(prefix, policy.Key(key))
			if !collectNestedRelationElement(ctx, item.ValueExpr, path, events, depth) {
				return false
			}
		}
	case *hclsyntax.TupleConsExpr:
		for i, child := range value.Exprs {
			path := policy.JoinPathKey(prefix, policy.Index(int64(i)))
			if !collectNestedRelationElement(ctx, child, path, events, depth) {
				return false
			}
		}
	}
	return true
}

// collectNestedRelationElement records one object or tuple element and its
// leaves. It returns false once ctx is done or the element is not static.
func collectNestedRelationElement(
	ctx context.Context,
	expr hcl.Expression,
	path string,
	events *[]relationWalkEvent,
	depth int,
) bool {
	if ctx.Err() != nil {
		return false
	}
	*events = append(*events, relationWalkEvent{attrPath: path, expr: expr})
	return collectNestedRelationWalk(ctx, expr, path, events, depth+1)
}

//nolint:gocyclo
func walkBodyAttrRefs(
	cancel context.Context,
	body *hclsyntax.Body,
	dynCounts tfeval.DynamicCounts,
	prefix string,
	getEvalCtx func() *hcl.EvalContext,
	uncertainOnly bool,
	fn func(attrPath string, expr hcl.Expression, exprEvalCtx func() *hcl.EvalContext, uncertainOnly bool),
	resolved *tfeval.ResolvedResource,
) {
	if body == nil {
		return
	}
	for name, attr := range body.Attributes {
		if cancel.Err() != nil {
			return
		}
		if prefix == "" && resourceMetaArgs[name] {
			continue
		}
		attrPath := policy.JoinPathKey(prefix, policy.Key(name))
		fn(attrPath, attr.Expr, getEvalCtx, uncertainOnly)
		walkNestedExprRefs(cancel, attr.Expr, attrPath, getEvalCtx, uncertainOnly, fn, 0)
	}
	idxByType := map[string]int{}
	for _, blk := range body.Blocks {
		if cancel.Err() != nil {
			return
		}
		if blk.Type == blockTypeDynamic {
			if !dynamicblock.Is(blk) {
				continue
			}
			genType := dynamicblock.GeneratedType(blk)
			if genType == "" || (prefix == "" && resourceMetaArgs[genType]) {
				continue
			}
			n := 0
			if dynCounts != nil {
				n = dynCounts[blk]
			}
			if n == 0 {
				// Known 0 expanded instances: fast-path skip without advancing indices.
				continue
			}
			content := dynamicblock.Content(blk)
			if n < 0 {
				// Unresolved dynamic block (DynamicKeptAsWritten): do not advance
				// concrete block indices so trailing static blocks stay aligned,
				// but walk content in uncertainty-only mode so potential targets
				// and referrers are marked incomplete without inventing edges.
				if content != nil {
					nextPrefix := policy.JoinPathKey(policy.JoinPathKey(prefix, policy.Key(genType)), policy.Index(int64(idxByType[genType])))
					walkBodyAttrRefs(cancel, content, dynCounts, nextPrefix, getEvalCtx, true, fn, resolved)
				}
				continue
			}
			var exp dynamicblock.Expansion
			if getEvalCtx != nil {
				ctx := getEvalCtx()
				if resolved != nil {
					if attr := blk.Body.Attributes["for_each"]; attr != nil {
						ctx = resolved.EvalContextForFile(attr.Expr.Range().Filename, ctx)
					}
				}
				exp = dynamicblock.Expand(cancel, blk, ctx)
			}
			iterName := dynamicblock.IteratorName(blk)
			for i := range n {
				if cancel.Err() != nil {
					return
				}
				pos := idxByType[genType]
				idxByType[genType] = pos + 1
				if content != nil {
					nextPrefix := policy.JoinPathKey(policy.JoinPathKey(prefix, policy.Key(genType)), policy.Index(int64(pos)))
					iterCtxFn := getEvalCtx
					if exp.Resolved && i < len(exp.Iterators) && getEvalCtx != nil {
						iterVal := exp.Iterators[i]
						parentFn := getEvalCtx
						var cached *hcl.EvalContext
						iterCtxFn = func() *hcl.EvalContext {
							if cached == nil {
								base := parentFn()
								if base == nil {
									base = &hcl.EvalContext{}
								}
								child := base.NewChild()
								child.Variables = map[string]cty.Value{iterName: iterVal}
								cached = child
							}
							return cached
						}
					}
					walkBodyAttrRefs(cancel, content, dynCounts, nextPrefix, iterCtxFn, uncertainOnly, fn, resolved)
				}
			}
			continue
		}
		if prefix == "" && resourceMetaArgs[blk.Type] {
			continue
		}
		pos := idxByType[blk.Type]
		idxByType[blk.Type] = pos + 1
		nextPrefix := policy.JoinPathKey(policy.JoinPathKey(prefix, policy.Key(blk.Type)), policy.Index(int64(pos)))
		walkBodyAttrRefs(cancel, blk.Body, dynCounts, nextPrefix, getEvalCtx, uncertainOnly, fn, resolved)
	}
}

// nolint:gocyclo
func resolveExprTargets(
	expr hcl.Expression,
	moduleAddr string,
	scope *tfeval.ModuleScope,
	getEvalCtx func() *hcl.EvalContext,
	trace *relationTrace,
	depth int,
	eachCall *relationCall,
) (targets []*hclResourceMeta, hasUntraced bool) {
	if expr == nil || depth > maxLocalAliasDepth {
		return nil, false
	}
	matchBlock := func(kind string, r *refs.Ref) {
		list := trace.byBlock[blockIdentityKey{
			moduleAddr: moduleAddr,
			kind:       kind,
			typ:        r.Type,
			name:       r.Name,
		}]
		matched, untraced := matchRefInstances(list, r, getEvalCtx)
		for _, target := range matched {
			copy := *target
			copy.readPath = r.ReadPath()
			targets = append(targets, &copy)
		}
		if untraced {
			hasUntraced = true
		}
	}
	for _, r := range refs.Of(expr) {
		switch r.Kind {
		case refs.KindResource:
			matchBlock(address.KindResource, &r)
		case refs.KindData:
			matchBlock(address.KindData, &r)
		case refs.KindEphemeral:
			matchBlock(address.KindEphemeral, &r)
		case refs.KindLocal:
			if scope != nil && scope.Locals != nil {
				if localExpr, ok := scope.Locals[r.Name]; ok {
					localExpr, selected := selectRelationRef(localExpr, &r, getEvalCtx())
					if !selected {
						hasUntraced = true
						continue
					}
					sub, subUntraced := resolveExprTargets(localExpr, moduleAddr, scope, getEvalCtx, trace, depth+1, eachCall)
					targets = append(targets, sub...)
					hasUntraced = hasUntraced || subUntraced
					continue
				}
			}
			hasUntraced = true
		case refs.KindVar:
			call, ok := trace.calls[moduleAddr]
			if ok && call.site.Body != nil {
				if arg := call.site.Body.Attributes[r.Name]; arg != nil {
					ctx := call.context()
					selected, ok := selectRelationRef(arg.Expr, &r, ctx)
					if ok {
						sub, incomplete := resolveCallInputTargets(selected, &call, trace, depth+1)
						targets = append(targets, sub...)
						hasUntraced = hasUntraced || incomplete
						continue
					}
				}
			}
			if !ok && moduleAddr == "" && getEvalCtx != nil {
				traversal := &hclsyntax.ScopeTraversalExpr{Traversal: r.Traversal}
				if value, diags := traversal.Value(getEvalCtx()); !diags.HasErrors() && value.IsKnown() {
					// A known root variable can select a local collection element, but
					// it cannot itself introduce a resource edge.
					continue
				}
			}
			hasUntraced = true
		case refs.KindEach:
			if eachCall == nil {
				hasUntraced = true
				continue
			}
			sub, incomplete := resolveEachInputRef(&r, eachCall, trace, depth+1)
			targets = append(targets, sub...)
			hasUntraced = hasUntraced || incomplete
		case refs.KindModule:
			key := r.Key
			if key == nil && r.DynamicKey && r.KeyExpr != nil && getEvalCtx != nil {
				if v, diags := r.KeyExpr.Value(getEvalCtx()); !diags.HasErrors() && v.IsKnown() && !v.IsNull() {
					key = &v
				}
			}
			if r.DynamicKey && key == nil {
				hasUntraced = true
				continue
			}
			read := strings.Split(r.ReadPath(), ".")
			matched := false
			for addr := range trace.calls {
				call := trace.calls[addr]
				if call.parent != moduleAddr || call.site.ModuleName != r.Name {
					continue
				}
				if key != nil && !call.site.InstanceKey.RawEquals(*key) {
					continue
				}
				child := trace.scopes[addr]
				if child == nil {
					continue
				}
				for _, body := range child.Bodies {
					for _, block := range body.Blocks {
						if block.Type != "output" || len(block.Labels) != 1 || block.Labels[0] != read[0] {
							continue
						}
						if value := block.Body.Attributes["value"]; value != nil {
							selected := selectRelationExpr(value.Expr, strings.Join(read[1:], "."), child.EvalContext())
							if selected != nil {
								matched = true
								sub, incomplete := resolveExprTargets(selected, addr, child, child.EvalContext, trace, depth+1, nil)
								targets = append(targets, sub...)
								hasUntraced = hasUntraced || incomplete
							}
						}
					}
				}
			}
			hasUntraced = hasUntraced || !matched
		}
	}
	return targets, hasUntraced
}

// resolveCallInputTargets resolves one module call argument. Terraform's each.value
// is the selected for_each element, so project that concrete entry before tracing
// its references; unresolved shapes stay incomplete rather than joining siblings.
func resolveCallInputTargets(
	expr hcl.Expression,
	call *relationCall,
	trace *relationTrace,
	depth int,
) (targets []*hclResourceMeta, hasUntraced bool) {
	if expr == nil || depth > maxLocalAliasDepth {
		return nil, false
	}
	for _, ref := range refs.Of(expr) {
		matched, incomplete := resolveCallInputRef(&ref, call, trace, depth+1)
		targets = append(targets, matched...)
		hasUntraced = hasUntraced || incomplete
	}
	return targets, hasUntraced
}

func resolveCallInputRef(ref *refs.Ref, call *relationCall, trace *relationTrace, depth int) ([]*hclResourceMeta, bool) {
	if ref.Kind == refs.KindEach {
		return resolveEachInputRef(ref, call, trace, depth)
	}
	traversal := &hclsyntax.ScopeTraversalExpr{Traversal: ref.Traversal}
	return resolveExprTargets(traversal, call.parent, call.site.Caller, call.site.Caller.EvalContext, trace, depth+1, nil)
}

func resolveEachInputRef(ref *refs.Ref, call *relationCall, trace *relationTrace, depth int) ([]*hclResourceMeta, bool) {
	path := strings.Split(ref.ReadPath(), ".")
	if len(path) == 0 || path[0] != metaArgValue || call.site.InstanceKey == cty.NilVal || call.site.Body == nil {
		return nil, true
	}
	forEach := call.site.Body.Attributes["for_each"]
	if forEach == nil {
		return nil, true
	}
	ctx := call.site.Caller.EvalContext()
	selected := selectRelationExprAtKey(forEach.Expr, call.site.InstanceKey, ctx)
	if selected == nil {
		return nil, true
	}
	if len(path) > 1 {
		selected = selectRelationExpr(selected, strings.Join(path[1:], "."), ctx)
		if selected == nil {
			return nil, true
		}
	}
	return resolveExprTargets(selected, call.parent, call.site.Caller, call.site.Caller.EvalContext, trace, depth+1, nil)
}

func matchRefInstances(
	list []*hclResourceMeta,
	r *refs.Ref,
	getEvalCtx func() *hcl.EvalContext,
) (matched []*hclResourceMeta, untraced bool) {
	if len(list) == 0 {
		return nil, r.DynamicKey
	}
	keyVal := r.Key
	if keyVal == nil && r.DynamicKey && r.KeyExpr != nil && getEvalCtx != nil {
		if v, diags := r.KeyExpr.Value(getEvalCtx()); !diags.HasErrors() && v != cty.NilVal && v.IsKnown() && !v.IsNull() {
			keyVal = &v
		}
	}
	if keyVal == nil {
		if r.DynamicKey {
			return nil, true
		}
		return list, false
	}
	wantSuffix := formatInstanceKey(*keyVal)
	if wantSuffix == "" {
		return list, r.DynamicKey
	}
	for _, m := range list {
		if strings.HasSuffix(m.res.Address, wantSuffix) {
			matched = append(matched, m)
		}
	}
	return matched, false
}

func extractStringValues(res *policy.Resource, attrPath string) (vals []string, isUnknown bool) {
	if res.State.Unknown[attrPath] || res.State.IncompleteCollections[attrPath] {
		isUnknown = true
	}
	raw, ok := res.Attributes[attrPath]
	if !ok {
		return nil, isUnknown
	}
	switch v := raw.(type) {
	case string:
		if v != "" {
			return []string{v}, isUnknown
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				vals = append(vals, s)
			}
		}
	}
	return vals, isUnknown
}
