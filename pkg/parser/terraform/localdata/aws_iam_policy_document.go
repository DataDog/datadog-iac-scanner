/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package localdata

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// awsIAMPolicyDocumentType is the AWS data source that renders an IAM policy.
const awsIAMPolicyDocumentType = "aws_iam_policy_document"

const (
	// defaultPolicyVersion is the policy language version the provider defaults to.
	defaultPolicyVersion = "2012-10-17"
	defaultPolicyEffect  = "Allow"
)

// policyStatement is one policy statement.
type policyStatement struct {
	Sid           string
	Effect        string
	Actions       []string
	NotActions    []string
	Resources     []string
	NotResources  []string
	Principals    map[string][]string
	NotPrincipals map[string][]string
	Condition     map[string]map[string][]string
}

// policyDocument is a rendered policy document.
type policyDocument struct {
	ID         string
	Version    string
	Statements []policyStatement
	// Incomplete is set when a dynamic block of the document could not be
	// expanded, so Statements may lack some it declares.
	Incomplete bool
}

var documentSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "id"},
		{Name: "policy_id"},
		{Name: "version"},
		{Name: "source_policy_documents"},
		{Name: "override_policy_documents"},
		{Name: "source_json"},
		{Name: "override_json"},
	},
	Blocks: []hcl.BlockHeaderSchema{{Type: "statement"}, dynamicHeader},
}

var statementSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "sid"},
		{Name: "effect"},
		{Name: "actions"},
		{Name: "not_actions"},
		{Name: "resources"},
		{Name: "not_resources"},
	},
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "principals"},
		{Type: "not_principals"},
		{Type: "condition"},
		dynamicHeader,
	},
}

var principalSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "type"}, {Name: "identifiers"}},
}

var conditionSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "test"}, {Name: "variable"}, {Name: "values"}},
}

// policyDocumentAttributes renders the json and minified_json attributes; the
// two only differ in whitespace, which rules do not read.
func policyDocumentAttributes(body hcl.Body, eval EvalFunc) map[string]string {
	policy, ok := decodePolicyDocument(body, eval)
	// Any unresolved dynamic or source/override leaves the document incomplete,
	// so emitting a partial policy would mislead rules.
	if !ok || policy.Incomplete {
		return nil
	}
	out, err := policy.render()
	if err != nil {
		return nil
	}
	return map[string]string{"json": out, "minified_json": out}
}

// decodePolicyDocument reads the policy an aws_iam_policy_document body
// declares, merging the source and override documents it names the way
// Terraform does. Arguments the data source does not define, and values eval
// cannot resolve, are left out rather than discarding the document. ok is
// false when a named source or override document could not be read.
func decodePolicyDocument(body hcl.Body, eval EvalFunc) (policyDocument, bool) {
	content, _, _ := body.PartialContent(documentSchema)
	if content == nil {
		return policyDocument{}, true
	}
	d := newDecoder(eval)
	own := policyDocument{
		ID:      d.str(content.Attributes["policy_id"]),
		Version: d.str(content.Attributes["version"]),
	}
	if own.ID == "" {
		own.ID = d.str(content.Attributes["id"])
	}
	// Match the provider schema default so an unset own version upgrades
	// sources the same way Terraform does.
	if own.Version == "" {
		own.Version = defaultPolicyVersion
	}
	for _, block := range d.blocks(content, "statement") {
		own.Statements = append(own.Statements, block.d.statement(block.body))
	}
	var policy policyDocument
	sourceDocs, ok := d.documents(content.Attributes["source_json"])
	if !ok {
		return policyDocument{}, false
	}
	more, ok := d.documents(content.Attributes["source_policy_documents"])
	if !ok {
		return policyDocument{}, false
	}
	for _, src := range append(sourceDocs, more...) {
		policy.merge(src)
	}
	policy.merge(own)
	policy.Incomplete = *d.skipped
	// Match the provider: override_policy_documents then override_json so the
	// deprecated singular wins last.
	overrideDocs, ok := d.documents(content.Attributes["override_policy_documents"])
	if !ok {
		return policyDocument{}, false
	}
	more, ok = d.documents(content.Attributes["override_json"])
	if !ok {
		return policyDocument{}, false
	}
	for _, override := range append(overrideDocs, more...) {
		policy.merge(override)
	}
	return policy, true
}

// merge merges other into p as the provider does: a non-empty Id replaces p's,
// Version upgrades lexicographically, and statements override by sid.
func (p *policyDocument) merge(other policyDocument) {
	if other.ID != "" {
		p.ID = other.ID
	}
	if other.Version > p.Version {
		p.Version = other.Version
	}
	p.Statements = overrideBySid(p.Statements, other.Statements)
}

// overrideBySid adds statements to base, replacing the statement of base with
// the same non-empty sid in place.
func overrideBySid(base, statements []policyStatement) []policyStatement {
	for i := range statements {
		st := &statements[i]
		replaced := false
		if st.Sid != "" {
			for j := range base {
				if base[j].Sid == st.Sid {
					base[j] = *st
					replaced = true
					break
				}
			}
		}
		if !replaced {
			base = append(base, *st)
		}
	}
	return base
}

func (d decoder) statement(body hcl.Body) policyStatement {
	content, _, _ := body.PartialContent(statementSchema)
	if content == nil {
		return policyStatement{}
	}
	st := policyStatement{
		Sid:          d.str(content.Attributes["sid"]),
		Actions:      d.list(content.Attributes["actions"]),
		NotActions:   d.list(content.Attributes["not_actions"]),
		Resources:    d.list(content.Attributes["resources"]),
		NotResources: d.list(content.Attributes["not_resources"]),
	}
	// The provider defaults effect when it is omitted or null.
	if attr := content.Attributes["effect"]; attr == nil {
		st.Effect = defaultPolicyEffect
	} else if v, ok := d.eval(attr.Expr); ok {
		v, _ = v.UnmarkDeep()
		if v.IsNull() {
			st.Effect = defaultPolicyEffect
		} else {
			st.Effect = toString(v)
		}
	}
	for _, block := range d.blocks(content, "principals") {
		st.Principals = block.d.principal(st.Principals, block.body)
	}
	for _, block := range d.blocks(content, "not_principals") {
		st.NotPrincipals = block.d.principal(st.NotPrincipals, block.body)
	}
	for _, block := range d.blocks(content, "condition") {
		st.Condition = block.d.condition(st.Condition, block.body)
	}
	return st
}

func (d decoder) principal(into map[string][]string, body hcl.Body) map[string][]string {
	content, _, _ := body.PartialContent(principalSchema)
	if content == nil {
		return into
	}
	typ := d.str(content.Attributes["type"])
	if typ == "" {
		return into
	}
	ids := d.list(content.Attributes["identifiers"])
	if len(ids) == 0 {
		// An empty identifiers list is not a principal the provider would emit.
		return into
	}
	if into == nil {
		into = map[string][]string{}
	}
	into[typ] = append(into[typ], ids...)
	return into
}

func (d decoder) condition(into map[string]map[string][]string, body hcl.Body) map[string]map[string][]string {
	content, _, _ := body.PartialContent(conditionSchema)
	if content == nil {
		return into
	}
	variable := d.str(content.Attributes["variable"])
	if variable == "" {
		return into
	}
	test := d.str(content.Attributes["test"])
	if test == "" {
		return into
	}
	values := d.list(content.Attributes["values"])
	if len(values) == 0 {
		// A condition without values is not a constraint; emitting it would
		// look gated when it is not.
		return into
	}
	if into == nil {
		into = map[string]map[string][]string{}
	}
	if into[test] == nil {
		into[test] = map[string][]string{}
	}
	into[test][variable] = append(into[test][variable], values...)
	return into
}

// documents reads a list of policy JSON documents. Null and empty string are
// treated as unset. ok is false when the attribute is set but an element is
// missing or not parseable policy JSON, so the caller does not merge a partial
// document.
func (d decoder) documents(attr *hcl.Attribute) ([]policyDocument, bool) {
	if attr == nil {
		return nil, true
	}
	v, ok := d.eval(attr.Expr)
	if !ok {
		return nil, false
	}
	v, _ = v.UnmarkDeep()
	if v.IsNull() {
		return nil, true
	}
	if !v.IsKnown() {
		return nil, false
	}
	ty := v.Type()
	if ty == cty.String {
		s := toString(v)
		if s == "" {
			return nil, true
		}
		policy, ok := parsePolicyJSON(s)
		if !ok {
			return nil, false
		}
		return []policyDocument{policy}, true
	}
	if !ty.IsListType() && !ty.IsTupleType() && !ty.IsSetType() {
		return nil, false
	}
	out := make([]policyDocument, 0, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		_, elem := it.Element()
		s := toString(elem)
		if s == "" {
			return nil, false
		}
		policy, ok := parsePolicyJSON(s)
		if !ok {
			return nil, false
		}
		out = append(out, policy)
	}
	return out, true
}

type renderedStatement struct {
	Actions       []string                       `json:"Actions,omitempty"`
	Condition     map[string]map[string][]string `json:"Condition,omitempty"`
	Effect        string                         `json:"Effect,omitempty"`
	NotActions    []string                       `json:"Not_actions,omitempty"`
	NotPrincipals map[string][]string            `json:"Not_principals,omitempty"`
	NotResources  []string                       `json:"Not_resources,omitempty"`
	Principals    map[string][]string            `json:"Principals,omitempty"`
	Resources     []string                       `json:"Resources,omitempty"`
	Sid           string                         `json:"Sid,omitempty"`
}

type renderedPolicy struct {
	ID        string              `json:"Id,omitempty"`
	Statement []renderedStatement `json:"Statement,omitempty"`
	Version   string              `json:"Version,omitempty"`
}

// render renders the policy in the shape rules read from the data source's json
// attribute.
func (p policyDocument) render() (string, error) {
	// The provider writes its default version when none is given.
	version := p.Version
	if version == "" {
		version = defaultPolicyVersion
	}
	out := renderedPolicy{ID: p.ID, Version: version}
	if len(p.Statements) > 0 {
		out.Statement = make([]renderedStatement, len(p.Statements))
	}
	for i := range p.Statements {
		st := &p.Statements[i]
		out.Statement[i] = renderedStatement{
			Actions:       st.Actions,
			Condition:     st.Condition,
			Effect:        st.Effect,
			NotActions:    st.NotActions,
			NotPrincipals: st.NotPrincipals,
			NotResources:  st.NotResources,
			Principals:    st.Principals,
			Resources:     st.Resources,
			Sid:           st.Sid,
		}
	}
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(out); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// parsePolicyJSON reads a policy document given as JSON, in AWS policy grammar
// or in the shape render produces. ok is false when the document, or any field
// of it that is present, cannot be read, so the caller never merges a statement
// that lost part of itself (a dropped Condition would turn a guarded Deny or
// Allow into an unconditional one).
func parsePolicyJSON(raw string) (policyDocument, bool) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return policyDocument{}, false
	}
	r := &jsonReader{}
	policy := policyDocument{ID: r.str(doc["Id"]), Version: r.str(doc["Version"])}
	stmts, ok := doc["Statement"]
	if !ok || isJSONNull(stmts) {
		return policy, r.ok()
	}
	var list []map[string]json.RawMessage
	if err := json.Unmarshal(stmts, &list); err != nil {
		var single map[string]json.RawMessage
		if err := json.Unmarshal(stmts, &single); err != nil {
			return policyDocument{}, false
		}
		list = []map[string]json.RawMessage{single}
	}
	for _, st := range list {
		if st == nil {
			return policyDocument{}, false
		}
		policy.Statements = append(policy.Statements, policyStatement{
			Sid:           r.str(st["Sid"]),
			Effect:        r.str(st["Effect"]),
			Actions:       r.strings(first(st, "Action", "Actions")),
			NotActions:    r.strings(first(st, "NotAction", "Not_actions")),
			Resources:     r.strings(first(st, "Resource", "Resources")),
			NotResources:  r.strings(first(st, "NotResource", "Not_resources")),
			Principals:    r.principal(first(st, "Principal", "Principals")),
			NotPrincipals: r.principal(first(st, "NotPrincipal", "Not_principals")),
			Condition:     r.condition(st["Condition"]),
		})
	}
	if !r.ok() {
		return policyDocument{}, false
	}
	return policy, true
}

func first(m map[string]json.RawMessage, keys ...string) json.RawMessage {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// jsonReader reads the fields of a policy document and remembers whether any
// field that is present could not be read. An absent or null field is unset,
// not unreadable.
type jsonReader struct {
	failed bool
}

func (r *jsonReader) ok() bool { return !r.failed }

func (r *jsonReader) str(raw json.RawMessage) string {
	if len(raw) == 0 || isJSONNull(raw) {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		r.failed = true
		return ""
	}
	if unresolvedTemplate(s) {
		r.failed = true
		return ""
	}
	return s
}

// strings reads a string or a list of them. Numbers and bools, as jsonencode
// writes condition values, read as their text like the provider does.
func (r *jsonReader) strings(raw json.RawMessage) []string {
	if len(raw) == 0 || isJSONNull(raw) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if dec.Decode(&v) != nil {
		r.failed = true
		return nil
	}
	list, ok := v.([]interface{})
	if !ok {
		list = []interface{}{v}
	}
	out := make([]string, 0, len(list))
	for _, elem := range list {
		switch e := elem.(type) {
		case string:
			if unresolvedTemplate(e) {
				r.failed = true
				return nil
			}
			out = append(out, e)
		case json.Number:
			out = append(out, e.String())
		case bool:
			out = append(out, strconv.FormatBool(e))
		default:
			r.failed = true
			return nil
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// unresolvedTemplate reports whether s is a placeholder the partial renderer
// leaves when an expression does not resolve. A source document that still
// holds one is incomplete.
func unresolvedTemplate(s string) bool {
	return strings.Contains(s, "${")
}

func (r *jsonReader) principal(raw json.RawMessage) map[string][]string {
	if len(raw) == 0 || isJSONNull(raw) {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		switch s {
		case "":
			r.failed = true
			return nil
		case "*":
			// AWS accepts only "*" as a bare string principal; match the HCL
			// type = "*" shape rules already read.
			return map[string][]string{"*": {"*"}}
		default:
			return map[string][]string{"AWS": {s}}
		}
	}
	var byType map[string]json.RawMessage
	if json.Unmarshal(raw, &byType) != nil {
		r.failed = true
		return nil
	}
	out := make(map[string][]string, len(byType))
	for typ, ids := range byType {
		if typ == "" || unresolvedTemplate(typ) {
			r.failed = true
			return nil
		}
		if len(ids) == 0 || isJSONNull(ids) {
			r.failed = true
			return nil
		}
		list := r.strings(ids)
		if len(list) == 0 {
			r.failed = true
			return nil
		}
		out[typ] = list
	}
	return out
}

func (r *jsonReader) condition(raw json.RawMessage) map[string]map[string][]string {
	if len(raw) == 0 || isJSONNull(raw) {
		return nil
	}
	var byTest map[string]map[string]json.RawMessage
	if json.Unmarshal(raw, &byTest) != nil {
		r.failed = true
		return nil
	}
	out := make(map[string]map[string][]string, len(byTest))
	for test, vars := range byTest {
		if test == "" || unresolvedTemplate(test) {
			r.failed = true
			return nil
		}
		out[test] = make(map[string][]string, len(vars))
		for variable, values := range vars {
			if variable == "" || unresolvedTemplate(variable) {
				r.failed = true
				return nil
			}
			if len(values) == 0 || isJSONNull(values) {
				r.failed = true
				return nil
			}
			ids := r.strings(values)
			if len(ids) == 0 {
				r.failed = true
				return nil
			}
			out[test][variable] = ids
		}
	}
	return out
}
