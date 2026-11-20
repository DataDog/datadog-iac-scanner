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
}

// policyDocumentAttributes renders the json and minified_json attributes; the
// two only differ in whitespace, which rules do not read.
func policyDocumentAttributes(d decoder, input Configuration) map[string]string {
	policy := decodePolicyDocument(d, input)
	if d.ctx.Err() != nil || d.state.documentIncomplete ||
		(!d.document && (d.state.unresolved || len(d.state.diagnostics) > 0)) {
		return nil
	}
	out, err := policy.render()
	if err != nil {
		d.invalid(input, "json", "could not be encoded")
		return nil
	}
	return map[string]string{"json": out, "minified_json": out}
}

// decodePolicyDocument shares provider semantics across evaluated and rendered inputs.
func decodePolicyDocument(d decoder, input Configuration) policyDocument {
	own := policyDocument{ID: d.str(input, "policy_id"), Version: d.str(input, "version")}
	if own.ID == "" {
		own.ID = d.str(input, "id")
	}
	if own.Version == "" {
		own.Version = defaultPolicyVersion
	}
	for _, block := range d.blocks(input, "statement") {
		own.Statements = append(own.Statements, d.statement(block))
	}
	var policy policyDocument
	for _, name := range []string{"source_json", "source_policy_documents"} {
		for _, src := range d.documents(input, name) {
			policy.merge(src)
		}
	}
	policy.merge(own)
	for _, name := range []string{"override_policy_documents", "override_json"} {
		for _, src := range d.documents(input, name) {
			policy.merge(src)
		}
	}
	return policy
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

func (d decoder) statement(input Configuration) policyStatement {
	st := policyStatement{
		Sid:     d.str(input, "sid"),
		Actions: d.list(input, "actions"), NotActions: d.list(input, "not_actions"),
		Resources: d.list(input, "resources"), NotResources: d.list(input, "not_resources"),
	}
	value, known := d.value(input, "effect")
	if value == cty.NilVal {
		st.Effect = defaultPolicyEffect
	} else if known {
		st.Effect = d.stringValue(input, "effect", value)
	}

	for _, block := range d.blocks(input, "principals") {
		st.Principals = d.principal(st.Principals, block)
	}
	for _, block := range d.blocks(input, "not_principals") {
		st.NotPrincipals = d.principal(st.NotPrincipals, block)
	}
	for _, block := range d.blocks(input, "condition") {
		st.Condition = d.condition(st.Condition, block)
	}
	return st
}
func (d decoder) principal(into map[string][]string, input Configuration) map[string][]string {
	typ := d.str(input, "type")
	ids := d.list(input, "identifiers")
	if typ == "" || len(ids) == 0 {
		return into
	}
	if into == nil {
		into = map[string][]string{}
	}
	into[typ] = append(into[typ], ids...)
	return into
}
func (d decoder) condition(into map[string]map[string][]string, input Configuration) map[string]map[string][]string {
	variable := d.str(input, "variable")
	test := d.str(input, "test")
	values := d.list(input, "values")
	if variable == "" || test == "" || len(values) == 0 {
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

// documents reads source/override inputs without mistaking unknown members for
// malformed JSON. Every known sibling is checked even when another is unknown.
func (d decoder) documents(input Configuration, name string) []policyDocument {
	v, ok := d.value(input, name)
	if !ok {
		if v != cty.NilVal {
			d.state.documentIncomplete = true
		}
		return nil
	}
	// Historical singular attributes are strings; plural attributes are collections.
	// The document adapter retains its existing permissive recovered-text forms.
	ty := v.Type()
	collection := ty.IsListType() || ty.IsTupleType() || ty.IsSetType()
	plural := name == "source_policy_documents" || name == "override_policy_documents"
	if plural != collection {
		d.invalid(input, name, "has an incompatible policy document input shape")
		if !d.document {
			return nil
		}
	}
	if v.Type() == cty.String {
		if v.AsString() == "" {
			return nil
		}
		if document, ok := d.decodeDocument(input, name, v); ok {
			return []policyDocument{document}
		}
		return nil
	}
	if !collection {
		d.state.documentIncomplete = true
		d.invalid(input, name, "must contain policy JSON strings")
		return nil
	}
	var out []policyDocument
	for it := v.ElementIterator(); it.Next(); {
		if d.ctx.Err() != nil {
			d.state.unresolved = true
			break
		}
		_, value := it.Element()
		if document, ok := d.decodeDocument(input, name, value); ok {
			out = append(out, document)
		}
	}
	return out
}

func (d decoder) decodeDocument(input Configuration, name string, value cty.Value) (policyDocument, bool) {
	value, _ = value.Unmark()
	if !value.IsKnown() {
		d.state.unresolved = true
		d.state.documentIncomplete = true
		return policyDocument{}, false
	}
	if !value.IsNull() && value.Type() == cty.String {
		if policy, ok := parsePolicyJSON(value.AsString()); ok {
			return policy, true
		}
	}
	d.state.documentIncomplete = true
	d.invalid(input, name, "contains invalid policy JSON")
	return policyDocument{}, false
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

// str reads a string field. Like Sid and Effect, Id and Version are leaf
// text: a "${...}" placeholder passes through instead of failing the document.
func (r *jsonReader) str(raw json.RawMessage) string {
	if len(raw) == 0 || isJSONNull(raw) {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
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
// leaves when an expression does not resolve.
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
			// The principal type gates the statement, and guessing one from an
			// unresolved reference would not.
			if unresolvedTemplate(s) {
				r.failed = true
				return nil
			}
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
