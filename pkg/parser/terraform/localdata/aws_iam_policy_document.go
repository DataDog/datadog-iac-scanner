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

	"github.com/hashicorp/hcl/v2"
)

// awsIAMPolicyDocumentType is the AWS data source that renders an IAM policy.
const awsIAMPolicyDocumentType = "aws_iam_policy_document"

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
	Blocks: []hcl.BlockHeaderSchema{{Type: "statement"}},
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
	out, err := decodePolicyDocument(body, eval).render()
	if err != nil {
		return nil
	}
	return map[string]string{"json": out, "minified_json": out}
}

// decodePolicyDocument reads the policy an aws_iam_policy_document body
// declares, merging the source and override documents it names the way
// Terraform does. Arguments the data source does not define, and values eval
// cannot resolve, are left out rather than discarding the document.
func decodePolicyDocument(body hcl.Body, eval EvalFunc) policyDocument {
	content, _, _ := body.PartialContent(documentSchema)
	if content == nil {
		return policyDocument{}
	}
	d := decoder{eval: eval}
	own := policyDocument{
		ID:      d.str(content.Attributes["policy_id"]),
		Version: d.str(content.Attributes["version"]),
	}
	if own.ID == "" {
		own.ID = d.str(content.Attributes["id"])
	}
	own.Statements = make([]policyStatement, 0, len(content.Blocks))
	for _, block := range content.Blocks {
		own.Statements = append(own.Statements, d.statement(block.Body))
	}
	var policy policyDocument
	sourceDocs := append(d.documents(content.Attributes["source_json"]), d.documents(content.Attributes["source_policy_documents"])...)
	for _, src := range sourceDocs {
		policy.merge(src)
	}
	policy.merge(own)
	overrideDocs := append(d.documents(content.Attributes["override_json"]), d.documents(content.Attributes["override_policy_documents"])...)
	for _, override := range overrideDocs {
		policy.merge(override)
	}
	return policy
}

// merge merges other into p as the provider does: a non-empty Id replaces p's,
// the later Version wins and statements override by sid.
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
		Effect:       d.str(content.Attributes["effect"]),
		Actions:      d.list(content.Attributes["actions"]),
		NotActions:   d.list(content.Attributes["not_actions"]),
		Resources:    d.list(content.Attributes["resources"]),
		NotResources: d.list(content.Attributes["not_resources"]),
	}
	for _, block := range content.Blocks {
		switch block.Type {
		case "principals":
			st.Principals = d.principal(st.Principals, block.Body)
		case "not_principals":
			st.NotPrincipals = d.principal(st.NotPrincipals, block.Body)
		case "condition":
			st.Condition = d.condition(st.Condition, block.Body)
		}
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
	if into == nil {
		into = map[string][]string{}
	}
	into[typ] = append(into[typ], d.list(content.Attributes["identifiers"])...)
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
	if into == nil {
		into = map[string]map[string][]string{}
	}
	if into[test] == nil {
		into[test] = map[string][]string{}
	}
	into[test][variable] = append(into[test][variable], d.list(content.Attributes["values"])...)
	return into
}

// documents reads a list of policy JSON documents, skipping any that is not a
// known policy.
func (d decoder) documents(attr *hcl.Attribute) []policyDocument {
	var out []policyDocument
	for _, raw := range d.list(attr) {
		if policy, ok := parsePolicyJSON(raw); ok {
			out = append(out, policy)
		}
	}
	return out
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
	out := renderedPolicy{ID: p.ID, Version: p.Version}
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
// or in the shape render produces.
func parsePolicyJSON(raw string) (policyDocument, bool) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return policyDocument{}, false
	}
	policy := policyDocument{ID: rawString(doc["Id"]), Version: rawString(doc["Version"])}
	stmts, ok := doc["Statement"]
	if !ok {
		return policy, true
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
		policy.Statements = append(policy.Statements, policyStatement{
			Sid:           rawString(st["Sid"]),
			Effect:        rawString(st["Effect"]),
			Actions:       rawStrings(first(st, "Action", "Actions")),
			NotActions:    rawStrings(first(st, "NotAction", "Not_actions")),
			Resources:     rawStrings(first(st, "Resource", "Resources")),
			NotResources:  rawStrings(first(st, "NotResource", "Not_resources")),
			Principals:    rawPrincipal(first(st, "Principal", "Principals")),
			NotPrincipals: rawPrincipal(first(st, "NotPrincipal", "Not_principals")),
			Condition:     rawCondition(st["Condition"]),
		})
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

func rawString(raw json.RawMessage) string {
	var s string
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// rawStrings reads a string or a list of them. Numbers and bools, as jsonencode
// writes condition values, read as their text like the provider does.
func rawStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if dec.Decode(&v) != nil {
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
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func rawPrincipal(raw json.RawMessage) map[string][]string {
	if len(raw) == 0 {
		return nil
	}
	if s := rawString(raw); s != "" {
		return map[string][]string{"AWS": {s}}
	}
	var byType map[string]json.RawMessage
	if json.Unmarshal(raw, &byType) != nil {
		return nil
	}
	out := make(map[string][]string, len(byType))
	for typ, ids := range byType {
		out[typ] = rawStrings(ids)
	}
	return out
}

func rawCondition(raw json.RawMessage) map[string]map[string][]string {
	if len(raw) == 0 {
		return nil
	}
	var byTest map[string]map[string]json.RawMessage
	if json.Unmarshal(raw, &byTest) != nil {
		return nil
	}
	out := make(map[string]map[string][]string, len(byTest))
	for test, vars := range byTest {
		out[test] = make(map[string][]string, len(vars))
		for variable, values := range vars {
			out[test][variable] = rawStrings(values)
		}
	}
	return out
}
