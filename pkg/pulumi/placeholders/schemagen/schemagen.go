/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package schemagen builds schema-conformant placeholder outputs for the
// functions (data sources) of a Pulumi provider schema.
//
// Values follow the declared output types. Strings use name heuristics so
// that common program patterns survive: zone lists indexed [0..2], CIDRs that
// are parsed, ARN- and GUID-shaped identifiers. This is the D18 placeholder
// strategy measured in phase 0.
package schemagen

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Pin is a provider schema version the placeholder table is generated from.
type Pin struct {
	Provider string `json:"provider"`
	Version  string `json:"version"`
	SHA256   string `json:"sha256"`
}

// URL is where the schema of a pinned provider version is downloaded from.
func (p Pin) URL() string {
	return fmt.Sprintf("https://raw.githubusercontent.com/pulumi/pulumi-%[1]s/v%[2]s/provider/cmd/pulumi-resource-%[1]s/schema.json",
		p.Provider, p.Version)
}

// Pins are the provider schemas the embedded table is generated from: the
// versions measured in phase 0.
var Pins = []Pin{
	{Provider: "aws", Version: "7.52.0", SHA256: "9d73008a5db4cc94400effbbe3ad6b8aef871aff9f8429d7d32f8ebbc25fa1a5"},
	{Provider: "azure", Version: "6.40.1", SHA256: "9a7c94a2e0cc952a9a7f92ce3884c6bcd60d99d3f410d65d62326e627ebc4060"},
	{Provider: "gcp", Version: "10.2.0", SHA256: "78da42ff88fd694f81890cead9b0f21dbafe015a94090e8b983b9e953b237b10"},
}

// Placeholder values shared with the configuration placeholders.
const (
	GUID       = "00000000-0000-0000-0000-000000000000"
	AccountID  = "000000000000"
	GCPProject = "dd-placeholder-project"
	Text       = "dd-placeholder"
)

// Region is the placeholder region per provider.
var Region = map[string]string{"aws": "us-east-1", "gcp": "us-central1", "azure": "westus"}

var zones = map[string][]any{
	"aws":   {"us-east-1a", "us-east-1b", "us-east-1c"},
	"gcp":   {"us-central1-a", "us-central1-b", "us-central1-c"},
	"azure": {"1", "2", "3"},
}

const (
	maxDepth   = 4
	typeObject = "object"
)

// listLength is the number of elements of a placeholder list: programs often
// index the first two or three zones or subnets.
const listLength = 3

// overrides are token-specific fields the name heuristics cannot infer.
var overrides = map[string]map[string]any{
	"aws:index/getRegion:getRegion":                     {"name": Region["aws"]},
	"gcp:organizations/getClientConfig:getClientConfig": {"project": GCPProject},
}

// Schema is the part of a Pulumi package schema the generator reads.
type Schema struct {
	Functions map[string]struct {
		Outputs *Object `json:"outputs"`
	} `json:"functions"`
	Types map[string]*Type `json:"types"`
}

// Object is an object type with properties.
type Object struct {
	Properties map[string]*Type `json:"properties"`
}

// Type is a property or a named type of the schema.
type Type struct {
	Ref        string           `json:"$ref"`
	Type       string           `json:"type"`
	Items      *Type            `json:"items"`
	Properties map[string]*Type `json:"properties"`
	Enum       []struct {
		Value any `json:"value"`
	} `json:"enum"`
}

// Build returns the placeholder outputs of every function of a provider schema.
func Build(provider string, s *Schema) map[string]map[string]any {
	g := gen{provider: provider, types: s.Types}
	out := make(map[string]map[string]any, len(s.Functions))
	for token, fn := range s.Functions {
		props := map[string]*Type{}
		if fn.Outputs != nil && fn.Outputs.Properties != nil {
			props = fn.Outputs.Properties
		}
		values := g.object(props, 0)
		for k, v := range overrides[token] {
			values[k] = v
		}
		out[token] = values
	}
	return out
}

type gen struct {
	provider string
	types    map[string]*Type
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]`)

func norm(name string) string { return nonAlnum.ReplaceAllString(strings.ToLower(name), "") }

func (g gen) object(props map[string]*Type, depth int) map[string]any {
	out := make(map[string]any, len(props))
	for name, t := range props {
		if v := g.value(name, t, depth); v != nil {
			out[name] = v
		}
	}
	return out
}

func (g gen) value(name string, t *Type, depth int) any {
	if t == nil {
		return nil
	}
	if t.Ref != "" {
		return g.ref(name, t.Ref, depth)
	}
	switch t.Type {
	case "array":
		item := g.value(name, t.Items, depth+1)
		if item == nil {
			return []any{}
		}
		return g.list(name, item)
	case typeObject:
		return map[string]any{}
	case "string":
		return g.text(name)
	case "integer":
		return 1
	case "number":
		return 1.5 //nolint:mnd // a non-integer number
	case "boolean":
		return false
	}
	return nil
}

func (g gen) ref(name, ref string, depth int) any {
	const prefix = "#/types/"
	if !strings.HasPrefix(ref, prefix) || depth > maxDepth {
		return nil
	}
	key, err := url.PathUnescape(strings.TrimPrefix(ref, prefix))
	if err != nil {
		return nil
	}
	t := g.types[key]
	if t == nil {
		return nil
	}
	if len(t.Enum) > 0 {
		return t.Enum[0].Value
	}
	if t.Properties != nil || t.Type == typeObject {
		return g.object(t.Properties, depth+1)
	}
	return g.value(name, t, depth+1)
}

func (g gen) list(name string, item any) []any {
	n := norm(name)
	if s, ok := item.(string); ok {
		switch {
		case n == "names" || n == "zones" || n == "availabilityzones" || strings.HasSuffix(n, "zonenames"):
			return append([]any(nil), zones[g.provider]...)
		case strings.HasSuffix(n, "zoneids"):
			return []any{"use1-az1", "use1-az2", "use1-az4"}
		case strings.Contains(n, "cidr"):
			return []any{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"}
		}
		out := make([]any, listLength)
		for i := range out {
			out[i] = fmt.Sprintf("%s-%d", s, i)
		}
		return out
	}
	out := make([]any, listLength)
	for i := range out {
		out[i] = item
	}
	return out
}

// textRule gives the placeholder of a string property from its normalized name.
type textRule struct {
	match func(n, provider string) bool
	value func(provider string) string
}

func constant(v string) func(string) string { return func(string) string { return v } }

// textRules are tried in order; the first match wins.
var textRules = []textRule{
	{func(n, _ string) bool { return strings.Contains(n, "cidr") }, constant("10.0.0.0/16")},
	{func(n, _ string) bool { return strings.HasSuffix(n, "zoneid") }, constant("use1-az1")},
	{
		func(n, _ string) bool { return strings.HasSuffix(n, "zone") || n == "availabilityzone" },
		func(p string) string { return zones[p][0].(string) },
	},
	{
		func(n, _ string) bool { return strings.Contains(n, "region") || n == "location" },
		func(p string) string { return Region[p] },
	},
	{func(n, _ string) bool { return n == "accountid" || n == "ownerid" || n == "awsaccountid" }, constant(AccountID)},
	{
		func(n, _ string) bool { return n == "arn" || strings.HasSuffix(n, "arn") },
		func(p string) string {
			if p == "aws" {
				return "arn:aws:iam::" + AccountID + ":" + Text
			}
			return Text
		},
	},
	{
		func(n, _ string) bool {
			return hasAnySuffix(n, "tenantid", "subscriptionid", "clientid", "objectid", "principalid", "applicationid")
		},
		constant(GUID),
	},
	{func(n, p string) bool { return p == "gcp" && (n == "project" || n == "projectid") }, constant(GCPProject)},
	{func(n, _ string) bool { return strings.Contains(n, "email") }, constant(Text + "@example.invalid")},
	{
		func(n, _ string) bool {
			return strings.Contains(n, "url") || strings.Contains(n, "endpoint") || strings.Contains(n, "uri")
		},
		constant("https://" + Text + ".example.invalid"),
	},
	{func(n, _ string) bool { return n == "id" }, constant(Text + "-id")},
}

func (g gen) text(name string) string {
	n := norm(name)
	for _, r := range textRules {
		if r.match(n, g.provider) {
			return r.value(g.provider)
		}
	}
	return Text
}

func hasAnySuffix(s string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}
