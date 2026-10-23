/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package tfscale generates deterministic Terraform fixtures whose module and
// resource expansion is known in advance, so a scan of them can be checked for
// complete cardinality before its time and memory are compared.
package tfscale

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Kind is how one expansion level instantiates.
type Kind string

const (
	Count  Kind = "count"
	Map    Kind = "map" // for_each over a map
	Set    Kind = "set" // for_each over a set of strings
	Single Kind = "single"
)

// Level is one expansion level: a module call, or the leaf resource block.
type Level struct {
	Kind Kind `json:"kind"`
	N    int  `json:"n"`
}

func (l Level) instances() int {
	if l.Kind == Single {
		return 1
	}
	return l.N
}

// Shape describes a generated fixture.
type Shape struct {
	Name string `json:"name"`
	// Roots is the number of independent root directories calling the module tree.
	Roots int `json:"roots"`
	// DistinctRoots gives every root its own seed, so no two roots share inputs.
	DistinctRoots bool `json:"distinct_roots"`
	// Modules are the nested module expansion levels, outermost first.
	Modules []Level `json:"modules"`
	// Leaf is the expansion of the leaf resource block.
	Leaf Level `json:"leaf"`
	// IdenticalInstances passes the same inputs to every instance of a level,
	// so the evaluations are identical and only the addresses differ.
	IdenticalInstances bool `json:"identical_instances"`
	// DecodedBytes, when set, writes a JSON file of about this size that every
	// root decodes once and forwards unchanged through every module level.
	DecodedBytes int `json:"decoded_bytes"`
	// Dynamic is the size of a dynamic cors_rule block in the leaf resource.
	Dynamic int `json:"dynamic"`
	// NestedDynamic adds a nested dynamic block of this size inside each
	// generated cors_rule.
	NestedDynamic int `json:"nested_dynamic"`
	// RootResources is the expansion of a resource block in each root module.
	RootResources Level `json:"root_resources"`
	// Outputs aggregates the leaf instance names through every level's outputs.
	Outputs bool `json:"outputs"`
	// Data adds a for_each data block beside the leaf resource.
	Data bool `json:"data"`
	// Unnamed leaves the bucket name unset, so every finding reports the
	// block name and instances differ only by their address.
	Unnamed bool `json:"unnamed"`
}

// Expected is the cardinality a complete scan of a shape must report.
type Expected struct {
	Shape Shape `json:"shape"`
	// ModuleInstances is every evaluated module call across all roots.
	ModuleInstances int `json:"module_instances"`
	// LeafInstances is every leaf resource instance across all roots.
	LeafInstances int `json:"leaf_instances"`
	// RootResourceInstances is every root-module resource instance.
	RootResourceInstances int `json:"root_resource_instances"`
	// ModuleResources is the module resource and data instances the
	// evaluator instantiates: leaf resources plus data instances.
	ModuleResources int `json:"module_resources"`
	// ACLFindings is how many "S3 bucket ACL allows read or write to all users"
	// findings a complete scan reports: one per aws_s3_bucket instance.
	ACLFindings int `json:"acl_findings"`
	// CORSFindings is how many unsecured CORS findings a complete scan reports:
	// one per leaf instance when Dynamic > 0.
	CORSFindings int `json:"cors_findings"`
	// SourceBytes is the size of the generated Terraform and JSON.
	SourceBytes int64 `json:"source_bytes"`
}

// ACLRule and CORSRule are the rule names the fixture triggers once per instance.
const (
	ACLRule  = "S3 bucket ACL allows read or write to all users"
	CORSRule = "S3 bucket with unsecured CORS rule"
)

// Expect computes the cardinality of a shape without generating it.
func Expect(s *Shape) Expected {
	roots := max(s.Roots, 1)
	moduleInstances, product := 0, 1
	for _, l := range s.Modules {
		product *= l.instances()
		moduleInstances += product
	}
	leaf := product * s.Leaf.instances()
	data := 0
	if s.Data {
		data = product * dataKeys
	}
	rootRes := 0
	if s.RootResources.N > 0 || s.RootResources.Kind == Single {
		rootRes = s.RootResources.instances()
	}
	e := Expected{
		Shape:                 *s,
		ModuleInstances:       roots * moduleInstances,
		LeafInstances:         roots * leaf,
		RootResourceInstances: roots * rootRes,
		ModuleResources:       roots * (leaf + data),
		ACLFindings:           roots * (leaf + rootRes),
	}
	if s.Dynamic > 0 {
		e.CORSFindings = roots * leaf
	}
	return e
}

const (
	dataKeys  = 2
	dirPerms  = 0o750
	filePerms = 0o600
	eachKey   = "each.key"
	// itemTeams and itemTiers vary the decoded items, so they are not all alike.
	itemTeams = 17
	itemTiers = 3
)

// Generate writes the fixture for s under dir, which must be empty or absent.
func Generate(dir string, s *Shape) (Expected, error) {
	if err := os.MkdirAll(dir, dirPerms); err != nil {
		return Expected{}, err
	}
	w := &writer{root: dir}
	depth := len(s.Modules)
	for i := 0; i < depth; i++ {
		var body string
		if i == depth-1 {
			body = leafModule(s)
		} else {
			body = middleModule(s, i)
		}
		w.write(filepath.Join("modules", fmt.Sprintf("l%d", i), "main.tf"), body)
	}
	if s.DecodedBytes > 0 {
		w.write(filepath.Join("data", "shared.json"), decodedJSON(s.DecodedBytes))
	}
	for r := 0; r < max(s.Roots, 1); r++ {
		w.write(filepath.Join("roots", fmt.Sprintf("r%03d", r), "main.tf"), rootModule(s, r))
	}
	if w.err != nil {
		return Expected{}, w.err
	}
	e := Expect(s)
	e.SourceBytes = w.bytes
	return e, nil
}

type writer struct {
	root  string
	bytes int64
	err   error
}

func (w *writer) write(rel, content string) {
	if w.err != nil {
		return
	}
	path := filepath.Join(w.root, rel)
	if err := os.MkdirAll(filepath.Dir(path), dirPerms); err != nil {
		w.err = err
		return
	}
	w.bytes += int64(len(content))
	w.err = os.WriteFile(path, []byte(content), filePerms)
}

// rangeLimit is the most numbers Terraform's range function returns.
const rangeLimit = 1024

// sequence renders an expression for the numbers 0 to n-1. Terraform's range
// rejects more than rangeLimit numbers, so larger sequences are built from
// chunks of 1000.
func sequence(n int) string {
	if n <= rangeLimit {
		return fmt.Sprintf("range(%d)", n)
	}
	chunks := (n + 999) / 1000
	return fmt.Sprintf("[for i in flatten([for a in range(%d) : [for b in range(1000) : a * 1000 + b]]) : i if i < %d]",
		chunks, n)
}

// expansion renders the count or for_each argument of a level and the
// expression that identifies the current instance.
func expansion(l Level) (arg, index string) {
	switch l.Kind {
	case Count:
		return fmt.Sprintf("count = %d", l.N), "count.index"
	case Map:
		return fmt.Sprintf("for_each = { for i in %s : format(\"k%%05d\", i) => i }", sequence(l.N)), eachKey
	case Set:
		return fmt.Sprintf("for_each = toset([for i in %s : format(\"s%%05d\", i)])", sequence(l.N)), eachKey
	}
	return "", `"single"`
}

// collect renders an expression gathering the names output of every instance
// of a module call or resource expanded as l.
func collect(l Level, ref string) string {
	switch l.Kind {
	case Count:
		return fmt.Sprintf("flatten(%s[*].names)", ref)
	case Map, Set:
		return fmt.Sprintf("flatten([for k, m in %s : m.names])", ref)
	}
	return ref + ".names"
}

const commonVars = `variable "seed" {
  type        = string
  description = "seed"
}

variable "idx" {
  type        = string
  description = "instance path"
}

variable "cfg" {
  type        = any
  description = "forwarded decoded configuration"
  default     = null
}
`

func childCall(s *Shape, child int, l Level, cfg string) string {
	arg, index := expansion(l)
	idx := fmt.Sprintf(`"${var.idx}/${%s}"`, index)
	if s.IdenticalInstances {
		idx = "var.idx"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "module \"l%d\" {\n  source = \"../l%d\"\n", child, child)
	if arg != "" {
		fmt.Fprintf(&b, "  %s\n", arg)
	}
	fmt.Fprintf(&b, "  seed = var.seed\n  idx  = %s\n  cfg  = %s\n}\n", idx, cfg)
	return b.String()
}

func middleModule(s *Shape, i int) string {
	var b strings.Builder
	b.WriteString(commonVars)
	b.WriteString("\n")
	b.WriteString(childCall(s, i+1, s.Modules[i+1], "var.cfg"))
	if s.Outputs {
		fmt.Fprintf(&b, "\noutput \"names\" {\n  description = \"leaf names\"\n  value       = %s\n}\n",
			collect(s.Modules[i+1], fmt.Sprintf("module.l%d", i+1)))
	}
	return b.String()
}

func leafModule(s *Shape) string {
	var b strings.Builder
	b.WriteString(commonVars)
	arg, index := expansion(s.Leaf)
	region := `var.cfg == null ? "none" : var.cfg.settings.region`
	fmt.Fprintf(&b, "\nresource \"aws_s3_bucket\" \"b\" {\n")
	if arg != "" {
		fmt.Fprintf(&b, "  %s\n", arg)
	}
	if !s.Unnamed {
		fmt.Fprintf(&b, "  bucket = \"${var.seed}-${var.idx}-${%s}\"\n", index)
	}
	b.WriteString("  acl    = \"public-read\"\n")
	fmt.Fprintf(&b, "  tags = {\n    region = %s\n  }\n", region)
	if s.Dynamic > 0 {
		fmt.Fprintf(&b, "  dynamic \"cors_rule\" {\n    for_each = %s\n    content {\n", sequence(s.Dynamic))
		b.WriteString("      allowed_methods = [\"PUT\", \"DELETE\"]\n      allowed_origins = [\"*\"]\n")
		b.WriteString("      allowed_headers = [\"h${cors_rule.value}\"]\n")
		if s.NestedDynamic > 0 {
			fmt.Fprintf(&b, "      dynamic \"nested\" {\n        for_each = %s\n        content {\n", sequence(s.NestedDynamic))
			b.WriteString("          v = \"${cors_rule.value}-${nested.value}\"\n        }\n      }\n")
		}
		b.WriteString("    }\n  }\n")
	}
	b.WriteString("}\n")
	if s.Data {
		fmt.Fprintf(&b, "\ndata \"aws_iam_policy_document\" \"d\" {\n  for_each = toset([%s])\n", dataKeyList())
		b.WriteString("  statement {\n    actions   = [\"s3:GetObject\"]\n    resources = [\"arn:aws:s3:::${var.seed}/${each.key}\"]\n  }\n}\n")
	}
	if s.Outputs {
		ref := "aws_s3_bucket.b"
		var value string
		switch s.Leaf.Kind {
		case Count:
			value = ref + "[*].bucket"
		case Map, Set:
			value = fmt.Sprintf("[for k, r in %s : r.bucket]", ref)
		default:
			value = fmt.Sprintf("[%s.bucket]", ref)
		}
		fmt.Fprintf(&b, "\noutput \"names\" {\n  description = \"bucket names\"\n  value       = %s\n}\n", value)
	}
	return b.String()
}

func dataKeyList() string {
	keys := make([]string, dataKeys)
	for i := range keys {
		keys[i] = fmt.Sprintf("%q", fmt.Sprintf("d%d", i))
	}
	return strings.Join(keys, ", ")
}

func rootModule(s *Shape, r int) string {
	seed := "shared"
	if s.DistinctRoots {
		seed = fmt.Sprintf("root%03d", r)
	}
	var b strings.Builder
	cfg := "null"
	if s.DecodedBytes > 0 {
		b.WriteString("locals {\n  cfg = jsondecode(file(\"${path.module}/../../data/shared.json\"))\n}\n\n")
		cfg = "local.cfg"
	}
	if len(s.Modules) > 0 {
		arg, index := expansion(s.Modules[0])
		idx := fmt.Sprintf(`"${%s}"`, index)
		if s.IdenticalInstances {
			idx = `"same"`
		}
		b.WriteString("module \"l0\" {\n  source = \"../../modules/l0\"\n")
		if arg != "" {
			fmt.Fprintf(&b, "  %s\n", arg)
		}
		fmt.Fprintf(&b, "  seed = %q\n  idx  = %s\n  cfg  = %s\n}\n", seed, idx, cfg)
		if s.Outputs {
			fmt.Fprintf(&b, "\noutput \"names\" {\n  description = \"all leaf names\"\n  value       = %s\n}\n",
				collect(s.Modules[0], "module.l0"))
		}
	}
	if s.RootResources.N > 0 || s.RootResources.Kind == Single {
		arg, index := expansion(s.RootResources)
		b.WriteString("\nresource \"aws_s3_bucket\" \"root\" {\n")
		if arg != "" {
			fmt.Fprintf(&b, "  %s\n", arg)
		}
		fmt.Fprintf(&b, "  bucket = \"%s-root-${%s}\"\n  acl    = \"public-read\"\n}\n", seed, index)
	}
	return b.String()
}

// decodedJSON renders a deterministic JSON object of about n bytes with a
// settings object and a list of items, as a decoded configuration file would be.
func decodedJSON(n int) string {
	var b strings.Builder
	b.WriteString(`{"settings":{"region":"us-east-1","owner":"platform"},"items":[`)
	for i := 0; b.Len() < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"id":%d,"name":"item-%06d","enabled":%t,"tags":{"team":"t%d","tier":"%d"}}`,
			i, i, i%2 == 0, i%itemTeams, i%itemTiers)
	}
	b.WriteString("]}\n")
	return b.String()
}

// Catalog returns the named benchmark shapes, smallest first.
func Catalog() []Shape {
	shapes := []Shape{
		{Name: "nested_20x20", Modules: []Level{{Map, 20}, {Count, 20}}, Leaf: Level{Count, 3}, Outputs: true},
		{Name: "nested_60x60", Modules: []Level{{Map, 60}, {Count, 60}}, Leaf: Level{Count, 3}, Outputs: true},
		{
			Name: "decoded_153x20", Modules: []Level{{Map, 153}, {Count, 20}}, Leaf: Level{Single, 1},
			DecodedBytes: 3_500_000, Outputs: true,
		},
		{Name: "fanout_153x60x63", Modules: []Level{{Map, 153}, {Count, 60}}, Leaf: Level{Count, 63}},
		{
			Name: "roots_300_identical", Roots: 300, Modules: []Level{{Count, 4}, {Set, 3}},
			Leaf: Level{Count, 2}, RootResources: Level{Count, 2}, Outputs: true,
		},
		{
			Name: "roots_300_distinct", Roots: 300, DistinctRoots: true, Modules: []Level{{Count, 4}, {Set, 3}},
			Leaf: Level{Count, 2}, RootResources: Level{Count, 2}, Outputs: true,
		},
		{
			Name: "identical_instances_100x100", Modules: []Level{{Count, 100}, {Count, 100}},
			Leaf: Level{Single, 1}, IdenticalInstances: true,
		},
		{
			Name: "deep_6x4", Modules: []Level{{Count, 4}, {Map, 4}, {Set, 4}, {Count, 4}, {Map, 4}, {Set, 4}},
			Leaf: Level{Single, 1}, Outputs: true,
		},
		{Name: "chain_40", Modules: chain(chainDepth), Leaf: Level{Count, 2}, Outputs: true},
		{Name: "resource_foreach_5000", Modules: []Level{{Single, 1}}, Leaf: Level{Set, 5000}, Outputs: true},
		{Name: "root_count_5000", RootResources: Level{Count, 5000}},
		{
			Name: "dynamic_2000", Modules: []Level{{Count, 10}}, Leaf: Level{Single, 1},
			Dynamic: 2000,
		},
		{
			Name: "nested_dynamic_100x30", Modules: []Level{{Count, 10}}, Leaf: Level{Count, 2},
			Dynamic: 100, NestedDynamic: 30,
		},
		{Name: "data_foreach_50x50", Modules: []Level{{Map, 50}, {Count, 50}}, Leaf: Level{Single, 1}, Data: true},
		{Name: "unnamed_count_20x500", Modules: []Level{{Count, 20}}, Leaf: Level{Count, 500}, Unnamed: true},
	}
	sort.SliceStable(shapes, func(i, j int) bool {
		return Expect(&shapes[i]).LeafInstances < Expect(&shapes[j]).LeafInstances
	})
	return shapes
}

// chainDepth is far past the 15 levels module evaluation once stopped at.
const chainDepth = 40

func chain(n int) []Level {
	out := make([]Level, n)
	for i := range out {
		out[i] = Level{Single, 1}
	}
	return out
}

// Lookup returns the catalog shape named name.
func Lookup(name string) (Shape, bool) {
	catalog := Catalog()
	for i := range catalog {
		if catalog[i].Name == name {
			return catalog[i], true
		}
	}
	return Shape{}, false
}
