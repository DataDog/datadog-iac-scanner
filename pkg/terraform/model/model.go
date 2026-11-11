/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package model loads Terraform roots and evaluates them into blocks and
// instances with their values, source ranges and references, the input the
// rule projector turns into documents.
package model

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Root is one Terraform root module and every module instance it calls.
type Root struct {
	// ID names the root in block ids: its directory relative to the scan
	// base, "." for the base itself.
	ID  string
	Dir string
	// Modules holds the root module first, then the module instances in
	// address order.
	Modules []*Module
	// Incomplete is set when the root may hold blocks the model does not
	// see: a module call that did not resolve, a module directory evaluation
	// skipped, or a file that failed to parse.
	Incomplete bool
	// Unscoped is set when the incompleteness cannot be limited to what
	// unresolved module calls reach: every relation of the root is then
	// incomplete. Without it, only the blocks in Exposed are.
	Unscoped bool
	// Unresolved holds the instances of the module calls that did not
	// resolve. Such a call can create blocks of its own, and can read a
	// block of its caller only through the arguments of the call.
	Unresolved []*Instance
	// Exposed holds the instances the arguments of an unresolved call read,
	// directly or through locals, variables and module outputs, and the
	// unresolved call instances themselves.
	Exposed map[*Instance]bool
	// ExposedStrings holds the known strings the arguments of the
	// unresolved calls carry: a block whose identifying value is one of them
	// may be named by a block the call creates.
	ExposedStrings map[string]bool
	// Degraded is set when the root evaluated only with every root variable
	// unknown, or did not evaluate at all.
	Degraded bool
	// Notes say why the root is incomplete or degraded.
	Notes []string
	// VarFiles are the variable definition files of the root directory. Only
	// the autoloaded ones were read; the others are root inputs.
	VarFiles []string
	// Plan is set for a root modeled from a Terraform plan JSON file: ID and
	// Dir name the file and its directory, blocks have no native syntax.
	Plan bool
}

// IncompleteEverywhere reports whether every relation of the root is
// incomplete, whichever block it asks about.
func (r *Root) IncompleteEverywhere() bool {
	return r.Incomplete && (r.Unscoped || len(r.Unresolved) == 0)
}

// Module is one instance of a module directory.
type Module struct {
	Root *Root
	// Address is "" for the root module, module.a["x"].module.b otherwise.
	Address string
	Dir     string
	// Chain is the call chain from the root, empty for the root module.
	Chain []tfeval.CallSite
	// Scope is the module's evaluated scope; nil when it was not evaluated.
	Scope *tfeval.ModuleScope
	// Inputs are the module call arguments the instance was evaluated with.
	Inputs  map[string]cty.Value
	Outputs map[string]cty.Value
	// Static is set on the first instance of each module directory in a
	// root: variable, output and provider blocks are only modeled there, so
	// module instances do not repeat them.
	Static bool
	Blocks []*Block

	parent *Module
	// calls holds the instances of each module call, by label.
	calls map[string][]*Module
}

// Called returns the instances of the module call labeled label.
func (m *Module) Called(label string) []*Module { return m.calls[label] }

// Block is one block as written, with its instances.
type Block struct {
	Module *Module
	Kind   string
	// Type is the resource, data or ephemeral type, or the provider name.
	Type string
	// Name is the label, the provider alias, or "" for locals.
	Name string
	// File is the declaring file. A block merged with override files lives in
	// its base file; its attributes keep their own ranges.
	File   string
	Range  hcl.Range
	Syntax *hclsyntax.Block
	// Duplicate is set when another block of the root has the same address
	// (invalid Terraform): references to the address are may-only.
	Duplicate bool
	// KeyUnknown is set when count or for_each is unknown: the block has one
	// instance standing for any number.
	KeyUnknown bool
	// Overridable is set when count or for_each reads a root input, which a
	// plan can override.
	Overridable bool
	// Provider is the provider configuration the block uses, as written in
	// its module ("aws", "aws.west"); "" for blocks that use none.
	Provider string
	// ProviderBlock is the resolved provider configuration, nil when the
	// provider is not configured in the root.
	ProviderBlock *Block
	Lifecycle     cty.Value
	DependsOn     []string
	// Nonliteral holds the attribute paths (dot-joined) whose value derives
	// from path.* or terraform.*: their literals name nothing reliably.
	Nonliteral []string
	Instances  []*Instance
}

// Instance is one instance of a block.
type Instance struct {
	Block *Block
	// Key is the instance key in HCL syntax ("[0]", `["x"]`), "" for a block
	// without count or for_each, or whose count or for_each is unknown.
	Key     string
	Address string
	// Attrs are the evaluated attributes: meta-arguments removed, nested
	// blocks as tuples of objects, an unknown dynamic block as one unknown
	// element, null attributes kept (the projector drops them).
	Attrs map[string]cty.Value
	// Computed holds, for a plan, the planned values the configuration does
	// not write, in the shape of Attrs; unknown ones are unknown values.
	Computed map[string]cty.Value
	// Iteration binds count or each for the instance, nil when there is none.
	Iteration map[string]cty.Value
	// Ranges maps dot-joined paths, list indexes in decimal, to their source
	// range: "" is the block, "ingress.0" a nested block or the content of
	// the dynamic block that generated it.
	Ranges map[string]hcl.Range
	// Templates holds, for strings with an unknown part, the parts in order:
	// known strings and unknown values.
	Templates map[string][]cty.Value
	// JSON holds, for JSON-encoded strings with an unknown part, the value
	// before encoding (jsonencode) or the document parsed from a JSON
	// template or heredoc with unknown leaves. Unknown leaves are unknown
	// values, not "${expr}" text.
	JSON map[string]cty.Value
	// JSONExpr holds, for each JSON attribute, the "${expr}" text of every
	// unknown leaf at its document path (dot-joined, list indexes in decimal).
	JSONExpr map[string]map[string]string
	// Refs are the references the instance makes, Untraced the dot-joined
	// attribute paths (names only) where it holds a value the model could not
	// trace to a block.
	Refs     []Ref
	Untraced map[string]bool
	// UnresolvedAt holds the dot-joined attribute paths (names only) whose
	// only untraced values are what unresolved module calls return. Such a
	// value can name a block of the root only if the arguments of a call
	// reach it (see Root.Exposed).
	UnresolvedAt map[string]bool
}

// Ref is a reference from an instance attribute path to another instance.
type Ref struct {
	// Path holds attribute names only, no list indexes.
	Path []string
	To   *Instance
	// Attr is the attribute of the target that was read, "" for the whole
	// object.
	Attr string
	// Read is the dotted attribute path that was read, list indexes skipped:
	// "metric_transformation.name" for x.metric_transformation[0].name. It
	// starts with Attr and may be empty when Attr is not.
	Read string
	// Certain is false for a may-only reference (a conditional branch, a
	// dynamic key, a duplicate address) or when either end's count or
	// for_each is unknown or overridable.
	Certain bool
}

// Address returns the block's address in its module, without instance key.
func (b *Block) Address() string {
	if len(b.Instances) > 0 && b.Instances[0].Key == "" {
		return b.Instances[0].Address
	}
	return joinAddr(b.Module.Address, blockAddr(b))
}

// KindLocals is the kind of a locals block, which Terraform does not address
// as a whole (its values are local.<name>).
const KindLocals = "locals"

// ProviderKey is a provider configuration's name in its module: "aws" or
// "aws.west".
func ProviderKey(typ, alias string) string {
	if alias == "" {
		return typ
	}
	return typ + "." + alias
}

func joinAddr(module, addr string) string {
	if module == "" {
		return addr
	}
	return module + "." + addr
}
