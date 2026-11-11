/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
)

// LiteralKeys is the literal matching table of the Terraform library:
// companion type -> dot-joined attribute path -> target type -> target
// attributes. The projector indexes the literals companions write at these
// paths.
//
// An entry declares that a companion may name a target by a string instead of
// a reference. The projector reads it as follows.
//
// Identity: a companion names a target when a known string it writes at the
// path equals, exactly, a known string the target holds at one of the target
// attributes, written or planned. A path or attribute that derives from
// path.* or terraform.* names nothing, and a value a certain reference
// already names is not a literal.
//
// Scope: both blocks are in the same root, or the cross-root evidence links
// them. Within it the blocks must share a provider configuration (the
// implicit default counts as one); a type in globalLiteralTypes names the same
// block under any configuration, as S3 bucket names are global.
//
// Ambiguity: every block that matches is listed. The placeholder is added when
// the answer may be incomplete: no block matches in scope (the literal may
// name a block of another account), a target attribute or a companion count,
// for_each or override is not certain, or the root is incomplete.
type LiteralKeys map[string]map[string]map[string][]string

// libraryPackage is the package of the Terraform rules library.
var libraryPackage = ast.MustParseRef("data.generic.terraform")

const literalKeysRule = "literal_keys"

// LiteralKeysFromModules reads literal_keys from the Terraform library among
// modules, compiled or not. A missing table gives nil; a table that is not a
// constant of the expected shape is an error.
func LiteralKeysFromModules(modules map[string]*ast.Module) (LiteralKeys, error) {
	for _, m := range modules {
		if m.Package == nil || !m.Package.Path.Equal(libraryPackage) {
			continue
		}
		for _, r := range m.Rules {
			if r.Head == nil || r.Head.Ref().String() != literalKeysRule || r.Head.Value == nil {
				continue
			}
			return parseLiteralKeys(r.Head.Value)
		}
	}
	return nil, nil
}

func parseLiteralKeys(t *ast.Term) (LiteralKeys, error) {
	if !t.IsGround() {
		return nil, fmt.Errorf("%s is not a constant", literalKeysRule)
	}
	raw, err := ast.JSON(t.Value)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", literalKeysRule, err)
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", literalKeysRule, err)
	}
	var keys LiteralKeys
	if err := json.Unmarshal(b, &keys); err != nil {
		return nil, fmt.Errorf("%s: %w", literalKeysRule, err)
	}
	return keys, nil
}
