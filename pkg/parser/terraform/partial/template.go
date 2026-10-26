/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package partial

import (
	"hash/maphash"
	"sync"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// maxPlacingTemplates bounds the template texts TemplateVerdicts remembers;
// it starts over once full.
const maxPlacingTemplates = 4096

// TemplateVerdicts remembers, by a digest of a template's text, whether it
// only interpolates bare variables. Every instance of a module loop renders
// the same template, which would otherwise be parsed again for each of them.
// One is shared by the renderers of a scan and dropped with it.
type TemplateVerdicts struct {
	mu       sync.Mutex
	verdicts map[templateDigest]bool
}

// NewTemplateVerdicts returns an empty TemplateVerdicts.
func NewTemplateVerdicts() *TemplateVerdicts {
	return &TemplateVerdicts{verdicts: map[templateDigest]bool{}}
}

type templateDigest struct {
	n    int
	a, b uint64
}

// The seeds stay secret for the process, so crafted template text cannot be
// made to collide with another template's digest.
var templateSeedA, templateSeedB = maphash.MakeSeed(), maphash.MakeSeed()

func (t *TemplateVerdicts) lookup(src string) bool {
	if t == nil {
		return placesVariablesOnly(src)
	}
	key := templateDigest{n: len(src), a: maphash.String(templateSeedA, src), b: maphash.String(templateSeedB, src)}
	t.mu.Lock()
	placing, ok := t.verdicts[key]
	t.mu.Unlock()
	if ok {
		return placing
	}
	placing = placesVariablesOnly(src)
	t.mu.Lock()
	if len(t.verdicts) >= maxPlacingTemplates {
		t.verdicts = map[templateDigest]bool{}
	}
	t.verdicts[key] = placing
	t.mu.Unlock()
	return placing
}

// placesVariablesOnly reports whether the template src has no directive or
// expression other than bare variables that could decide on or rewrite their
// text.
func placesVariablesOnly(src string) bool {
	tmpl, diags := hclsyntax.ParseTemplate([]byte(src), "template", hcl.InitialPos)
	if diags.HasErrors() {
		return false
	}
	placing := true
	_ = hclsyntax.VisitAll(tmpl, func(node hclsyntax.Node) hcl.Diagnostics {
		switch n := node.(type) {
		case *hclsyntax.TemplateExpr, *hclsyntax.TemplateWrapExpr, *hclsyntax.LiteralValueExpr:
		case *hclsyntax.ScopeTraversalExpr:
			placing = placing && len(n.Traversal) == 1
		default:
			placing = false
		}
		return nil
	})
	return placing
}
