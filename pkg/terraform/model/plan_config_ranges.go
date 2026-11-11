/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"strconv"

	"github.com/hashicorp/hcl/v2"
)

// addConfigRanges locates the attributes a resource's configuration writes and
// the planned values lack, such as an unknown value, at their expression in
// the configuration section. A path the planned values locate keeps that
// range. Provisioners, which planned_values omit entirely, are located under
// the labeled provisioner paths planProvisioners builds.
func (b *planBuilder) addConfigRanges(inst *Instance, m *Module, baddr string) {
	ref, ok := b.configResources(m)[baddr]
	if !ok {
		return
	}
	pos := b.configPos(m, "resources", strconv.Itoa(ref.i))
	pos.kid("expressions").flattenMissing("", inst.Ranges)
	addProvisionerRanges(pos.kid("provisioners"), list(ref.cfg, "provisioners"), inst.Ranges)
}

// addProvisionerRanges records configuration ranges for provisioners under the
// same paths as planProvisioners: provisioner.0.<type> for a single block of
// that type, and provisioner.0.<type>.<i> when several share a type. A
// synthetic ".0" under a single typed block matches tf.nested's object wrap.
func addProvisionerRanges(pos *jsonNode, provisioners []any, ranges map[string]hcl.Range) {
	if pos == nil || len(provisioners) == 0 {
		return
	}
	if _, ok := ranges["provisioner"]; !ok {
		ranges["provisioner"] = pos.rng
	}
	if _, ok := ranges["provisioner.0"]; !ok {
		ranges["provisioner.0"] = pos.rng
	}
	count := map[string]int{}
	for _, p := range provisioners {
		m, _ := p.(map[string]any)
		typ, _ := m["type"].(string)
		if typ != "" {
			count[typ]++
		}
	}
	seen := map[string]int{}
	for i, p := range provisioners {
		m, _ := p.(map[string]any)
		typ, _ := m["type"].(string)
		if typ == "" {
			continue
		}
		elem := pos.kid(strconv.Itoa(i))
		prefix := joinPath("provisioner.0", typ)
		if count[typ] > 1 {
			prefix = joinPath(prefix, strconv.Itoa(seen[typ]))
		}
		seen[typ]++
		if _, ok := ranges[prefix]; !ok && elem != nil {
			ranges[prefix] = elem.rng
		}
		elem.kid("expressions").flattenMissing(prefix, ranges)
		if count[typ] == 1 {
			// tf.nested wraps a single typed object as a one-element list.
			indexed := joinPath(prefix, "0")
			if _, ok := ranges[indexed]; !ok && elem != nil {
				ranges[indexed] = elem.rng
			}
			elem.kid("expressions").flattenMissing(indexed, ranges)
		}
	}
}

// flattenMissing records, by dot-joined path, the range of every configuration
// expression and nested block under n that out does not hold. It does not
// descend into an expression: its members are not attributes.
func (n *jsonNode) flattenMissing(prefix string, out map[string]hcl.Range) {
	if n == nil {
		return
	}
	for name, k := range n.kids {
		path := joinPath(prefix, name)
		if _, ok := out[path]; !ok {
			out[path] = k.rng
		}
		if !k.isExpression() {
			k.flattenMissing(path, out)
		}
	}
}

// isExpression reports whether n is a plan configuration expression: an object
// of constant_value and references only.
func (n *jsonNode) isExpression() bool {
	for name := range n.kids {
		if name != exprConstant && name != exprReferences {
			return false
		}
	}
	return true
}
