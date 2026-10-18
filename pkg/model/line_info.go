/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

// ParseExpansions decodes the plain-map expansion records a Terraform parse
// embeds under _dd_expansions into model form. Values of any other shape are
// skipped.
func ParseExpansions(v interface{}) []ResourceExpansion {
	list, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]ResourceExpansion, 0, len(list))
	for _, raw := range list {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		exp := ResourceExpansion{
			Path:      stringKey(m["path"]),
			Type:      stringKey(m["type"]),
			Name:      stringKey(m["name"]),
			Data:      boolKey(m["data"]),
			Truncated: boolKey(m["truncated"]),
		}
		if addresses, ok := m["addresses"].([]interface{}); ok {
			for _, a := range addresses {
				if s, ok := a.(string); ok {
					exp.Addresses = append(exp.Addresses, s)
				}
			}
		}
		if positions, ok := m["positions"].([]interface{}); ok {
			for _, pos := range positions {
				idx, ok := pos.([]interface{})
				if !ok {
					continue
				}
				out2 := make([]int, 0, len(idx))
				for _, i := range idx {
					if n, ok := indexInt(i); ok {
						out2 = append(out2, n)
					}
				}
				exp.Positions = append(exp.Positions, out2)
			}
		}
		out = append(out, exp)
	}
	return out
}

func stringKey(v interface{}) string {
	s, _ := v.(string)
	return s
}

func boolKey(v interface{}) bool {
	b, _ := v.(bool)
	return b
}

// indexInt reads a position index as written by the converter (Go int) or
// after a JSON round-trip (float64).
func indexInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}
