/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package detector

import "strconv"

const (
	linesKey       = "_dd_lines"
	lineKey        = "_dd_line"
	arrKey         = "_dd_arr"
	defaultLineKey = "_dd__default"
)

// planLine is the source line of path in a plan line-info document, or -1.
// A list element has no line table of its own: its table is the list entry's
// _dd_arr element, so the walk carries each node's table along. A path part
// naming a list element's key without an index goes through every element in
// order, since a nested block is a list even when written once.
func planLine(doc interface{}, path []string) int {
	table, _ := childAt(doc, linesKey)
	return planLineAt(doc, table, path, -1)
}

// planLineAt walks path from node, whose line table is table and whose own
// line is line.
func planLineAt(node, table interface{}, path []string, line int) int {
	if len(path) == 0 {
		return line
	}
	if list, ok := node.([]interface{}); ok {
		return planListLine(list, table, path)
	}
	entry, _ := childAt(table, "_dd_"+path[0])
	childLine := lineAtPath(entry, []string{lineKey})
	child, ok := childAt(node, path[0])
	if !ok {
		// A null value is dropped from the document but keeps its line.
		if len(path) == 1 {
			return childLine
		}
		return -1
	}
	if _, isList := child.([]interface{}); isList {
		return planLineAt(child, entry, path[1:], childLine)
	}
	return planLineAt(child, ownTable(child, nil), path[1:], childLine)
}

// planListLine walks path from a list whose line entry is entry.
func planListLine(list []interface{}, entry interface{}, path []string) int {
	elements, _ := childAt(entry, arrKey)
	if i, err := strconv.Atoi(path[0]); err == nil {
		if i < 0 || i >= len(list) {
			return -1
		}
		elementTable, _ := childAt(elements, path[0])
		line := lineAtPath(elementTable, []string{defaultLineKey, lineKey})
		return planLineAt(list[i], ownTable(list[i], elementTable), path[1:], line)
	}
	for i := range list {
		if line := planListLine(list, entry, append([]string{strconv.Itoa(i)}, path...)); line > 0 {
			return line
		}
	}
	return -1
}

// ownTable is the line table node carries, or inherited when it has none.
func ownTable(node, inherited interface{}) interface{} {
	if table, ok := childAt(node, linesKey); ok {
		return table
	}
	return inherited
}
