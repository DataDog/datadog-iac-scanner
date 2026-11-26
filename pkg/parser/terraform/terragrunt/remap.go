/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package terragrunt

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// linesKey is the document key that holds line information.
const linesKey = "_dd_lines"

// RemapLines rewrites in place the virtual lines of the line information of
// doc (the parse of a translation) into lines of the file that sets each
// value. A line the table does not hold maps to the module block's anchor.
func RemapLines(doc model.Document, table model.LineTable) {
	if len(table) == 0 {
		return
	}
	remapNode(map[string]interface{}(doc), table)
}

func remapNode(node interface{}, table model.LineTable) {
	switch n := node.(type) {
	case model.Document:
		remapNode(map[string]interface{}(n), table)
	case map[string]interface{}:
		for k, v := range n {
			if k == linesKey {
				remapLines(v, table)
				continue
			}
			remapNode(v, table)
		}
	case []interface{}:
		for _, v := range n {
			remapNode(v, table)
		}
	}
}

func remapLines(lines interface{}, table model.LineTable) {
	switch l := lines.(type) {
	case map[string]model.LineObject:
		for k, obj := range l {
			obj.Line = realLine(obj.Line, table)
			remapArr(obj.Arr, table)
			l[k] = obj
		}
	case map[string]*model.LineObject:
		for _, obj := range l {
			if obj != nil {
				obj.Line = realLine(obj.Line, table)
				remapArr(obj.Arr, table)
			}
		}
	}
}

func remapArr(arr []map[string]*model.LineObject, table model.LineTable) {
	for _, elem := range arr {
		remapLines(elem, table)
	}
}

// realLine maps a virtual line; 0 (no line) stays 0.
func realLine(line int, table model.LineTable) int {
	if line == 0 {
		return 0
	}
	if m, ok := table.LookupOrAnchor(line); ok {
		return m.Real.LineStart
	}
	return 0
}
