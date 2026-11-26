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
// doc (the parse of a translation) into lines of the unit file. A line the
// table does not hold maps to the module block's anchor; a value set by
// another file (an include, a tfvars file) maps to the first line of the unit
// file the table points at, or line 1.
func RemapLines(doc model.Document, table model.LineTable, unitFile string) {
	if len(table) == 0 {
		return
	}
	r := remapper{table: table, unit: unitFile}
	for _, m := range table {
		if r.inUnit(&m) {
			r.fallback = m.Real.LineStart
			break
		}
	}
	if r.fallback == 0 {
		r.fallback = 1
	}
	r.node(map[string]interface{}(doc))
}

type remapper struct {
	table    model.LineTable
	unit     string
	fallback int
}

func (r remapper) inUnit(m *model.LineMapping) bool {
	return m.Real.Filename == "" || m.Real.Filename == r.unit
}

func (r remapper) node(node interface{}) {
	switch n := node.(type) {
	case model.Document:
		r.node(map[string]interface{}(n))
	case map[string]interface{}:
		for k, v := range n {
			if k == linesKey {
				r.lines(v)
				continue
			}
			r.node(v)
		}
	case []interface{}:
		for _, v := range n {
			r.node(v)
		}
	}
}

func (r remapper) lines(lines interface{}) {
	switch l := lines.(type) {
	case map[string]model.LineObject:
		for k, obj := range l {
			obj.Line = r.line(obj.Line)
			r.arr(obj.Arr)
			l[k] = obj
		}
	case map[string]*model.LineObject:
		for _, obj := range l {
			if obj != nil {
				obj.Line = r.line(obj.Line)
				r.arr(obj.Arr)
			}
		}
	}
}

func (r remapper) arr(arr []map[string]*model.LineObject) {
	for _, elem := range arr {
		r.lines(elem)
	}
}

// line maps a virtual line; 0 (no line) stays 0.
func (r remapper) line(line int) int {
	if line == 0 {
		return 0
	}
	m, ok := r.table.LookupOrAnchor(line)
	if !ok || !r.inUnit(&m) {
		return r.fallback
	}
	return m.Real.LineStart
}
