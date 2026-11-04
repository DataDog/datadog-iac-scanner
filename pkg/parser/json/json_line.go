/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"bytes"
	"encoding/json"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// jsonLine holds the source line of every object key and list element of a
// JSON document, in the document's own structure.
type jsonLine struct {
	root *lineNode
}

// lineNode is one value of the document: line is the line of the key naming
// it (an object member) or of its first token (a list element).
type lineNode struct {
	line  int
	keys  map[string]*lineNode
	elems []*lineNode
}

// lineFrame is an object or list being read. pending is the member whose key
// was read last, waiting for its value.
type lineFrame struct {
	node      *lineNode
	object    bool
	expectKey bool
	pending   *lineNode
}

// initializeJSONLine reads the line of every key and list element of doc. A
// string is a key only in key position, so a value never takes a key's line.
func initializeJSONLine(doc []byte) *jsonLine {
	dec := json.NewDecoder(bytes.NewReader(doc))
	root := &lineNode{}
	var stack []*lineFrame
	line, prevOffset := 1, 0
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		offset := int(dec.InputOffset())
		line += bytes.Count(doc[prevOffset:offset], []byte{'\n'})
		prevOffset = offset

		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}

		var node *lineNode
		if len(stack) == 0 {
			node = root
		} else {
			top := stack[len(stack)-1]
			switch {
			case top.object && top.expectKey:
				key, _ := tok.(string)
				top.pending = &lineNode{line: line}
				top.node.keys[key] = top.pending
				top.expectKey = false
				continue
			case top.object:
				node = top.pending
				top.expectKey = true
			default:
				node = &lineNode{line: line}
				top.node.elems = append(top.node.elems, node)
			}
		}

		switch tok {
		case json.Delim('{'):
			node.keys = make(map[string]*lineNode)
			stack = append(stack, &lineFrame{node: node, object: true, expectKey: true})
		case json.Delim('['):
			stack = append(stack, &lineFrame{node: node})
		}
	}
	return &jsonLine{root: root}
}

// setLineInfo will set the line information of keys in json based on the line Information map
func (j *jsonLine) setLineInfo(doc map[string]interface{}) map[string]interface{} {
	doc["_dd_lines"] = setLine(doc, j.root, 0)
	return doc
}

// setLine returns the line table of val, whose lines are node and whose own
// line is def. A nested object gets its own table.
func setLine(val map[string]interface{}, node *lineNode, def int) map[string]*model.LineObject {
	lineMap := map[string]*model.LineObject{
		"_dd__default": {Line: def, Arr: []map[string]*model.LineObject{}},
	}
	for key, v := range val {
		child := node.keys[key]
		if child == nil {
			continue
		}
		entry := &model.LineObject{Line: child.line, Arr: []map[string]*model.LineObject{}}
		switch v := v.(type) {
		case []interface{}:
			entry.Arr = setSeqLines(v, child)
		case map[string]interface{}:
			v["_dd_lines"] = setLine(v, child, child.line)
		}
		lineMap["_dd_"+key] = entry
	}
	return lineMap
}

// setSeqLines is the line table of each element of list, whose lines are node.
// An object element's own line is its first key's, or the list's when it has
// none.
func setSeqLines(list []interface{}, node *lineNode) []map[string]*model.LineObject {
	lineArr := make([]map[string]*model.LineObject, 0, len(list))
	for i, element := range list {
		if i >= len(node.elems) {
			break
		}
		elementNode := node.elems[i]
		switch e := element.(type) {
		case map[string]interface{}:
			lineArr = append(lineArr, setLine(e, elementNode, firstKeyLine(elementNode, node.line)))
		case []interface{}:
			lineArr = append(lineArr, map[string]*model.LineObject{
				"_dd__default": {Line: elementNode.line, Arr: setSeqLines(e, elementNode)},
			})
		default:
			lineArr = append(lineArr, map[string]*model.LineObject{
				"_dd__default": {Line: elementNode.line},
			})
		}
	}
	return lineArr
}

func firstKeyLine(node *lineNode, def int) int {
	first := -1
	for _, child := range node.keys {
		if first == -1 || child.line < first {
			first = child.line
		}
	}
	if first == -1 {
		return def
	}
	return first
}
