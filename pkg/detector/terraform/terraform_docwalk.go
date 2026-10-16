/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package terraform

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

const unknownTotal = -1

// repeatedBlocks describes the blocks a key part indexes into, as the converted
// document holds them: how many there are and, when the document records it,
// the 0-indexed source line of the block each one was generated from.
type repeatedBlocks struct {
	total int
	lines []int
}

// unknownBlocks is what the document says when it says nothing.
var unknownBlocks = repeatedBlocks{total: unknownTotal}

// docCursor follows a search key through the converted document of the file,
// so the number of blocks a key part indexes into is read from the document
// rather than guessed from the source: that count includes the blocks dynamic
// blocks generated, which only the converter, with the scan's variables, knows.
type docCursor struct {
	node      interface{}
	root      model.Document
	extracted [][]string
	stage     int
}

const (
	cursorStart = iota
	cursorTypeName
	cursorBody
)

func newDocCursor(doc model.Document, extracted [][]string) *docCursor {
	if doc == nil {
		return &docCursor{}
	}
	return &docCursor{node: map[string]interface{}(doc), root: doc, extracted: extracted}
}

// advance consumes the next key part. It returns the blocks the part indexes
// into when it is the index of a repeated block, and unknownBlocks when the
// document does not say.
func (c *docCursor) advance(part string) repeatedBlocks {
	if c.node == nil {
		return unknownBlocks
	}
	for i, str := range c.extracted {
		part = strings.Replace(part, fmt.Sprintf("{{%d}}", i), str[0], 1)
	}
	base, value, indexed := splitIndexedPart(part)
	if c.stage != cursorBody {
		c.enterBlock(base, value, indexed)
		return unknownBlocks
	}
	return c.enterChild(lookup(c.node, base), value, indexed)
}

// enterBlock follows the parts naming a top-level block: an optional resource
// or data keyword, then type[name].
func (c *docCursor) enterBlock(base, value string, indexed bool) {
	if c.stage == cursorStart {
		switch {
		case !indexed && (base == blockTypeResource || base == blockTypeData):
			c.node = c.root[base]
			c.stage = cursorTypeName
			return
		case indexed && labelOnlyBlockTypes[base]:
			c.node = lookup(lookup(c.root, base), value)
			c.stage = cursorBody
			return
		}
		c.node = c.root[blockTypeResource]
	}
	if !indexed {
		c.node = nil
		return
	}
	c.node = lookup(lookup(c.node, base), value)
	c.stage = cursorBody
}

// enterChild follows a part below a block's body.
func (c *docCursor) enterChild(child interface{}, value string, indexed bool) repeatedBlocks {
	if !indexed {
		c.node = singleBlock(child)
		return unknownBlocks
	}
	index, err := strconv.Atoi(value)
	if err != nil {
		c.node = lookup(child, value)
		return unknownBlocks
	}
	switch v := child.(type) {
	case []interface{}:
		c.node = nil
		if index >= 0 && index < len(v) {
			c.node = v[index]
		}
		return repeatedBlocks{total: len(v), lines: blockLines(v)}
	case nil:
		c.node = nil
		return unknownBlocks
	default:
		c.node = nil
		if index == 0 {
			c.node = v
		}
		return repeatedBlocks{total: 1, lines: blockLines([]interface{}{v})}
	}
}

// blockLines reads the source line each block of a repeated block was generated
// from: its own line, or the line of the dynamic block that generated it. It
// returns nil unless every block records one.
func blockLines(blocks []interface{}) []int {
	lines := make([]int, 0, len(blocks))
	for _, block := range blocks {
		line, ok := blockSourceLine(block)
		if !ok {
			return nil
		}
		lines = append(lines, line-1)
	}
	return lines
}

// blockSourceLine is the 1-indexed line recorded in a block's line table.
func blockSourceLine(block interface{}) (int, bool) {
	table, ok := lookup(block, "_dd_lines").(map[string]model.LineObject)
	if ok {
		if def, found := table["_dd__default"]; found && def.Line > 0 {
			return def.Line, true
		}
		return 0, false
	}
	generic, ok := lookup(lookup(block, "_dd_lines"), "_dd__default").(map[string]interface{})
	if !ok {
		return 0, false
	}
	switch n := generic["_dd_line"].(type) {
	case int:
		return n, n > 0
	case float64:
		return int(n), n >= 1
	}
	return 0, false
}

func splitIndexedPart(part string) (base, value string, indexed bool) {
	start := strings.Index(part, "[")
	if start <= 0 || !strings.HasSuffix(part, "]") {
		return part, "", false
	}
	value = strings.Trim(part[start+1:len(part)-1], `"'`)
	if strings.HasPrefix(value, "{{") && strings.HasSuffix(value, "}}") {
		value = value[2 : len(value)-2]
	}
	return part[:start], value, true
}

func lookup(node interface{}, key string) interface{} {
	switch m := node.(type) {
	case map[string]interface{}:
		return m[key]
	case model.Document:
		return m[key]
	}
	return nil
}

// singleBlock is the node of a key part naming a block without an index: the
// block itself, or the only element when it is repeated once.
func singleBlock(child interface{}) interface{} {
	if list, ok := child.([]interface{}); ok {
		if len(list) == 1 {
			return list[0]
		}
		return nil
	}
	return child
}
