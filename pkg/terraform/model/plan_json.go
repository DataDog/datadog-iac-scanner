/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/hashicorp/hcl/v2"
)

// jsonNode is the source range of a JSON value: an object member's range runs
// from its key to the end of its value. Kids are keyed by member name or
// decimal element index.
type jsonNode struct {
	rng  hcl.Range
	kids map[string]*jsonNode
}

func (n *jsonNode) kid(names ...string) *jsonNode {
	for _, name := range names {
		if n == nil {
			return nil
		}
		n = n.kids[name]
	}
	return n
}

// flatten records the range of every value under n by dot-joined path.
func (n *jsonNode) flatten(prefix string, out map[string]hcl.Range) {
	if n == nil {
		return
	}
	for name, k := range n.kids {
		path := joinPath(prefix, name)
		out[path] = k.rng
		k.flatten(path, out)
	}
}

// jsonPositions decodes src again, token by token, and returns the ranges of
// the values under the top-level members keep names.
func jsonPositions(filename string, src []byte, keep map[string]bool) (*jsonNode, error) {
	w := &jsonWalker{src: src, filename: filename, dec: json.NewDecoder(bytes.NewReader(src))}
	w.lineStarts = []int{0}
	for i, c := range src {
		if c == '\n' {
			w.lineStarts = append(w.lineStarts, i+1)
		}
	}
	root := &jsonNode{}
	start := w.tokenStart()
	tok, err := w.dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("plan is not a JSON object")
	}
	for w.dec.More() {
		keyStart := w.tokenStart()
		key, err := w.key()
		if err != nil {
			return nil, err
		}
		var node *jsonNode
		if keep[key] {
			node = &jsonNode{}
			if root.kids == nil {
				root.kids = map[string]*jsonNode{}
			}
			root.kids[key] = node
		}
		if err := w.value(node); err != nil {
			return nil, err
		}
		if node != nil {
			node.rng = w.rng(keyStart, int(w.dec.InputOffset()))
		}
	}
	if _, err := w.dec.Token(); err != nil {
		return nil, err
	}
	root.rng = w.rng(start, int(w.dec.InputOffset()))
	return root, nil
}

type jsonWalker struct {
	src        []byte
	filename   string
	dec        *json.Decoder
	lineStarts []int
}

// tokenStart is the offset of the next token: the decoder's offset is the end
// of the previous one, before separators.
func (w *jsonWalker) tokenStart() int {
	off := int(w.dec.InputOffset())
	for off < len(w.src) {
		switch w.src[off] {
		case ' ', '\t', '\r', '\n', ',', ':':
			off++
			continue
		}
		break
	}
	return off
}

func (w *jsonWalker) key() (string, error) {
	tok, err := w.dec.Token()
	if err != nil {
		return "", err
	}
	key, ok := tok.(string)
	if !ok {
		return "", errors.New("JSON object key is not a string")
	}
	return key, nil
}

// value reads one value, recording the ranges of its members and elements
// under node; a nil node skips it.
func (w *jsonWalker) value(node *jsonNode) error {
	tok, err := w.dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	i := 0
	for w.dec.More() {
		start := w.tokenStart()
		name := ""
		if d == '{' {
			if name, err = w.key(); err != nil {
				return err
			}
		} else {
			name = strconv.Itoa(i)
			i++
		}
		var kid *jsonNode
		if node != nil {
			kid = &jsonNode{}
			if node.kids == nil {
				node.kids = map[string]*jsonNode{}
			}
			node.kids[name] = kid
		}
		if err := w.value(kid); err != nil {
			return err
		}
		if kid != nil {
			kid.rng = w.rng(start, int(w.dec.InputOffset()))
		}
	}
	_, err = w.dec.Token()
	return err
}

func (w *jsonWalker) rng(start, end int) hcl.Range {
	return hcl.Range{Filename: w.filename, Start: w.pos(start), End: w.pos(end)}
}

func (w *jsonWalker) pos(off int) hcl.Pos {
	line := sort.Search(len(w.lineStarts), func(i int) bool { return w.lineStarts[i] > off }) - 1
	return hcl.Pos{Line: line + 1, Column: off - w.lineStarts[line] + 1, Byte: off}
}
