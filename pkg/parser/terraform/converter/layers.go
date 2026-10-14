/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package converter

import (
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// Expanded is a block whose count or for_each expands into instances that
// differ from one another.
type Expanded struct {
	// Path is the block type followed by its labels: where the block sits in
	// the document.
	Path []string
	// Values are the converted instances, the first of which is in the first
	// document.
	Values []model.Document
}

// BuildLayers returns the documents of a file whose blocks expand: first, that
// holds every block with the first instance of each expanded one, and one
// more for each position beyond that, as many as the block with the most
// instances. A later document is the whole file again with every expanded
// block read at that position, or as in the first document when it has no
// instance there, so rules that look across the blocks of a document see the
// same configuration in each. A document key stays the block's name, so rules
// and line detection read an instance the way they read the block. A finding
// on a block that is the same in several documents is therefore repeated;
// callers drop the repeats.
func BuildLayers(first model.Document, expanded []Expanded) []model.Document {
	layers := []model.Document{first}
	count := 0
	for _, block := range expanded {
		count = max(count, len(block.Values))
	}
	for position := 1; position < count; position++ {
		layers = append(layers, layerAt(first, expanded, position))
	}
	return layers
}

// layerAt copies first with each expanded block replaced by its instance at
// position, sharing everything else with first.
func layerAt(first model.Document, expanded []Expanded, position int) model.Document {
	layer := shallowCopy(first)
	copied := make(map[string]bool)
	for _, block := range expanded {
		if position >= len(block.Values) {
			continue
		}
		cur := layer
		for depth, key := range block.Path[:len(block.Path)-1] {
			next, ok := cur[key].(model.Document)
			if !ok {
				cur = nil
				break
			}
			prefix := strings.Join(block.Path[:depth+1], "\x00")
			if !copied[prefix] {
				next = shallowCopy(next)
				cur[key] = next
				copied[prefix] = true
			}
			cur = next
		}
		if cur != nil {
			cur[block.Path[len(block.Path)-1]] = block.Values[position]
		}
	}
	return layer
}

func shallowCopy(doc model.Document) model.Document {
	out := make(model.Document, len(doc))
	for key, value := range doc {
		out[key] = value
	}
	return out
}
