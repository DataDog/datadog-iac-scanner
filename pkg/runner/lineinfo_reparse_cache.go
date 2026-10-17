/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package runner

import (
	"context"
	"hash/maphash"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	iacparser "github.com/DataDog/datadog-iac-scanner/pkg/parser"
)

// reparseCacheSize bounds how many files keep their reparsed documents.
const reparseCacheSize = 32

// reparseKey identifies the content a file was reparsed from.
type reparseKey struct {
	filename string
	content  uint64
}

type reparseEntry struct {
	once   sync.Once
	parsed iacparser.ParsedDocument
	err    error
}

// reparseCache lets the documents of one file, which are the layers of an
// expanded Terraform file, share a single reparse when their line info is
// loaded, instead of each reparsing and re-expanding the whole file.
type reparseCache struct {
	mu      sync.Mutex
	seed    maphash.Seed
	entries map[reparseKey]*reparseEntry
	order   []reparseKey
}

var layeredReparses = &reparseCache{seed: maphash.MakeSeed(), entries: make(map[reparseKey]*reparseEntry)}

func (c *reparseCache) load(
	f *model.FileMetadata, filename string, reparse func() (iacparser.ParsedDocument, error),
) (iacparser.ParsedDocument, error) {
	key := reparseKey{filename: filename, content: maphash.String(c.seed, f.OriginalData)}
	c.mu.Lock()
	entry, ok := c.entries[key]
	if !ok {
		entry = &reparseEntry{}
		c.entries[key] = entry
		c.order = append(c.order, key)
		if len(c.order) > reparseCacheSize {
			delete(c.entries, c.order[0])
			c.order = c.order[1:]
		}
	}
	c.mu.Unlock()
	entry.once.Do(func() { entry.parsed, entry.err = reparse() })
	return entry.parsed, entry.err
}

// sharedReparse wraps reparse so the documents of a layered file share one
// result while findings are decoded. Other callers reparse on their own, as
// they may modify the tree they get.
func sharedReparse(
	layered bool,
	filename string,
	reparse func(context.Context, *model.FileMetadata) (iacparser.ParsedDocument, error),
) func(context.Context, *model.FileMetadata) (iacparser.ParsedDocument, error) {
	if !layered {
		return reparse
	}
	return func(ctx context.Context, f *model.FileMetadata) (iacparser.ParsedDocument, error) {
		if !model.SharedLineInfo(ctx) {
			return reparse(ctx, f)
		}
		return layeredReparses.load(f, filename, func() (iacparser.ParsedDocument, error) {
			return reparse(ctx, f)
		})
	}
}
