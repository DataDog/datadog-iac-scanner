/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package placeholders holds the outputs the fake Pulumi engine answers data
// sources (invokes) with.
//
// invokes.json.gz is generated from the Pulumi provider schemas (Apache-2.0)
// at the versions recorded in invokes.meta.json. Regenerate it (this downloads
// the schemas) from the repository root with:
//
//	make generate-pulumi-placeholders
package placeholders

import (
	"bytes"
	"compress/gzip"
	_ "embed" // embeds the generated table
	"encoding/json"
	"io"
	"sync"
)

//go:embed invokes.json.gz
var table []byte

var (
	loadOnce sync.Once
	raw      map[string]json.RawMessage
	loadErr  error

	cacheMu sync.Mutex
	cache   = map[string]map[string]any{}
)

func load() {
	r, err := gzip.NewReader(bytes.NewReader(table))
	if err != nil {
		loadErr = err
		return
	}
	data, err := io.ReadAll(r)
	if err != nil {
		loadErr = err
		return
	}
	loadErr = json.Unmarshal(data, &raw)
}

// Invoke returns the placeholder outputs for a function token. The returned
// map is shared: callers must not modify it.
func Invoke(token string) (map[string]any, bool) {
	loadOnce.Do(load)
	if loadErr != nil {
		return nil, false
	}
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if v, ok := cache[token]; ok {
		return v, true
	}
	msg, ok := raw[token]
	if !ok {
		return nil, false
	}
	var v map[string]any
	if err := json.Unmarshal(msg, &v); err != nil {
		return nil, false
	}
	cache[token] = v
	return v, true
}

// Len is the number of functions in the table.
func Len() int {
	loadOnce.Do(load)
	return len(raw)
}

// LoadError reports a corrupt embedded table.
func LoadError() error {
	loadOnce.Do(load)
	return loadErr
}
