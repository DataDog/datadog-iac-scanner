package docker

import (
	"context"
	"encoding/json"
	"slices"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/dockerfile"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/klauspost/compress/s2"
)

type sourceLocationKey struct{}
type locationFileKey struct{}

// sourceLocations keeps a compact encoding of the JSON already emitted by the
// parser, plus sparse raw-value overrides. This permits the scan document, AST
// and input buffer to be released independently, even without any findings.
type sourceLocations struct {
	document []byte
	values   map[int]json.RawMessage
	ignore   []int
	lines    dockerfile.SourceLines
}

func (saved *sourceLocations) expandCommand(cmd *Command, scope *variableScope, global map[string]string, lex, declaration *wordExpander) {
	raw := slices.Clone(cmd.Value)
	scope.expandCommand(cmd, global, lex, declaration)
	if !slices.Equal(raw, cmd.Value) {
		if saved.values == nil {
			saved.values = make(map[int]json.RawMessage)
		}
		// []string always marshals; this also preserves the parser's UTF-8 policy.
		encoded, _ := json.Marshal(raw)
		saved.values[cmd.StartLine] = encoded
	}
}

func (saved *sourceLocations) parse(ctx context.Context, content []byte) (
	resolved []byte, documents []model.Document, ignore []int, resolvedFiles map[string]model.ResolvedFile, err error) {
	// Decoding is O(N), and restoring overrides is O(C). Files without
	// findings never materialize this independent source document.
	data, err := s2.Decode(nil, saved.document)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, nil, nil, err
	}
	if err := saved.restoreCommands(doc["args"]); err != nil {
		return nil, nil, nil, nil, err
	}
	for _, commands := range doc["command"].(map[string]interface{}) {
		if err := saved.restoreCommands(commands); err != nil {
			return nil, nil, nil, nil, err
		}
	}

	if file, ok := ctx.Value(locationFileKey{}).(*model.FileMetadata); ok {
		file.DetectionLines(dockerfile.SourceViewKey, saved.lines.Apply)
	}
	return content, []model.Document{doc}, saved.ignore, nil, nil
}

// restoreCommands mutates only the independently decoded source tree.
func (saved *sourceLocations) restoreCommands(value interface{}) error {
	commands, _ := value.([]interface{})
	for _, entry := range commands {
		cmd := entry.(map[string]interface{})
		if raw, changed := saved.values[int(cmd["_dd_line"].(float64))]; changed {
			var value interface{}
			if err := json.Unmarshal(raw, &value); err != nil {
				return err
			}
			cmd["Value"] = value
		}
	}
	return nil
}

// SourceContext retains compact source metadata only. Dispatch's BuildKit AST
// and input bytes are released before evaluation, even for files without findings.
func (p *Parser) SourceContext(ctx context.Context) func(context.Context) context.Context {
	if saved, ok := ctx.Value(sourceLocationKey{}).(*sourceLocations); ok {
		return func(next context.Context) context.Context { return context.WithValue(next, sourceLocationKey{}, saved) }
	}
	saved, ok := dockerfile.SavedSource(ctx).(*sourceLocations)
	if !ok {
		return nil
	}
	return func(next context.Context) context.Context { return context.WithValue(next, sourceLocationKey{}, saved) }
}

// FinishContext explicitly ends dispatch ownership after all source transfers.
func (p *Parser) FinishContext(ctx context.Context) { dockerfile.DetachSource(ctx) }

// S2 requires worst-case capacity while encoding. Pool that scratch space and
// keep only an exactly sized result, rather than retaining uncompressed-size
// backing arrays for every Dockerfile until evaluation finishes.
var sourceEncodeBuffers = sync.Pool{New: func() any { return new([]byte) }}

func encodeSourceDocument(document []byte) []byte {
	buffer := sourceEncodeBuffers.Get().(*[]byte)
	encoded := s2.Encode(*buffer, document)
	result := slices.Clone(encoded)
	if cap(encoded) <= 1<<20 {
		*buffer = encoded
		sourceEncodeBuffers.Put(buffer)
	}
	return result
}
