/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package cicd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"reflect"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/cicd/gitlab"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/yamlnode"
	"gopkg.in/yaml.v3"
)

// parseGitLabCI preserves the legacy parser interface for direct callers.
func (p *Parser) parseGitLabCI(ctx context.Context, content []byte, path string) (
	resolved []byte, docs []model.Document, ignored []int, files map[string]model.ResolvedFile, err error,
) {
	out, err := p.parseGitLabOutput(ctx, content, path)
	if err == nil {
		for index := range out.Sources {
			if out.Sources[index].Incomplete {
				err = gitlab.ErrConditionalInclude
				break
			}
		}
	}
	return out.Resolved, out.Documents, out.IgnoreLines, out.ResolvedFiles, err
}

func (p *Parser) parseGitLabOutput(ctx context.Context, content []byte, path string) (model.ParseOutput, error) {
	ctx, cancel := gitlab.WithLimits(ctx)
	defer cancel()
	if !gitlab.Reserve(ctx, 0, len(content)) {
		return model.ParseOutput{}, context.Cause(ctx)
	}
	fsys, finishRequests := gitlab.ScopeMissingRequests(ctx, p.FS)
	defer finishRequests()
	state := gitlab.NewFileState(ctx, fsys, p.RepoRoot, path)
	output := model.ParseOutput{Resolved: content, ResolvedFiles: map[string]model.ResolvedFile{}}
	written := string(content)
	snapshot := state.RegisterSource(nil, path, written, 0)
	output.IgnoreLines = snapshot.IgnoreLines
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	sourceIndex := 0
	for {
		var node yaml.Node
		err := decoder.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil {
			return model.ParseOutput{}, fmt.Errorf("%w %s: %w", gitlab.ErrInvalidPipeline, path, err)
		}
		if yamlnode.IsImplicitEmptyDocument(&node) {
			continue
		}
		root := node.Content[0]
		state.RegisterSource(root, path, written, sourceIndex)
		state.TransformDocument(root)
		if ctx.Err() != nil {
			return model.ParseOutput{}, context.Cause(ctx)
		}
		if root.Kind != yaml.MappingNode {
			return model.ParseOutput{}, fmt.Errorf("%w %s: expected a mapping", gitlab.ErrInvalidPipeline, path)
		}
		doc := model.Document{}
		decodeContext := model.WithLazyLineInfo(model.WithYAMLFilePath(ctx, path))
		if err := doc.UnmarshalSharedNativeYAML(decodeContext, root); err != nil {
			return model.ParseOutput{}, fmt.Errorf("%w %s: %w", gitlab.ErrInvalidPipeline, path, err)
		}
		appendGitLabDocument(&output, state, root, doc, snapshot, sourceIndex)
		sourceIndex++
	}
	if len(output.Documents) == 0 {
		return model.ParseOutput{}, yamlParser.ErrNoDocuments
	}
	if !parser.IsLineInfoOnly(ctx) {
		globals := p.enhanceGitLabCIScripts(ctx, output.Documents)
		for index := range output.Sources {
			output.Sources[index].GlobalScripts = globals[index]
		}
	}
	if ctx.Err() != nil {
		return model.ParseOutput{}, context.Cause(ctx)
	}
	snapshots := state.Sources()
	dependencies := state.Dependencies()
	for i := range output.Sources {
		output.Sources[i].Incomplete = state.UncertainIncludes()
		output.Sources[i].Snapshots = snapshots
		output.Sources[i].Dependencies = dependencies
	}
	return output, nil
}

// Each source YAML document compiles to one effective pipeline. Sources are
// location metadata, not separate rule inputs: jobs can depend on other jobs
// and globals regardless of which included file supplied them.
func appendGitLabDocument(
	output *model.ParseOutput, state *gitlab.FileState, root *yaml.Node,
	doc model.Document, snapshot *model.SourceSnapshot, index int,
) {
	output.Documents = append(output.Documents, doc)
	output.Sources = append(output.Sources, model.ParsedSource{Path: snapshot.Path, Content: snapshot.Content,
		DocumentIndex: index, LineOverlay: state.LineOverlay(root), Dialect: gitlab.Dialect, Snapshot: snapshot})
}

// ParseOutput carries the written source of every emitted GitLab document.
func (p *Parser) ParseOutput(ctx context.Context, content []byte, path string, resolve bool, depth int) (model.ParseOutput, error) {
	if gitlab.ShouldParse(content, path) {
		return p.parseGitLabOutput(ctx, content, path)
	}
	resolved, docs, ignore, files, err := p.Parse(ctx, content, path, resolve, depth)
	return model.ParseOutput{Resolved: resolved, Documents: docs, IgnoreLines: ignore, ResolvedFiles: files}, err
}

// enhanceGitLabCIScripts parses shell commands in GitLab CI script,
// before_script, after_script, and hooks.pre_get_sources_script blocks using
// the CI/CD tree-sitter bash parser.
func (p *Parser) enhanceGitLabCIScripts(ctx context.Context, documents []model.Document) []map[string]interface{} {
	enricher := newScriptEnricher()
	globals := make([]map[string]interface{}, len(documents))
	for index, doc := range documents {
		if ctx.Err() != nil {
			return globals
		}
		if gitlab.IsSpecHeaderDocument(doc) {
			continue
		}
		globals[index] = parseGlobalScripts(ctx, enricher, doc)

		if def, ok := doc["default"].(map[string]interface{}); ok {
			doc["default"] = enricher.enrichMapping(ctx, def, defaultScripts)
		}

		for key, raw := range doc {
			if ctx.Err() != nil {
				return globals
			}
			if gitlab.IsReservedTopLevelKeyword(key) {
				continue
			}
			job, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			doc[key] = enricher.enrichMapping(ctx, job, jobScripts)
		}
	}
	return globals
}

func parseGlobalScripts(ctx context.Context, e *scriptEnricher, document model.Document) map[string]interface{} {
	var globals map[string]interface{}
	for _, field := range []string{"before_script", "after_script"} {
		if raw, present := document[field]; present {
			temporary := map[string]interface{}{field: raw}
			e.parseField(ctx, temporary, field)
			if parsed := temporary["_parsed_"+field]; parsed != nil {
				if globals == nil {
					globals = make(map[string]interface{})
				}
				globals[field] = parsed
			}
		}
	}
	return globals
}

// maxJoinedScriptBytes bounds the materialized shell script string passed to
// tree-sitter for a single job script block (8 MiB).
const maxJoinedScriptBytes = 8 * 1024 * 1024

type joinedScript struct {
	text string
	ok   bool
}

type scriptSliceKey struct {
	ptr    uintptr
	length int
}
type scriptEnricher struct {
	joined   map[scriptSliceKey]joinedScript
	parsed   map[string]*ParsedRun
	steps    map[scriptSliceKey]enrichedSteps
	mappings map[scriptMapKey]map[string]interface{}
}

type scriptMapKey struct {
	source reflect.Value
	kind   scriptContext
}

type scriptContext uint8

const (
	jobScripts scriptContext = iota
	defaultScripts
	hookScripts
	stepScripts
	nativeMapAllocationBytes = 64
	nativeMapEntryBytes      = 32
)

type enrichedSteps struct {
	source, owned []interface{}
}

func newScriptEnricher() *scriptEnricher {
	return &scriptEnricher{
		joined: make(map[scriptSliceKey]joinedScript), parsed: make(map[string]*ParsedRun),
		steps:    make(map[scriptSliceKey]enrichedSteps),
		mappings: make(map[scriptMapKey]map[string]interface{}),
	}
}

// Analysis owns its mapping containers. A raw mapping can simultaneously be a
// job and literal trigger input; enriching either must not change the other.
func (e *scriptEnricher) enrichMapping(ctx context.Context, raw map[string]interface{}, kind scriptContext) map[string]interface{} {
	key := scriptMapKey{reflect.ValueOf(raw), kind}
	if cached := e.mappings[key]; cached != nil {
		return cached
	}
	if !gitlab.Reserve(ctx, 1, nativeMapAllocationBytes+len(raw)*nativeMapEntryBytes) {
		return raw
	}
	owned := maps.Clone(raw)
	e.mappings[key] = owned
	var fields []string
	switch kind {
	case jobScripts:
		fields = []string{"script", "before_script", "after_script"}
	case defaultScripts:
		fields = []string{"before_script", "after_script"}
	case hookScripts:
		fields = []string{"pre_get_sources_script"}
	case stepScripts:
		fields = []string{"script"}
	}
	for _, field := range fields {
		e.parseField(ctx, owned, field)
	}
	if kind == jobScripts {
		e.parseRunSteps(ctx, owned)
	}
	if kind == jobScripts || kind == defaultScripts {
		if hooks, ok := owned["hooks"].(map[string]interface{}); ok {
			owned["hooks"] = e.enrichMapping(ctx, hooks, hookScripts)
		}
	}
	return owned
}

// run-step arrays can be reused by aliases, inputs and references just like
// script arrays. Enrich each shared step list once and retain predefined steps.
const stepCacheEntryBytes = 64

func (e *scriptEnricher) parseRunSteps(ctx context.Context, job map[string]interface{}) {
	steps, ok := job["run"].([]interface{})
	if !ok || len(steps) == 0 {
		return
	}
	key := scriptSliceKey{ptr: reflect.ValueOf(steps).Pointer(), length: len(steps)}
	if cached, exists := e.steps[key]; exists {
		job["run"] = cached.owned
		return
	}
	if !gitlab.Reserve(ctx, 1, stepCacheEntryBytes+len(steps)*16) {
		return
	}
	owned := append([]interface{}(nil), steps...)
	e.steps[key] = enrichedSteps{source: steps, owned: owned}
	job["run"] = owned
	for index, raw := range steps {
		if !gitlab.Reserve(ctx, 1, 0) {
			return
		}
		if step, ok := raw.(map[string]interface{}); ok {
			owned[index] = e.enrichMapping(ctx, step, stepScripts)
		}
	}
}

func (e *scriptEnricher) parseField(ctx context.Context, container map[string]interface{}, field string) {
	if _, alreadyParsed := container["_parsed_"+field].(*ParsedRun); alreadyParsed {
		return
	}
	delete(container, "_parsed_"+field)
	raw, exists := container[field]
	if !exists {
		return
	}
	joined, ok := joinGitLabScript(ctx, raw, map[uintptr]struct{}{}, e.joined)
	if !ok {
		gitlab.ExceedLimit(ctx, "joined script bytes")
		return
	}
	if strings.TrimSpace(joined) == "" {
		return
	}
	if cached, ok := e.parsed[joined]; ok {
		container["_parsed_"+field] = cached
		return
	}
	if !gitlab.Reserve(ctx, 1, len(joined)) {
		return
	}
	parsed := parseRunBlock(joined, bash_shell)
	if parsed.Error != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Err(parsed.Error).Msgf("Failed to parse shell expressions in GitLab CI %s block", field)
	}
	e.parsed[joined] = parsed
	container["_parsed_"+field] = parsed
}

func joinGitLabScript(
	ctx context.Context,
	val interface{},
	inProgress map[uintptr]struct{},
	memo map[scriptSliceKey]joinedScript,
) (string, bool) {
	if ctx.Err() != nil {
		return "", false
	}
	switch v := val.(type) {
	case string:
		if len(v) > maxJoinedScriptBytes {
			return "", false
		}
		return v, true
	case []interface{}:
		return joinGitLabScriptSlice(ctx, v, inProgress, memo)
	default:
		return "", true
	}
}

func joinGitLabScriptSlice(
	ctx context.Context,
	v []interface{},
	inProgress map[uintptr]struct{},
	memo map[scriptSliceKey]joinedScript,
) (string, bool) {
	if len(v) == 0 {
		return "", true
	}
	ptr := reflect.ValueOf(v).Pointer()
	key := scriptSliceKey{ptr: ptr, length: len(v)}
	if cached, seen := memo[key]; seen {
		return cached.text, cached.ok
	}
	if _, gray := inProgress[ptr]; gray {
		return "", true
	}
	if len(v) > gitlab.MaxFlattenedListEntries {
		memo[key] = joinedScript{ok: false}
		return "", false
	}
	inProgress[ptr] = struct{}{}

	lines := make([]string, 0, len(v))
	totalBytes := 0
	for _, elem := range v {
		if ctx.Err() != nil {
			delete(inProgress, ptr)
			return "", false
		}
		s, ok := joinGitLabScript(ctx, elem, inProgress, memo)
		if !ok {
			delete(inProgress, ptr)
			memo[key] = joinedScript{ok: false}
			return "", false
		}
		if s == "" {
			continue
		}
		sep := 0
		if len(lines) > 0 {
			sep = 1
		}
		if totalBytes+sep+len(s) > maxJoinedScriptBytes {
			delete(inProgress, ptr)
			memo[key] = joinedScript{ok: false}
			return "", false
		}
		totalBytes += sep + len(s)
		lines = append(lines, s)
	}
	delete(inProgress, ptr)
	if !gitlab.Reserve(ctx, 1, totalBytes) {
		return "", false
	}
	res := strings.Join(lines, "\n")
	memo[key] = joinedScript{text: res, ok: true}
	return res, true
}
