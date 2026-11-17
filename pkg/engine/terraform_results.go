/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/hashicorp/hcl/v2"
	"github.com/pkg/errors"
)

// Result fields of the Terraform Terraform rule contract (see common.finding).
// The engine derives the document, resource, search key, location and
// fingerprint of such a result from the block the id names.
const (
	blockResultField    = "_dd_id"
	pathResultField     = "path"
	keyResultField      = "key"
	evidenceResultField = "evidence"
)

// unknownShown replaces the unknown value placeholder in text shown to users.
const unknownShown = "${...}"

// errUnknownBlock is a result naming no block of the input it was evaluated on.
var errUnknownBlock = errors.New("result names no Terraform block of the input")

// terraformInput is the Terraform input of an evaluation under rule contract
// v2 and what decoding its results needs.
type terraformInput struct {
	projection *project.Projection
	// base is the directory block files are relative to.
	base string
	// files maps the fileKey of an absolute file path to the scanned file.
	files       map[string]*model.FileMetadata
	repoPath    string
	placeholder string
	outputLines int
	attribution *terraformAttribution
	// rules holds the harvest and the unknown gate of every rule.
	rules *terraformRules
	// fan maps the results of a unit root to the roots with the same content.
	fan *terraformFanout
	// written holds the findings already reported on blocks written once in
	// a module but modeled per instance.
	written *writtenFindings
}

// writtenFindings is the set of findings on static blocks of module
// instances, shared by every root of a scan.
type writtenFindings struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func newWrittenFindings() *writtenFindings {
	return &writtenFindings{seen: map[string]struct{}{}}
}

// first reports whether key is seen for the first time.
func (w *writtenFindings) first(key string) bool {
	if w == nil {
		return true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.seen[key]; ok {
		return false
	}
	w.seen[key] = struct{}{}
	return true
}

// staticInModule reports a block of a module instance that is not a
// resource, data or ephemeral block: variables, outputs, providers, module
// calls, locals and terraform blocks have one meaning per written block, not
// per instance or calling root.
func staticInModule(loc *project.Located) bool {
	if loc.Block == nil || loc.Block.Module == nil || loc.Block.Module.Address == "" {
		return false
	}
	switch loc.Kind {
	case address.KindResource, address.KindData, address.KindEphemeral:
		return false
	}
	return true
}

// terraformAttribution attributes findings in module instances to their root
// call. Rules decode concurrently, so the cache is guarded.
type terraformAttribution struct {
	mu     sync.Mutex
	lookup moduleProvenanceLookup
	cache  *moduleAttributionCache
}

func (a *terraformAttribution) attribute(loc *project.Located, file, repoPath string) *model.ModuleAttribution {
	if a == nil || loc.Block == nil || loc.Block.Module == nil || len(loc.Block.Module.Chain) == 0 {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return callAttribution(loc.Block.Module.Chain, file, repoPath, a.lookup, a.cache)
}

// resource attributes a resource of a module instance to its root call.
func (a *terraformAttribution) resource(r *tfeval.ResolvedResource, repoPath string) *model.ModuleAttribution {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cache.attribution(r, repoPath, a.lookup)
}

// vulnerability decodes a result naming a block: its location comes from the
// block's source ranges at the result's path, its identity from the block.
func (t *terraformInput) vulnerability(
	ctx context.Context, qCtx *QueryContext, vObj map[string]interface{}, useOldSeverities bool, queryDuration time.Duration,
) (*model.Vulnerability, error) {
	id, _ := vObj[blockResultField].(string)
	var loc *project.Located
	if t != nil {
		loc = t.projection.Blocks[id]
	}
	if loc == nil {
		qCtx.unknownBlocks++
		return nil, fmt.Errorf("%w: %q", errUnknownBlock, id)
	}
	path, err := resultPath(vObj[pathResultField])
	if err != nil {
		return nil, err
	}
	key, err := resultKey(vObj[keyResultField])
	if err != nil {
		return nil, err
	}

	rng := loc.Range(path)
	file := t.reportedFile(loc, rng)
	contextLogger := logger.FromContext(ctx)
	if file == nil {
		contextLogger.Debug().Str("block", id).Msg("Dropping a result on a block outside the scanned files")
		return nil, ErrNoResult
	}

	vObj = mergeWithMetadata(vObj, qCtx.Query.Metadata.Metadata)
	logWithFields := contextLogger.With().
		Str("scanID", qCtx.scanID).
		Str("fileName", file.FilePath).
		Str("queryName", qCtx.Query.Metadata.Query).
		Logger()
	overrideKey, _ := vObj["overrideKey"].(string)
	vulnerability := ruleVulnerability(ctx, qCtx, vObj, ruleFields{
		overrideKey:   overrideKey,
		platform:      getStringFromMap(ctx, "platform", "", overrideKey, vObj, &logWithFields),
		queryID:       getStringFromMap(ctx, "id", DefaultQueryID, overrideKey, vObj, &logWithFields),
		legacyQueryID: getOptionalStringKey(ctx, "legacyId", DefaultQueryID, overrideKey, vObj, &logWithFields),
	}, &logWithFields, useOldSeverities, queryDuration)

	declaring := project.JoinRoot(t.base, loc.File)
	span := loc.Span()
	at := resourceLocation(rng)
	block := resourceLocation(span)
	if filepath.Clean(rng.Filename) != filepath.Clean(span.Filename) {
		block = at
	}
	lines := file.Lines()

	vulnerability.FileID = file.ID
	vulnerability.FileName = file.FilePath
	vulnerability.Line = rng.Start.Line
	vulnerability.VulnerabilityLocation = block
	vulnerability.RemediationLocation = at
	vulnerability.BlockLocation = block
	if filepath.Clean(rng.Filename) == filepath.Clean(file.FilePath) {
		// Fixes are built on these lines, the untrimmed line and the
		// insertion point, as for the legacy detector.
		vulnerability.FileSource = lines
		if syn := loc.Block.Syntax; syn != nil && filepath.Clean(syn.TypeRange.Filename) == filepath.Clean(file.FilePath) {
			line, col := terraform.RemediationPoint(syn, rng.Start.Line, file)
			vulnerability.RemediationLocation = model.ResourceLocation{
				Start: model.ResourceLine{Line: line, Col: col},
				End:   model.ResourceLine{Line: line, Col: col},
			}
		}
	}
	vulnerability.VulnLines = detector.GetAdjacentVulnLines(rng.Start.Line-1, t.outputLines, lines)
	if i := rng.Start.Line - 1; i >= 0 && i < len(lines) {
		vulnerability.LineWithVulnerability = lines[i]
	}
	if filepath.Clean(file.FilePath) != filepath.Clean(declaring) && t.file(declaring) != nil {
		vulnerability.DetectedFileName = t.file(declaring).FilePath
		vulnerability.DetectedLineWithVulnerability = vulnerability.LineWithVulnerability
	}
	vulnerability.ResourceType, vulnerability.ResourceName = blockResource(loc)
	vulnerability.SearchKey = searchKey(loc.Address, path, key)
	vulnerability.IdentityKey = identityKey(path, key)
	vulnerability.Remediation = strings.ReplaceAll(vulnerability.Remediation, t.placeholder, unknownShown)
	if staticInModule(loc) {
		return t.writtenOnce(vulnerability, loc, file, rng, path, key, vObj)
	}
	t.setModule(vulnerability, loc, declaring, span)
	vulnerability.RelatedLocations = t.evidence(vObj[evidenceResultField])
	return vulnerability, nil
}

// writtenOnce reports v, on a static block of a module instance, once on the
// written block, as the legacy path does: with the address the module writes
// and no module attribution.
func (t *terraformInput) writtenOnce(
	v *model.Vulnerability, loc *project.Located, file *model.FileMetadata, rng hcl.Range,
	path []any, key string, vObj map[string]interface{},
) (*model.Vulnerability, error) {
	local := strings.TrimPrefix(loc.Address, loc.Block.Module.Address+".")
	v.SearchKey = searchKey(local, path, key)
	if !t.written.first(strings.Join([]string{v.QueryID, file.FilePath,
		strconv.Itoa(rng.Start.Line), strconv.Itoa(rng.Start.Column), v.IdentityKey}, "\x00")) {
		return nil, ErrNoResult
	}
	v.RelatedLocations = t.evidence(vObj[evidenceResultField])
	return v, nil
}

// reportedFile is the scanned file a result at rng on loc is reported in: the
// file holding rng, else the file declaring the block, else the root file
// calling its module.
func (t *terraformInput) reportedFile(loc *project.Located, rng hcl.Range) *model.FileMetadata {
	if file := t.file(rng.Filename); file != nil {
		return file
	}
	if file := t.file(project.JoinRoot(t.base, loc.File)); file != nil {
		return file
	}
	return t.callerFile(loc)
}

// setModule attributes a finding on a block declared in a module instance to
// the instance's call chain.
func (t *terraformInput) setModule(v *model.Vulnerability, loc *project.Located, declaring string, span hcl.Range) {
	m := loc.Block.Module
	if m == nil || m.Address == "" {
		return
	}
	v.ModuleCallChain = moduleCallChainKey(m.Chain, m.Address, t.chainBase())
	if inst := loc.Instance(); inst != nil && m.Scope != nil {
		if r, _ := resolvedBlock(loc.Block, inst, m, declaring); r != nil {
			// As in legacy: who controls the finding's line, the caller's
			// argument and the fix all come from the resource's attribution.
			if attr := t.attribution.resource(r, t.repoPath); attr != nil {
				v.ModuleAttribution = findingAttribution(attr, v)
				return
			}
		}
	}
	v.ModuleAttribution = t.attribution.attribute(loc, declaring, t.repoPath)
	if attr := v.ModuleAttribution; attr != nil {
		attr.ModuleCodeLocation.LineStart = span.Start.Line
		attr.ModuleCodeLocation.LineEnd = max(span.End.Line, span.Start.Line)
		attr.ModuleCodeLocation.ColumnStart = span.Start.Column
		attr.ModuleCodeLocation.ColumnEnd = span.End.Column
		narrowCodeLocation(&attr.ModuleCodeLocation, v)
	}
}

func (t *terraformInput) file(path string) *model.FileMetadata {
	if path == "" {
		return nil
	}
	return t.files[fileKey(path)]
}

// keyedFiles is files keyed by fileKey.
func keyedFiles(files map[string]*model.FileMetadata) map[string]*model.FileMetadata {
	out := make(map[string]*model.FileMetadata, len(files))
	for path, f := range files {
		if _, ok := out[fileKey(path)]; !ok {
			out[fileKey(path)] = f
		}
	}
	return out
}

// fileKey is the key of a scanned file path: cleaned, with forward slashes,
// so OS paths and the in-memory filesystem's slash paths match on Windows.
func fileKey(path string) string {
	return filepath.ToSlash(filepath.Clean(path))
}

// callerFile is the root file calling the module instance holding loc, for a
// block in a module directory that was not scanned.
func (t *terraformInput) callerFile(loc *project.Located) *model.FileMetadata {
	if loc.Block == nil || loc.Block.Module == nil || len(loc.Block.Module.Chain) == 0 {
		return nil
	}
	return t.file(absPath(loc.Block.Module.Chain[0].CalledFrom, t.base))
}

func (t *terraformInput) chainBase() string {
	if t.repoPath != "" {
		return t.repoPath
	}
	return t.base
}

// evidence locates the [block id, path] pairs a result cites.
func (t *terraformInput) evidence(raw any) []model.SourceLocation {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	var out []model.SourceLocation
	for _, item := range items {
		pair, ok := item.([]any)
		if !ok || len(pair) != 2 {
			continue
		}
		id, _ := pair[0].(string)
		loc := t.projection.Blocks[id]
		if loc == nil {
			continue
		}
		path, err := resultPath(pair[1])
		if err != nil {
			continue
		}
		rng := loc.Range(path)
		out = append(out, declarationLocation(rng.Filename, rng.Start.Line, rng.End.Line,
			rng.Start.Column, rng.End.Column, t.chainBase()))
	}
	return out
}

// resultPath reads a result path: attribute names and list indexes.
func resultPath(raw any) ([]any, error) {
	if raw == nil {
		return nil, nil
	}
	steps, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("result field %q must be an array, got %T", pathResultField, raw)
	}
	path := make([]any, 0, len(steps))
	for _, s := range steps {
		switch s := s.(type) {
		case string:
			path = append(path, s)
		case json.Number:
			i, err := s.Int64()
			if err != nil || i < 0 {
				return nil, fmt.Errorf("result field %q holds %s, not a list index", pathResultField, s)
			}
			path = append(path, int(i))
		default:
			return nil, fmt.Errorf("result field %q holds a %T, not an attribute name or list index", pathResultField, s)
		}
	}
	return path, nil
}

// resultKey reads the key telling apart several findings on one block.
func resultKey(raw any) (string, error) {
	switch k := raw.(type) {
	case nil:
		return "", nil
	case string:
		return k, nil
	case json.Number:
		return k.String(), nil
	case bool:
		return strconv.FormatBool(k), nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("result field %q: %w", keyResultField, err)
	}
	return string(b), nil
}

// blockResource is the resource type and name a finding on loc reports: the
// type and label, with the count or for_each instance key in Terraform address
// style (e.g. db[0], b["open"]) when the block is expanded.
func blockResource(loc *project.Located) (resourceType, resourceName string) {
	switch loc.Kind {
	case address.KindModule:
		return moduleCallRoot, loc.Block.Name
	case address.KindProvider:
		return loc.Type, loc.Type
	case address.KindVariable, address.KindOutput:
		return loc.Kind, loc.Block.Name
	case tfmodel.KindLocals:
		return loc.Kind, loc.Kind
	}
	name := loc.Block.Name
	if inst := loc.Instance(); inst != nil {
		name += inst.Key
	}
	return loc.Type, name
}

// searchKey names the attribute a finding is on, for output.
func searchKey(addr string, path []any, key string) string {
	var b strings.Builder
	b.WriteString(addr)
	for _, s := range path {
		switch s := s.(type) {
		case string:
			b.WriteString(".")
			b.WriteString(s)
		case int:
			b.WriteString("[" + strconv.Itoa(s) + "]")
		}
	}
	if key != "" {
		b.WriteString("[" + strconv.Quote(key) + "]")
	}
	return b.String()
}

// identityKey is what tells a finding apart from the rule's other findings on
// the same block: its path and key. Empty for the block itself.
func identityKey(path []any, key string) string {
	if len(path) == 0 && key == "" {
		return ""
	}
	steps := make([]string, 0, len(path))
	for _, s := range path {
		switch s := s.(type) {
		case string:
			steps = append(steps, s)
		case int:
			steps = append(steps, strconv.Itoa(s))
		}
	}
	b, _ := json.Marshal([]any{steps, key})
	return string(b)
}

func resourceLocation(r hcl.Range) model.ResourceLocation {
	return model.ResourceLocation{
		Start: model.ResourceLine{Line: r.Start.Line, Col: r.Start.Column},
		End:   model.ResourceLine{Line: r.End.Line, Col: r.End.Column},
	}
}
