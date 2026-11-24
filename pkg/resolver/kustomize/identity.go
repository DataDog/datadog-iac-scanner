package kustomize

import (
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"sigs.k8s.io/kustomize/api/resource"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/resid"
	kyamlutils "sigs.k8s.io/kustomize/kyaml/utils"
	"sigs.k8s.io/yaml"
)

const (
	jsonPatchCopy = "copy"
	jsonPatchMove = "move"
)

// Identity is computed after source attribution is finalized. Ordinary objects
// use their rendered group/kind, namespace and name, independent of where they
// were written. Generated names lose only a proven content-hash suffix.
//
// Replacements may copy generated data into identity fields. Only the fields
// and kinds they may write use source values plus structural affixes. Ambiguous
// objects get an explicit source fallback; its render ordinal preserves every
// object, but is not a promise of stability across reordering.
func (r *Renderer) assignResourceIDs(res *Result, resources []*resource.Resource, g *loadGraph, expired func() bool) error {
	edits := r.identityEdits(res.Reads)
	counts := make(map[string]int, len(resources))
	fieldsByType := make(map[resid.Gvk]identityFields)
	for i, rs := range resources {
		if expired() {
			return &RenderError{Reason: ReasonTimeout}
		}
		gvk := rs.GetGvk()
		fields, ok := fieldsByType[gvk]
		if !ok {
			fields = edits.fields(gvk)
			fieldsByType[gvk] = fields
		}
		d := &res.Documents[i]
		d.Kustomize.ResourceID = r.resourceID(d, rs, g, fields, i)
		counts[d.Kustomize.ResourceID]++
	}
	// Distinct rendered objects must survive even if their safe logical names
	// coincide. Recheck after attribution rejection, not before it.
	for i := range res.Documents {
		if expired() {
			return &RenderError{Reason: ReasonTimeout}
		}
		d := &res.Documents[i]
		if counts[d.Kustomize.ResourceID] > 1 {
			d.Kustomize.ResourceID = sourceResourceID(res.Root, d.FileName, -1, i)
		}
	}
	return nil
}

type identityFields uint8

const (
	identityName identityFields = 1 << iota
	identityNamespace
	identityType
	identityAll = identityName | identityNamespace | identityType
)

type identityEdit struct {
	selector *types.SelectorRegex
	fields   identityFields
}

type identityEdits []identityEdit

func (edits identityEdits) fields(gvk resid.Gvk) identityFields {
	var fields identityFields
	for _, edit := range edits {
		if edit.selector == nil || edit.selector.MatchGvk(gvk) {
			fields |= edit.fields
		}
	}
	return fields
}

func (r *Renderer) identityEdits(reads []string) identityEdits {
	var edits identityEdits
	for _, path := range reads {
		k, ok := r.Kustomization(path)
		if !ok {
			continue
		}
		// Custom field specs and legacy vars can write arbitrary identity fields.
		if len(k.Configurations) > 0 || len(k.Vars) > 0 { //nolint:staticcheck // supported legacy vars
			return identityEdits{{fields: identityAll}}
		}
		for _, patch := range slices.Concat(k.Patches, k.PatchesJson6902) { //nolint:staticcheck // supported legacy patches
			edits = append(edits, r.patchIdentityEdits(path, patch)...)
		}
		for _, entry := range k.Replacements {
			replacements := []types.Replacement{entry.Replacement}
			if entry.Path != "" {
				content, ok := r.Source(r.canonical(filepath.Join(filepath.Dir(path), entry.Path)))
				if !ok {
					return identityEdits{{fields: identityAll}}
				}
				if err := yaml.Unmarshal(content, &replacements); err != nil {
					var single types.Replacement
					if err := yaml.Unmarshal(content, &single); err != nil {
						return identityEdits{{fields: identityAll}}
					}
					replacements = []types.Replacement{single}
				}
			}
			for _, replacement := range replacements {
				for _, target := range replacement.Targets {
					fields := replacementIdentityFields(target.FieldPaths)
					if fields == 0 {
						continue
					}
					edits = append(edits, newIdentityEdit(target.Select, fields))
				}
			}
		}
	}
	return edits
}

func replacementIdentityFields(paths []string) identityFields {
	if len(paths) == 0 {
		return identityName
	} // Kustomize's default target.
	var fields identityFields
	for _, path := range paths {
		parts := kyamlutils.SmarterPathSplitter(strings.TrimLeft(path, "."), ".")
		if len(parts) == 0 {
			continue
		}
		switch parts[0] {
		case "*", "kind", "apiVersion":
			fields |= identityAll
		case "metadata":
			if len(parts) == 1 || parts[1] == "*" {
				fields |= identityName | identityNamespace
			} else if parts[1] == "name" {
				fields |= identityName
			} else if parts[1] == "namespace" {
				fields |= identityNamespace
			}
		}
	}
	return fields
}

func (r *Renderer) resourceID(d *model.ResolvedHelm, rs *resource.Resource, g *loadGraph, fields identityFields, ordinal int) string {
	fallback := func() string {
		return sourceResourceID(d.Kustomize.RenderRoot, d.FileName, d.SourceDocumentIndex, ordinal)
	}
	if fields&identityType != 0 {
		return fallback()
	}
	name, namespace := rs.GetName(), rs.GetNamespace()
	if d.Kustomize.Generator != nil {
		var ok bool
		name, ok = r.generatorIdentityName(d, g)
		if !ok {
			return fallback()
		}
	}
	if fields != 0 {
		written, ok := r.writtenIdentity(d, g)
		if !ok {
			return fallback()
		}
		if fields&identityName != 0 {
			name = written.name
		}
		if fields&identityNamespace != 0 {
			namespace = written.namespace
		}
	}
	if name == "" {
		return fallback()
	}
	return url.PathEscape(rs.GetGvk().Group) + "/" + url.PathEscape(rs.GetKind()) + "|" +
		url.PathEscape(namespace) + "|" + url.PathEscape(name)
}

// writtenIdentity recovers a single source object without consulting the
// rendered name (a replacement could have copied a sibling's name into it).
func (r *Renderer) writtenIdentity(d *model.ResolvedHelm, g *loadGraph) (sourceDoc, bool) {
	if d.Kustomize.Generator != nil || d.Kustomize.Kind == namespaceKind {
		return sourceDoc{}, false
	}
	var found sourceDoc
	count := 0
	for _, candidate := range r.sourceDocuments(d.FileName) {
		if candidate.kind == d.Kustomize.Kind {
			found = candidate
			count++
		}
	}
	chain := g.chains[d.FileName]
	prefix, suffix, ok := r.affixes(chain, renameAffix, g.count(d.FileName))
	if !ok || count != 1 || found.name == "" {
		return sourceDoc{}, false
	}
	if !affixSkipped[found.kind] {
		found.name = prefix + found.name + suffix
	}
	for _, path := range chain {
		if k, ok := r.Kustomization(path); ok && k.Namespace != "" {
			found.namespace = k.Namespace
			break // outermost namespace is applied last
		}
	}
	return found, true
}

// hashSuffix is the content hash Kustomize appends to generated objects.
var hashSuffix = regexp.MustCompile(`-[2456789bcdfghkmt]{10}$`)

func (r *Renderer) generatorIdentityName(d *model.ResolvedHelm, g *loadGraph) (string, bool) {
	k, ok := r.Kustomization(d.FileName)
	if !ok {
		return "", false
	}
	args := generatorArgs(k, d.Kustomize.Generator.Kind)
	if !r.generatorSettingsKnown(g.chains[d.FileName], d.Kustomize.Generator.Kind) {
		return "", false
	}
	prefix, suffix, affixed := r.affixes(g.chains[d.FileName], renameAffix, g.count(d.FileName))
	hashOn, hashOff := false, false
	matched := ""
	for i := range args {
		off := generatorHashDisabled(k, &args[i])
		hashOn, hashOff = hashOn || !off, hashOff || off
		if affixed && generatedAs(d.Kustomize.RenderedName, prefix+args[i].Name+suffix, off) {
			if off {
				return prefix + args[i].Name + suffix, true
			}
			matched = prefix + args[i].Name + suffix
		}
	}
	if matched != "" {
		return matched, true
	}
	// Even failed source attribution cannot make two default generators collapse.
	// Uniform hash settings prove whether the final suffix is a content hash.
	if hashOn && !hashOff {
		return hashSuffix.ReplaceAllString(d.Kustomize.RenderedName, ""), true
	}
	if hashOff && !hashOn {
		return d.Kustomize.RenderedName, true
	}
	return "", false
}

func sourceResourceID(root, file string, document, ordinal int) string {
	rel, err := filepath.Rel(root, file)
	if err != nil {
		rel = filepath.Base(file)
	}
	index := strconv.Itoa(document)
	if document < 0 {
		index = "~" + strconv.Itoa(ordinal)
	}
	return "source:" + url.PathEscape(filepath.ToSlash(rel)) + "#" + index
}

func generatorHashDisabled(k *types.Kustomization, arg *types.GeneratorArgs) bool {
	return k.GeneratorOptions != nil && k.GeneratorOptions.DisableNameSuffixHash ||
		arg.Options != nil && arg.Options.DisableNameSuffixHash
}

// Select by type only: names, namespaces and labels may themselves have changed
// since the replacement ran. Overestimating affected objects is safe.
func newIdentityEdit(selector *types.Selector, fields identityFields) identityEdit {
	edit := identityEdit{fields: fields}
	if selector != nil && fields&identityType == 0 {
		edit.selector, _ = types.NewSelectorRegex(selector)
	}
	return edit
}

// JSON patches can copy generator data into metadata just like replacements.
// Static patch values already come from source and need no identity redaction.
func (r *Renderer) patchIdentityEdits(kust string, patch types.Patch) identityEdits {
	content := []byte(patch.Patch)
	if patch.Path != "" {
		var ok bool
		content, ok = r.Source(r.canonical(filepath.Join(filepath.Dir(kust), patch.Path)))
		if !ok {
			return identityEdits{{fields: identityAll}}
		}
	}
	var ops []struct {
		Op   string
		Path string
	}
	if err := yaml.Unmarshal(content, &ops); err != nil {
		return nil
	} // strategic merge
	var edits identityEdits
	for _, op := range ops {
		if op.Op != jsonPatchCopy && op.Op != jsonPatchMove {
			continue
		}
		fields := identityAll
		if op.Path != "" && op.Path != "/" {
			fields = replacementIdentityFields([]string{strings.ReplaceAll(strings.TrimPrefix(op.Path, "/"), "/", ".")})
		}
		if fields != 0 {
			edits = append(edits, newIdentityEdit(patch.Target, fields))
		}
	}
	return edits
}

// Merge/replace generators can inherit hash settings from another level.
// Use a source fallback when those settings cannot be proved from the origin.
func (r *Renderer) generatorSettingsKnown(chain []string, kind string) bool {
	for _, path := range chain {
		if k, ok := r.Kustomization(path); ok {
			args := generatorArgs(k, kind)
			for i := range args {
				if args[i].Behavior != "" && args[i].Behavior != generatorCreate {
					return false
				}
			}
		}
	}
	return true
}
