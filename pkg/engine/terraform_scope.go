/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
)

// terraformPlatformValue is the platform string Terraform findings carry, as
// the fingerprint compares it (see model.fingerprintInput).
const terraformPlatformValue = "Terraform"

// stampTerraformScopes records each Terraform file's identity context
// (K9CODESEC-7158) before findings are built: where its blocks live (root
// module, module instance), which blocks it declares, and, for a terraform
// plan -json file, the addresses Terraform itself computed. The vulnerability
// builder runs after the documents may have been released, so everything it
// needs from the document is extracted here.
func (c *Inspector) stampTerraformScopes(files model.FileMetadatas) {
	relDir := func(dir string) string {
		return repoRelativeDir(dir, c.repoPath, c.externalPathRoots)
	}
	for _, f := range files {
		if f == nil || isSyntheticTerraformDoc(f) {
			// Synthetic instance documents carry the scope their group built
			// (module address, root, instance keys); never overwrite it.
			continue
		}
		switch f.Kind {
		case model.KindTerraformPlan:
			// A plan file represents exactly one root's evaluation, already
			// performed by Terraform itself, so the plan file's own path is
			// that root. Two plan files in one directory are two roots.
			scope := &model.TerraformScope{RootModule: repoRelativeFile(f.FilePath, c.repoPath)}
			if planAddresses := json.PlanAddresses(f.Document); planAddresses != nil {
				scope.PlanAddresses = planAddresses
			}
			f.TerraformScope = scope
		case model.KindTerraform:
			if isTFVarsFile(f.FilePath) {
				// A vars file assigns variables; its root is itself, and its
				// findings are addressed var.<name>.
				f.TerraformScope = &model.TerraformScope{RootModule: repoRelativeFile(f.FilePath, c.repoPath)}
				continue
			}
			f.TerraformScope = &model.TerraformScope{
				RootModule: relDir(filepath.Dir(absPath(f.FilePath, c.repoPath))),
				Blocks:     documentBlocks(f.Document),
			}
		}
	}
	// Repeated unlabeled blocks (moved, import, removed) are indexed across
	// the whole module directory in deterministic file order: file-local
	// identities would give two files of one module the same address, and two
	// such findings would collapse. The declaration keys rules report stay
	// untouched; the module-wide index lives in a separate map used only to
	// build the address.
	indexUnlabeledBlocksModuleWide(files, relDir)
}

// indexUnlabeledBlocksModuleWide records, per repeated unlabeled block, its
// module-wide index in deterministic order (file path, then file-local
// index), leaving the declaration keys rules report exactly as declared.
func indexUnlabeledBlocksModuleWide(files model.FileMetadatas, relDir func(string) string) {
	type ref struct {
		file *model.FileMetadata
		name string
	}
	unlabeled := map[string]map[string][]ref{}
	for _, f := range files {
		if f == nil || f.TerraformScope == nil || f.TerraformScope.Blocks == nil {
			continue
		}
		dir := relDir(filepath.Dir(absPath(f.FilePath, "")))
		for kind := range repeatedUnlabeledKinds {
			for _, name := range unlabeledNames(f.TerraformScope.Blocks, kind) {
				key := dir + "\x00" + kind
				if unlabeled[key] == nil {
					unlabeled[key] = map[string][]ref{}
				}
				unlabeled[key][kind] = append(unlabeled[key][kind], ref{file: f, name: name})
			}
		}
	}
	for _, byKind := range unlabeled {
		for kind, refs := range byKind {
			// A lone block in the module keeps the bare address it always had;
			// only an actual collision is indexed.
			if len(refs) < 2 {
				continue
			}
			sort.Slice(refs, func(i, j int) bool {
				if refs[i].file.FilePath != refs[j].file.FilePath {
					return refs[i].file.FilePath < refs[j].file.FilePath
				}
				return refs[i].name < refs[j].name
			})
			for i, r := range refs {
				if r.file.TerraformScope.UnlabeledIndex == nil {
					r.file.TerraformScope.UnlabeledIndex = map[model.TerraformBlock]int{}
				}
				b := model.TerraformBlock{Kind: kind, Name: r.name}
				r.file.TerraformScope.UnlabeledIndex[b] = i
			}
		}
	}
}

// repeatedUnlabeledKinds are the unlabeled block types that may repeat in a
// module and are indexed; terraform {} is a single block and keeps its bare
// identity.
var repeatedUnlabeledKinds = map[string]bool{"moved": true, "import": true, "removed": true}

// unlabeledNames returns the recorded names of one unlabeled kind in a block
// set, sorted.
func unlabeledNames(blocks map[model.TerraformBlock]bool, kind string) []string {
	var names []string
	for b := range blocks {
		if b.Kind == kind {
			names = append(names, b.Name)
		}
	}
	sort.Strings(names)
	return names
}

// isTFVarsFile reports whether path is a terraform.tfvars-style variables file.
func isTFVarsFile(p string) bool {
	lower := strings.ToLower(p)
	return strings.HasSuffix(lower, tfpath.ExtTFVars) || strings.HasSuffix(lower, tfpath.ExtTFVarsJSON)
}

// repoRelativeDir returns dir relative to the scanned repository with forward
// slashes. A directory outside the repository (an external or remote module)
// is named relative to the innermost external root containing it, the way
// module attribution names its files, so two different modules never share a
// root name; and it never returns a ../-prefixed path.
func repoRelativeDir(dir, repoPath string, externalRoots map[string]bool) string {
	if repoPath == "" {
		// No repo root in content-push mode: the pushed path's shape is
		// self-locating (see repoRelativeFile).
		return path.Clean(filepath.ToSlash(dir))
	}
	// Both sides are normalized to forward slashes first: on Windows a path
	// rooted without a volume ("/repo") is not filepath.IsAbs, so absPath
	// would join it under the repo root and produce a wrong-but-plausible
	// relative path. With both arguments slashed, filepath.Rel degrades to
	// element-wise string math on every platform, and the result is slashed
	// back (Rel returns platform separators).
	absDir := path.Clean(filepath.ToSlash(absPath(dir, repoPath)))
	root := path.Clean(filepath.ToSlash(repoPath))
	if rel, err := filepath.Rel(root, absDir); err == nil {
		rel = filepath.ToSlash(rel)
		if rel != parentDirectoryPath && !strings.HasPrefix(rel, parentDirectoryPath+"/") {
			return rel
		}
	}
	if base, ok := externalRelativeDir(absDir, externalRoots); ok {
		return base
	}
	return path.Base(absDir)
}

// externalRelativeDir names abs relative to the innermost external root that
// contains it: <root basename>/<rel>. ok is false when no external root does.
// Both arguments are slash-space paths (see repoRelativeDir).
func externalRelativeDir(abs string, externalRoots map[string]bool) (string, bool) {
	best := ""
	for root := range externalRoots {
		cleaned := path.Clean(filepath.ToSlash(root))
		if rel, err := filepath.Rel(cleaned, abs); err != nil {
			continue
		} else {
			rel = filepath.ToSlash(rel)
			if rel == parentDirectoryPath || strings.HasPrefix(rel, parentDirectoryPath+"/") {
				continue
			}
		}
		if best == "" || len(cleaned) > len(best) {
			best = cleaned
		}
	}
	if best == "" {
		return "", false
	}
	rel, err := filepath.Rel(best, abs)
	if err != nil {
		return "", false
	}
	return path.Base(best) + "/" + filepath.ToSlash(rel), true
}

// documentBlocks records every top-level block a parsed Terraform document
// declares, as (kind, type, name) keys a finding's resourceType and
// resourceName are verified against (see resolveTerraformBlock). Names that
// failed to parse (nameless blocks, which parse to lists) are not recorded.
func documentBlocks(doc model.Document) map[model.TerraformBlock]bool {
	if len(doc) == 0 {
		return nil
	}
	blocks := make(map[model.TerraformBlock]bool)
	collectTypedBlocks(doc, blocks)
	collectLabeledBlocks(doc, blocks)
	collectUnlabeledBlocks(doc, blocks)
	collectProviderBlocks(doc, blocks)
	if len(blocks) == 0 {
		return nil
	}
	return blocks
}

// collectTypedBlocks records the resource-shaped sections a document
// declares: <type>.<name> under resource, data and ephemeral. A nameless
// block parses to a list; its type is still declared.
func collectTypedBlocks(doc model.Document, blocks map[model.TerraformBlock]bool) {
	typedBlocks := func(key string, kind string) {
		byType, ok := asStringMap(doc[key])
		if !ok {
			return
		}
		for typ, typeBlocksRaw := range byType {
			if isParserBookkeepingKey(typ) {
				continue
			}
			typeBlocks, ok := asStringMap(typeBlocksRaw)
			if !ok {
				blocks[address.Block{Kind: kind, Type: typ}] = true
				continue
			}
			for name := range typeBlocks {
				if isParserBookkeepingKey(name) {
					continue
				}
				blocks[address.Block{Kind: kind, Type: typ, Name: name}] = true
			}
		}
	}
	typedBlocks("resource", address.KindResource)
	typedBlocks("data", address.KindData)
	typedBlocks("ephemeral", address.KindEphemeral)
}

// collectLabeledBlocks records the label-only sections: one label per block.
// Repeated label-less blocks (locals) parse to a list of per-block maps;
// every declared name across them is indexed.
func collectLabeledBlocks(doc model.Document, blocks map[model.TerraformBlock]bool) {
	labeledBlocks := func(key string, kind string) {
		byName, ok := asStringMap(doc[key])
		if !ok {
			list, isList := doc[key].([]interface{})
			if !isList {
				return
			}
			for _, raw := range list {
				entries, ok := asStringMap(raw)
				if !ok {
					continue
				}
				for name := range entries {
					if isParserBookkeepingKey(name) {
						continue
					}
					blocks[address.Block{Kind: kind, Name: name}] = true
				}
			}
			return
		}
		for name := range byName {
			if isParserBookkeepingKey(name) {
				continue
			}
			blocks[address.Block{Kind: kind, Name: name}] = true
		}
	}
	labeledBlocks("module", address.KindModule)
	labeledBlocks("variable", address.KindVariable)
	labeledBlocks("output", address.KindOutput)
	labeledBlocks("check", address.KindCheck)
	labeledBlocks("locals", address.KindLocal)
}

// collectUnlabeledBlocks records the block types declared without labels
// (terraform, moved, import, removed). A repeated type parses to a list, and
// its blocks are indexed so two moved blocks never share an identity; a lone
// block keeps the bare type as its identity.
func collectUnlabeledBlocks(doc model.Document, blocks map[model.TerraformBlock]bool) {
	for _, key := range [...]string{"terraform", "moved", "import", "removed"} {
		if _, isMap := asStringMap(doc[key]); isMap {
			blocks[address.Block{Kind: key}] = true
			continue
		}
		list, isList := doc[key].([]interface{})
		if !isList {
			continue
		}
		if len(list) == 1 {
			blocks[address.Block{Kind: key}] = true
			continue
		}
		for i := range list {
			blocks[address.Block{Kind: key, Name: strconv.Itoa(i)}] = true
		}
	}
}

// bookkeepingKeys are the parser's own keys in document maps (line markers
// and the like), skipped when indexing declarations. Skipped exactly: a
// block label or name that merely starts with _dd_ is legal Terraform and
// must be indexed.
var bookkeepingKeys = map[string]bool{"_dd_lines": true}

func isParserBookkeepingKey(key string) bool {
	return bookkeepingKeys[key]
}

// collectProviderBlocks records the provider blocks a document declares,
// keyed by type and alias ("" for the default provider). Several provider
// blocks of one type parse to a list.
func collectProviderBlocks(doc model.Document, blocks map[model.TerraformBlock]bool) {
	providers, ok := asStringMap(doc["provider"])
	if !ok {
		return
	}
	for typ, raw := range providers {
		entries, ok := raw.([]interface{})
		if !ok {
			entries = []interface{}{raw}
		}
		for _, entry := range entries {
			attrs, ok := asStringMap(entry)
			if !ok {
				continue
			}
			alias, hasAlias := attrs["alias"].(string)
			if !hasAlias {
				alias = ""
			}
			blocks[address.Block{Kind: address.KindProvider, Type: typ, Name: alias}] = true
		}
	}
}

// resolveTerraformBlock maps a rule's resourceType and resourceName onto the
// Terraform block they name (K9CODESEC-7158). The rules report the block's own
// kind and name: module, variable and output rules report the kind as
// resourceType and the label as resourceName; resource rules report the
// provider type and the block label; data rules may prefix the type with
// "data.". resourceType and resourceName are only ever read as a block's
// identity here — never as a search key, never by position.
//
// ok is false when the pair names no block the file declares: the caller
// counts an identity gap and keeps the legacy fingerprint (a rule reporting an
// attribute value as resourceName, for one).
func resolveTerraformBlock(scope *model.TerraformScope, resourceType, resourceName string) (address.Block, bool) {
	typ, isData := strings.CutPrefix(resourceType, dataTypePrefix)
	if typ == "" {
		return address.Block{}, false
	}
	switch typ {
	case address.KindModule, address.KindVariable, address.KindOutput, address.KindCheck:
		b := address.Block{Kind: typ, Name: resourceName}
		return b, blockDeclared(scope, b)
	case address.KindProvider:
		// A provider rule names the provider, possibly with its alias
		// ("aws.west"). The match is exact: an aliased name never resolves to
		// the default provider, and a bare name never resolves to an alias.
		providerType, alias, hasAlias := strings.Cut(resourceName, ".")
		if !hasAlias {
			providerType, alias = resourceName, ""
		}
		b := address.Block{Kind: address.KindProvider, Type: providerType, Name: alias}
		return b, blockDeclared(scope, b)
	case address.KindLocal, "locals":
		b := address.Block{Kind: address.KindLocal, Name: resourceName}
		return b, blockDeclared(scope, b)
	case address.KindTerraform, "moved", "import", "removed":
		// Repeated blocks are indexed ("moved.0", "moved.1"); a rule naming
		// the index resolves that block, and a bare name resolves the lone
		// one. An empty name against an indexed declaration cannot pick a
		// block and stays a gap.
		if resourceName != "" {
			b := address.Block{Kind: typ, Name: resourceName}
			return b, blockDeclared(scope, b)
		}
		b := address.Block{Kind: typ}
		return b, blockDeclared(scope, b)
	}

	// Ephemeral resources are addressed ephemeral.<type>.<name>; a rule may
	// carry the "ephemeral." prefix on the type.
	if ephemeralType, ok := strings.CutPrefix(typ, "ephemeral."); ok {
		b := address.Block{Kind: address.KindEphemeral, Type: ephemeralType, Name: resourceName}
		return b, blockDeclared(scope, b)
	}

	kind := address.KindResource
	if isData {
		kind = address.KindData
	}
	b := address.Block{Kind: kind, Type: typ, Name: resourceName}
	if blockDeclared(scope, b) {
		return b, true
	}
	// A data rule may name its type without the "data." prefix: when the pair
	// is only declared as a data block, that is the block it names. When both
	// a resource and a data block share type and name, the unprefixed type
	// names the resource. An ephemeral block is tried last, the rarest
	// declaration.
	if !isData {
		for _, fallback := range [...]string{address.KindData, address.KindEphemeral} {
			alt := address.Block{Kind: fallback, Type: typ, Name: resourceName}
			if blockDeclared(scope, alt) {
				return alt, true
			}
		}
	}
	return address.Block{}, false
}

// blockDeclared verifies b against the file's declared blocks. A nil set means
// there is no document to verify against (a .tfvars file), and the pair is
// accepted as named.
func blockDeclared(scope *model.TerraformScope, b address.Block) bool {
	if scope.Blocks == nil {
		return true
	}
	return scope.Blocks[b]
}

// terraformBlockFor resolves the block a finding names in its file, returning
// false for plan files (their lookup is by document key, not block) and when
// the pair names no declared block.
func terraformBlockFor(file *model.FileMetadata, resourceType, resourceName string) (address.Block, bool) {
	if file.Kind == model.KindTerraformPlan {
		return address.Block{}, false
	}
	return resolveTerraformBlock(file.TerraformScope, resourceType, resourceName)
}

// terraformInstanceAddress is the full address of one block instance: the
// file's module instance address, the block's as-written address and, when
// this document represents exactly one count/for_each instance of the block,
// that instance's key. A repeated unlabeled block carries its module-wide
// index in the address — the declaration key rules report stays local.
func terraformInstanceAddress(scope *model.TerraformScope, b address.Block) string {
	if i, ok := scope.UnlabeledIndex[b]; ok {
		b.Name = strconv.Itoa(i)
	}
	return address.Instance(scope.ModuleAddress, b, scope.Instances[b])
}

// terraformIdentityFor resolves the Terraform identity (K9CODESEC-7158) a
// finding on file with this resourceType and resourceName carries: its block
// (or, for a plan, the resource the plan metadata keys by type and document
// key), its full instance address and its root module. ok is false when the
// finding has no Terraform identity context or names no block, leaving it the
// legacy fingerprint.
func terraformIdentityFor(file *model.FileMetadata, resourceType, resourceName string) (model.TerraformIdentity, bool) {
	scope := file.TerraformScope
	if scope == nil {
		return model.TerraformIdentity{}, false
	}
	if file.Kind == model.KindTerraformPlan {
		if scope.PlanAddresses == nil {
			return model.TerraformIdentity{}, false
		}
		// The section is the rule's resourceType as-is: the plan keys planned
		// resources by type and prior-state data sources by "data."+type, and
		// the two namespaces stay separate.
		id, ok := scope.PlanAddresses[[2]string{resourceType, resourceName}]
		if !ok {
			return model.TerraformIdentity{}, false
		}
		return model.TerraformIdentity{RootModule: scope.RootModule, ResourceID: id}, true
	}
	block, ok := resolveTerraformBlock(scope, resourceType, resourceName)
	if !ok {
		return model.TerraformIdentity{}, false
	}
	return model.TerraformIdentity{
		RootModule: scope.RootModule,
		ResourceID: terraformInstanceAddress(scope, block),
	}, true
}

// attachTerraformIdentity sets v's resolved Terraform identity from the file
// it was raised on (K9CODESEC-7158). It returns false — leaving v unchanged,
// so the finding keeps the legacy resource-name fingerprint — when the file
// has no identity context, or resourceType and resourceName name no block it
// declares; the caller counts that as an identity gap.
func attachTerraformIdentity(file *model.FileMetadata, v *model.Vulnerability) bool {
	id, ok := terraformIdentityFor(file, v.ResourceType, v.ResourceName)
	if !ok {
		return false
	}
	v.ResourceID = id.ResourceID
	v.RootModule = id.RootModule
	return true
}

// routedBlockAddress is the address of an external module file's block as it
// is reported through one call: the call's module instance address prefixes
// the block's address, with the module-wide unlabeled index applied — the
// declaration key rules report stays file-local (K9CODESEC-7158).
func routedBlockAddress(scope *model.TerraformScope, b address.Block, moduleAddress string) string {
	if scope != nil {
		if i, ok := scope.UnlabeledIndex[b]; ok {
			b.Name = strconv.Itoa(i)
		}
	}
	return address.Instance(moduleAddress, b, "")
}

// skipBorrowedBlock reports whether the finding's block is borrowed by this
// synthetic document: a sibling copied into an expanded-root layer it does not
// own, so the owning document reports it (see joinPlainRootSiblings). Dropping
// it here keeps each sibling at one finding per rule.
func skipBorrowedBlock(file *model.FileMetadata, resourceType, resourceName string) bool {
	scope := file.TerraformScope
	if scope == nil || len(scope.Borrowed) == 0 || file.Kind == model.KindTerraformPlan {
		return false
	}
	block, ok := resolveTerraformBlock(scope, resourceType, resourceName)
	return ok && scope.Borrowed[block]
}

// isSyntheticTerraformDoc reports whether f stands for a module instance or a
// count/for_each instance rather than the file as written.
func isSyntheticTerraformDoc(f *model.FileMetadata) bool {
	scope := f.TerraformScope
	return scope != nil && (scope.ModuleAddress != "" || len(scope.Instances) > 0)
}
