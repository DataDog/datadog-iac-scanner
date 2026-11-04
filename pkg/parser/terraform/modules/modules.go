package tfmodules

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/hclexpr"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/cespare/xxhash/v2"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

type ParsedModule struct {
	Name          string
	AbsSource     string
	Source        string
	Version       string
	IsLocal       bool
	SourceType    string // local, git, registry, etc.
	RegistryScope string // public, private, or "" (non-registry)
	FileName      string
	DefLine       int
	DefEndLine    int
}

type UnresolvedError struct {
	Reason string
	// NotApplicable marks a resolver declining a source it does not handle, as
	// opposed to a resolver that attempted the source and failed.
	NotApplicable bool
}

func (e *UnresolvedError) Error() string {
	return "module unresolved: " + e.Reason
}

func IsUnresolved(err error) bool {
	var e *UnresolvedError
	return errors.As(err, &e)
}

const (
	stringLocal                 = "local"
	stringUnknown               = "unknown"
	stringPublic                = "public"
	stringRegistry              = "registry"
	stringPrivate               = "private"
	unresolvedPlaceholder       = "__UNRESOLVED__"
	invalidTraversalPlaceholder = "__INVALID_TRAVERSAL__"
)

// contentKey identifies file content by length plus a 64-bit content hash.
type contentKey struct {
	len  int
	hash uint64
}

// fileExtract holds the only facts module resolution needs from a Terraform
// file: the string-valued locals and variable defaults a module argument may
// reference, plus one entry per module block. The parsed AST is dropped as soon
// as these are copied out of it, so a scan never holds a whole repository of
// Terraform ASTs at once.
type fileExtract struct {
	locals  map[string]string
	vars    map[string]string
	modules []moduleBlockExtract
}

// moduleBlockExtract is a module block reduced to what fillModuleAttrs reads.
// source and version stay unevaluated because resolving them needs the locals
// and vars of every file in the directory, which is only known once all of them
// have been extracted. A nil expression means the argument is absent.
type moduleBlockExtract struct {
	name       string
	defLine    int
	defEndLine int
	source     hclsyntax.Expression
	version    hclsyntax.Expression
}

func extractFile(body *hclsyntax.Body) *fileExtract {
	extract := &fileExtract{}
	for _, block := range body.Blocks {
		switch block.Type {
		case "locals":
			for name, attr := range block.Body.Attributes {
				if val, ok := constantString(attr.Expr); ok {
					if extract.locals == nil {
						extract.locals = make(map[string]string)
					}
					extract.locals[name] = val
				}
			}
		case "variable":
			if len(block.Labels) != 1 {
				continue
			}
			defAttr, ok := block.Body.Attributes["default"]
			if !ok {
				continue
			}
			if val, ok := constantString(defAttr.Expr); ok {
				if extract.vars == nil {
					extract.vars = make(map[string]string)
				}
				extract.vars[block.Labels[0]] = val
			}
		case "module":
			if len(block.Labels) == 0 {
				continue
			}
			mod := moduleBlockExtract{
				name:       block.Labels[0],
				defLine:    block.TypeRange.Start.Line,
				defEndLine: block.Range().End.Line,
			}
			if attr, ok := block.Body.Attributes["source"]; ok {
				mod.source = attr.Expr
			}
			if attr, ok := block.Body.Attributes["version"]; ok {
				mod.version = attr.Expr
			}
			extract.modules = append(extract.modules, mod)
		}
	}
	return extract
}

// constantString evaluates expr with no evaluation context, so only literals and
// constant templates resolve; anything referencing a variable is skipped.
func constantString(expr hclsyntax.Expression) (string, bool) {
	val, diags := expr.Value(nil)
	if diags.HasErrors() {
		return "", false
	}
	return ctyutil.ConcreteString(val)
}

// extractForContent returns the extract for content, parsing it only the first
// time a given content hash is seen: repositories commonly hold byte-identical
// .tf files in many directories. Caching the extract instead of the parsed body
// keeps the cache small enough to live for the whole scan.
func extractForContent(cache *sync.Map, content, filePath string) (*fileExtract, hcl.Diagnostics) {
	key := contentKey{len: len(content), hash: xxhash.Sum64String(content)}
	if cached, ok := cache.Load(key); ok {
		return cached.(*fileExtract), nil
	}
	if tfpath.IsJSONConfig(filePath) {
		extract, err := extractJSONFile([]byte(content))
		if err != nil {
			return nil, hcl.Diagnostics{{
				Severity: hcl.DiagError,
				Summary:  err.Error(),
			}}
		}
		cache.Store(key, extract)
		return extract, nil
	}
	hclFile, diags := hclsyntax.ParseConfig([]byte(content), filePath, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, diags
	}
	body, ok := hclFile.Body.(*hclsyntax.Body)
	if !ok {
		return nil, diags
	}
	extract := extractFile(body)
	cache.Store(key, extract)
	return extract, diags
}

// dirFiles holds the Terraform files of one directory, in scan order.
type dirFiles struct {
	dir   string
	files []*model.FileMetadata
}

// groupTerraformFilesByDir groups the .tf files by directory, keeping both the
// directory order and the per-directory file order stable so that duplicate
// module keys always resolve to the same first-wins entry.
func groupTerraformFilesByDir(files model.FileMetadatas) []dirFiles {
	var groups []dirFiles
	indexByDir := make(map[string]int)
	for _, file := range files {
		if file == nil || !tfpath.IsConfig(file.FilePath) {
			continue
		}
		dir := filepath.Dir(file.FilePath)
		i, ok := indexByDir[dir]
		if !ok {
			i = len(groups)
			indexByDir[dir] = i
			groups = append(groups, dirFiles{dir: dir})
		}
		groups[i].files = append(groups[i].files, file)
	}
	return groups
}

// ParseTerraformModules parses HCL content and extracts module source/version.
// numWorkers: 0 means auto-detect (GOMAXPROCS).
func ParseTerraformModules(
	ctx context.Context, fsys vfs.FS, files model.FileMetadatas, numWorkers int,
) (map[string]ParsedModule, error) {
	return parseModulesByDir(ctx, fsys, files, moduleParseOptions{validateLocalSources: true}, numWorkers)
}

type moduleParseOptions struct {
	// allowedFiles, when non-nil, restricts which files contribute module blocks;
	// every file still contributes locals/vars so resolution stays correct.
	allowedFiles map[string]bool
	// validateLocalSources warns about local sources that are not a module
	// directory. Only the pass that sees every scanned file should report them.
	validateLocalSources bool
}

// parseModulesByDir resolves module blocks one directory at a time. Locals and
// vars are scoped per Terraform module root (a directory), so grouping by
// directory both preserves that scoping — the same name may be defined
// differently in two directories — and bounds how much parsed Terraform is live
// at once: the directories in flight rather than the whole repository.
func parseModulesByDir(
	ctx context.Context,
	fsys vfs.FS,
	files model.FileMetadatas,
	opts moduleParseOptions,
	numWorkers int,
) (map[string]ParsedModule, error) {
	if fsys == nil {
		fsys = vfs.DiskFS{}
	}
	groups := groupTerraformFilesByDir(files)
	modules := make(map[string]ParsedModule)
	if len(groups) == 0 {
		return modules, nil
	}

	extracts := &sync.Map{}
	var mu sync.Mutex

	// HCL parsing is CPU-bound, so the pool draws from the shared CPU budget.
	// Individual HCL parse errors are logged and skipped (not fatal); ForEach
	// only returns an error on context cancellation, which the caller surfaces.
	err := utils.ForEach(ctx, groups, utils.PoolOptions{Workers: numWorkers, CPUBound: true},
		func(ctx context.Context, group dirFiles, _ int) error {
			found, err := parseDirModules(ctx, fsys, extracts, group, opts)
			if err != nil {
				return err
			}
			if len(found) == 0 {
				return nil
			}
			// Keys embed the defining file path, so no two directories can produce
			// the same key and this merge stays order-independent.
			mu.Lock()
			defer mu.Unlock()
			for key := range found {
				if _, exists := modules[key]; !exists {
					modules[key] = found[key]
				}
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return modules, nil
}

// parseDirModules extracts and resolves the module blocks of a single directory.
func parseDirModules(
	ctx context.Context,
	fsys vfs.FS,
	extracts *sync.Map,
	group dirFiles,
	opts moduleParseOptions,
) (map[string]ParsedModule, error) {
	contextLogger := logger.FromContext(ctx)
	files, _ := tfpath.Partition(group.files, func(f *model.FileMetadata) string { return f.FilePath })
	files = tfpath.OrderOverrideLast(files, func(f *model.FileMetadata) string { return f.FilePath })
	fileExtracts := make([]*fileExtract, len(files))
	localsMap := make(map[string]string)
	varsMap := make(map[string]string)

	for i, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		content := getFileContent(file)
		if placeholderCandidate([]byte(content)) {
			resolved, err := ResolveConfigContent(ctx, fsys, file.FilePath, "", []byte(content))
			if err != nil {
				continue
			}
			content = string(resolved)
		}
		extract, diags := extractForContent(extracts, content, file.FilePath)
		if diags.HasErrors() {
			contextLogger.Warn().Msgf("Skipping file %s due to parse errors: %s", file.FilePath, diags.Error())
			continue
		}
		if extract == nil {
			contextLogger.Error().Msgf("Unexpected body type in %s", file.FilePath)
			continue
		}
		fileExtracts[i] = extract
		maps.Copy(localsMap, extract.locals)
		maps.Copy(varsMap, extract.vars)
	}

	var contributing []dirModuleFile
	for i, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		extract := fileExtracts[i]
		if extract == nil || len(extract.modules) == 0 {
			continue
		}
		if opts.allowedFiles != nil && !opts.allowedFiles[file.FilePath] {
			continue
		}
		contributing = append(contributing, dirModuleFile{path: file.FilePath, blocks: extract.modules})
	}

	modules := make(map[string]ParsedModule)
	for _, file := range mergeOverrideModuleBlocks(contributing) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolveModuleBlocks(
			ctx, fsys, group.dir, file.path, file.blocks, localsMap, varsMap, opts.validateLocalSources, modules,
		)
	}
	return modules, nil
}

// dirModuleFile is one configuration file's module blocks, in file order.
type dirModuleFile struct {
	path   string
	blocks []moduleBlockExtract
}

type moduleBlockSlot struct {
	file  int
	block int
}

// mergeOverrideModuleBlocks applies override files to same-named module blocks.
// A set source or version replaces the base value. The base file and line range
// stay the declaration. A name that does not exist yet is a new module block.
func mergeOverrideModuleBlocks(files []dirModuleFile) []dirModuleFile {
	merged := make([]dirModuleFile, 0, len(files))
	var overrides []dirModuleFile
	for _, file := range files {
		copied := dirModuleFile{
			path:   file.path,
			blocks: append([]moduleBlockExtract(nil), file.blocks...),
		}
		if tfpath.IsOverrideFile(file.path) {
			overrides = append(overrides, copied)
			continue
		}
		merged = append(merged, copied)
	}
	slots := make(map[string][]moduleBlockSlot)
	for fi := range merged {
		for bi := range merged[fi].blocks {
			name := merged[fi].blocks[bi].name
			slots[name] = append(slots[name], moduleBlockSlot{file: fi, block: bi})
		}
	}
	for _, override := range overrides {
		introducedAt := len(merged)
		var introduced []moduleBlockExtract
		for _, block := range override.blocks {
			targets := slots[block.name]
			if len(targets) == 0 {
				introduced = append(introduced, block)
				slots[block.name] = []moduleBlockSlot{{file: introducedAt, block: len(introduced) - 1}}
				continue
			}
			for _, target := range targets {
				if target.file == introducedAt {
					mergeModuleOverride(&introduced[target.block], block)
					continue
				}
				mergeModuleOverride(&merged[target.file].blocks[target.block], block)
			}
		}
		if len(introduced) > 0 {
			merged = append(merged, dirModuleFile{path: override.path, blocks: introduced})
		}
	}
	return merged
}

func mergeModuleOverride(base *moduleBlockExtract, override moduleBlockExtract) {
	if override.source != nil {
		base.source = override.source
	}
	if override.version != nil {
		base.version = override.version
	}
}

// resolveModuleBlocks turns a file's extracted module blocks into ParsedModules,
// resolving relative sources against baseDir (the directory holding filePath).
func resolveModuleBlocks(
	ctx context.Context,
	fsys vfs.FS,
	baseDir, filePath string,
	blocks []moduleBlockExtract,
	localsMap, varsMap map[string]string,
	validateLocal bool,
	modules map[string]ParsedModule,
) {
	for i := range blocks {
		mod := ParsedModule{
			Name:       blocks[i].name,
			FileName:   filePath,
			DefLine:    blocks[i].defLine,
			DefEndLine: blocks[i].defEndLine,
		}
		fillModuleAttrs(ctx, fsys, &mod, &blocks[i], baseDir, localsMap, varsMap, validateLocal)
		key := moduleIdentityKey(&mod)
		if _, exists := modules[key]; !exists {
			modules[key] = mod
		}
	}
}

func fillModuleAttrs(
	ctx context.Context,
	fsys vfs.FS,
	mod *ParsedModule,
	block *moduleBlockExtract,
	baseDir string,
	localsMap, varsMap map[string]string,
	validateLocal bool,
) {
	log := logger.FromContext(ctx)
	if block.version != nil {
		mod.Version = resolveExpr(block.version, localsMap, varsMap)
	}
	if block.source == nil {
		return
	}
	resolved := resolveExpr(block.source, localsMap, varsMap)
	mod.Source = resolved
	mod.SourceType, mod.RegistryScope = DetectModuleSourceType(resolved)
	// Strip go-getter prefixes once (mirroring tfeval) so compound sources like
	// "git::file://./x" are classified and resolved as the local path they
	// denote, per ResolveLocalModuleDir's contract of a prefix-free source.
	sourcePath := StripGetterPrefix(resolved)
	mod.IsLocal = LooksLikeLocalModuleSource(sourcePath)
	if !mod.IsLocal {
		return
	}
	absPath, err := resolveLocalModuleDir(ctx, fsys, baseDir, sourcePath)
	if err != nil {
		return
	}
	mod.AbsSource, err = fsys.Abs(absPath)
	if err != nil {
		log.Warn().Msgf("Could not compute absolute path name for %v: %v", absPath, err)
		mod.AbsSource = filepath.Clean(absPath)
	}
	if !validateLocal {
		return
	}
	if err = validateModuleSource(fsys, mod.AbsSource); err != nil {
		event := log.Warn()
		if utils.IsTestFixturePath(baseDir) {
			event = log.Debug()
		}
		event.Msgf("Invalid local module source %q: %v", mod.Source, err)
	}
}

func moduleIdentityKey(mod *ParsedModule) string {
	return mod.Source + "\x00" + mod.Version + "\x00" + mod.Name + "\x00" + mod.FileName
}

func validateModuleSource(fsys vfs.FS, absPath string) error {
	entries, err := fsys.ReadDir(absPath)
	if err != nil {
		return fmt.Errorf("module source path %q is not accessible: %w", absPath, err)
	}

	valid := false
	for _, entry := range entries {
		if !entry.IsDir() && tfpath.IsConfig(entry.Name()) {
			valid = true
			break
		}
	}

	if !valid {
		return fmt.Errorf("module at %s does not contain any Terraform or OpenTofu configuration files", absPath)
	}
	return nil
}

func getFileContent(file *model.FileMetadata) string {
	// Avoid allocating a full copy when there are no carriage returns to strip
	// (the common case on Linux/CI); ReplaceAll always allocates otherwise.
	if strings.IndexByte(file.OriginalData, '\r') < 0 {
		return file.OriginalData
	}
	return strings.ReplaceAll(file.OriginalData, "\r", "")
}

// resolveExpr evaluates HCL expressions using known locals and vars
func resolveExpr(expr hclsyntax.Expression, locals, vars map[string]string) string {
	s, _ := hclexpr.Dispatch(expr, &resolveExprVisitor{locals: locals, vars: vars})
	return s
}

// resolveExprVisitor implements hclexpr.Visitor[string] for resolveExpr.
type resolveExprVisitor struct {
	locals, vars map[string]string
}

func (v *resolveExprVisitor) VisitLiteralValue(e *hclsyntax.LiteralValueExpr) (string, error) {
	return resolveLiteralValueExpr(e), nil
}
func (v *resolveExprVisitor) VisitTemplateExpr(e *hclsyntax.TemplateExpr) (string, error) {
	return resolveTemplateExpr(e, v.locals, v.vars), nil
}
func (v *resolveExprVisitor) VisitScopeTraversal(e *hclsyntax.ScopeTraversalExpr) (string, error) {
	return resolveScopeTraversal(e, v.locals, v.vars), nil
}
func (v *resolveExprVisitor) VisitIndexExpr(e *hclsyntax.IndexExpr) (string, error) {
	collStr := resolveExpr(e.Collection, v.locals, v.vars)
	keyStr := resolveExpr(e.Key, v.locals, v.vars)
	return collStr + "[" + keyStr + "]", nil
}
func (v *resolveExprVisitor) VisitRelativeTraversal(e *hclsyntax.RelativeTraversalExpr) (string, error) {
	return resolveRelativeTraversalExpr(e, v.locals, v.vars), nil
}
func (v *resolveExprVisitor) VisitFunctionCall(e *hclsyntax.FunctionCallExpr) (string, error) {
	return resolveFunctionCall(e, v.locals, v.vars), nil
}
func (v *resolveExprVisitor) VisitConditional(e *hclsyntax.ConditionalExpr) (string, error) {
	condStr := resolveExpr(e.Condition, v.locals, v.vars)
	trueStr := resolveExpr(e.TrueResult, v.locals, v.vars)
	falseStr := resolveExpr(e.FalseResult, v.locals, v.vars)
	return condStr + " ? " + trueStr + " : " + falseStr, nil
}
func (v *resolveExprVisitor) VisitTupleCons(e *hclsyntax.TupleConsExpr) (string, error) {
	parts := make([]string, 0, len(e.Exprs))
	for _, ex := range e.Exprs {
		parts = append(parts, resolveExpr(ex, v.locals, v.vars))
	}
	return "[" + strings.Join(parts, ", ") + "]", nil
}
func (v *resolveExprVisitor) VisitObjectCons(e *hclsyntax.ObjectConsExpr) (string, error) {
	parts := make([]string, 0, len(e.Items))
	for _, item := range e.Items {
		keyStr := resolveExpr(item.KeyExpr, v.locals, v.vars)
		valStr := resolveExpr(item.ValueExpr, v.locals, v.vars)
		parts = append(parts, keyStr+": "+valStr)
	}
	return "{" + strings.Join(parts, ", ") + "}", nil
}
func (v *resolveExprVisitor) VisitTemplateJoin(e *hclsyntax.TemplateJoinExpr) (string, error) {
	return resolveExprDefault(e), nil
}
func (v *resolveExprVisitor) VisitBinaryOp(e *hclsyntax.BinaryOpExpr) (string, error) {
	lhs := resolveExpr(e.LHS, v.locals, v.vars)
	rhs := resolveExpr(e.RHS, v.locals, v.vars)
	return lhs + " " + hclexpr.BinaryOpSymbol(e.Op) + " " + rhs, nil
}
func (v *resolveExprVisitor) VisitUnaryOp(e *hclsyntax.UnaryOpExpr) (string, error) {
	valStr := resolveExpr(e.Val, v.locals, v.vars)
	return hclexpr.UnaryOpSymbol(e.Op) + valStr, nil
}
func (v *resolveExprVisitor) VisitForExpr(e *hclsyntax.ForExpr) (string, error) {
	return resolveExprDefault(e), nil
}
func (v *resolveExprVisitor) VisitSplatExpr(e *hclsyntax.SplatExpr) (string, error) {
	sourceStr := resolveExpr(e.Source, v.locals, v.vars)
	if strings.HasPrefix(sourceStr, "__") {
		return unresolvedPlaceholder, nil
	}
	base := sourceStr + "[*]"
	if e.Each != nil && e.Each != e.Source {
		eachStr := resolveExpr(e.Each, v.locals, v.vars)
		if strings.HasPrefix(eachStr, "__") {
			return unresolvedPlaceholder, nil
		}
		if eachStr == base || strings.HasPrefix(eachStr, base) {
			return eachStr, nil
		}
	}
	return base, nil
}
func (v *resolveExprVisitor) VisitAnonSymbol(_ *hclsyntax.AnonSymbolExpr) (string, error) {
	return unresolvedPlaceholder, nil
}
func (v *resolveExprVisitor) VisitExprSyntaxError(_ *hclsyntax.ExprSyntaxError) (string, error) {
	return unresolvedPlaceholder, nil
}
func (v *resolveExprVisitor) VisitDefault(e hclsyntax.Expression) (string, error) {
	return resolveExprDefault(e), nil
}

func resolveLiteralValueExpr(e *hclsyntax.LiteralValueExpr) string {
	if s, ok := ctyutil.ConcreteString(e.Val); ok {
		return s
	}
	return "__NON_STRING_LITERAL__"
}

func resolveTemplateExpr(e *hclsyntax.TemplateExpr, locals, vars map[string]string) string {
	var result strings.Builder
	for _, part := range e.Parts {
		result.WriteString(resolveExpr(part, locals, vars))
	}
	return result.String()
}

func resolveRelativeTraversalExpr(e *hclsyntax.RelativeTraversalExpr, locals, vars map[string]string) string {
	sourceStr := resolveExpr(e.Source, locals, vars)
	if strings.HasPrefix(sourceStr, "__") {
		return unresolvedPlaceholder
	}
	for _, step := range e.Traversal {
		switch s := step.(type) {
		case hcl.TraverseAttr:
			sourceStr += "." + s.Name
		case hcl.TraverseIndex:
			formatted, ok := ctyutil.FormatIndexKey(s.Key)
			if !ok {
				return unresolvedPlaceholder
			}
			sourceStr += formatted
		}
	}
	return sourceStr
}

func resolveExprDefault(expr hclsyntax.Expression) string {
	val, diag := expr.Value(nil)
	if !diag.HasErrors() {
		if s, ok := ctyutil.ConcreteString(val); ok {
			return s
		}
	}
	return unresolvedPlaceholder
}

func resolveScopeTraversal(expr *hclsyntax.ScopeTraversalExpr, locals, vars map[string]string) string {
	traversal := expr.Traversal
	if len(traversal) == 0 {
		return invalidTraversalPlaceholder
	}
	if len(traversal) == 1 {
		if root, ok := traversal[0].(hcl.TraverseRoot); ok {
			return root.Name
		}
		return invalidTraversalPlaceholder
	}

	root := traversal[0].(hcl.TraverseRoot).Name

	switch root {
	case stringLocal:
		if attr, ok := traversal[1].(hcl.TraverseAttr); ok {
			if val, ok := locals[attr.Name]; ok {
				return val
			}
		}
	case "var":
		if attr, ok := traversal[1].(hcl.TraverseAttr); ok {
			if val, ok := vars[attr.Name]; ok {
				return val
			}
		}
	case "data":
		// Convert traversal to something like: data_ref:aws_s3_bucket.logs.bucket_domain_name
		parts := []string{}
		for _, step := range traversal[1:] {
			switch s := step.(type) {
			case hcl.TraverseAttr:
				parts = append(parts, s.Name)
			default:
				parts = append(parts, "__UNKNOWN__")
			}
		}
		return "data_ref:" + strings.Join(parts, ".")
	}

	return "__UNKNOWN_REF__"
}

func resolveFunctionCall(expr *hclsyntax.FunctionCallExpr, locals, vars map[string]string) string {
	switch expr.Name {
	case "format":
		if len(expr.Args) < 1 {
			return "__INVALID_FORMAT__"
		}
		formatStr := resolveExpr(expr.Args[0], locals, vars)
		args := make([]interface{}, 0, len(expr.Args)-1)
		for _, arg := range expr.Args[1:] {
			args = append(args, resolveExpr(arg, locals, vars))
		}
		return fmt.Sprintf(formatStr, args...)

	case "join":
		if len(expr.Args) != 2 {
			return "__INVALID_JOIN__"
		}
		sep := resolveExpr(expr.Args[0], locals, vars)
		listExpr, ok := expr.Args[1].(*hclsyntax.TupleConsExpr)
		if !ok {
			return "__INVALID_JOIN_LIST__"
		}
		items := []string{}
		for _, item := range listExpr.Exprs {
			items = append(items, resolveExpr(item, locals, vars))
		}
		return strings.Join(items, sep)

	default:
		return fmt.Sprintf("__UNSUPPORTED_FUNC_%s__", expr.Name)
	}
}

// LooksLikeLocalModuleSource uses heuristics to determine if the resolved source string is likely local
func LooksLikeLocalModuleSource(source string) bool {
	source = strings.TrimSpace(source)
	if strings.HasPrefix(source, "file://") {
		return true
	}
	source = StripGetterPrefix(source)
	if source == "" {
		return false
	}

	// Absolute file path
	if filepath.IsAbs(source) {
		return true
	}

	// Starts with a '.' or '..' path component
	slashed := filepath.ToSlash(source)
	return strings.HasPrefix(slashed, "./") ||
		strings.HasPrefix(slashed, "../")
}

func DetectModuleSourceType(source string) (sourceType, registryScope string) {
	source = strings.TrimSpace(source)
	if source == "" {
		return stringUnknown, ""
	}
	if strings.HasPrefix(source, "data_ref:") {
		return "data_ref", ""
	}
	if strings.HasPrefix(source, "git::") {
		return "git", ""
	}
	if LooksLikeLocalModuleSource(source) {
		return stringLocal, ""
	}
	if addr, err := ParseRegistryModuleSource(source); err == nil {
		if addr.Public() {
			return stringRegistry, stringPublic
		}
		return stringRegistry, stringPrivate
	}
	return stringUnknown, ""
}

// ParseTerraformModulesFromFiles is a variant of ParseTerraformModules that accepts an
// optional allowedFiles set to restrict which files contribute module blocks (all files
// still contribute locals/vars for correct resolution). fsys is used for local-source
// path validation; a nil fsys falls back to vfs.DiskFS{}.
func ParseTerraformModulesFromFiles(
	ctx context.Context, fsys vfs.FS, files model.FileMetadatas, allowedFiles map[string]bool,
) (map[string]ParsedModule, error) {
	return parseModulesByDir(ctx, fsys, files, moduleParseOptions{allowedFiles: allowedFiles}, 0)
}

// LoadTFFilesFromDir returns FileMetadata for top-level Terraform/OpenTofu
// configuration files (.tf, .tofu, .tf.json, .tofu.json) in dir (no recursion —
// a Terraform module is a single directory). When packageRoot is non-empty,
// symlinked config files are included only when their targets stay within the
// package root.
func LoadTFFilesFromDir(ctx context.Context, dir, packageRoot string) (model.FileMetadatas, error) {
	return LoadTFFilesFromDirWithLimit(ctx, dir, packageRoot, 0)
}

// DefaultMaxConfigFileBytes is the largest Terraform configuration file the
// scan parses with its default --max-file-size of 5 MB (see MaxConfigFileBytesForScan).
const DefaultMaxConfigFileBytes int64 = 5 * bytesPerMB

const bytesPerMB = 1 << 20

// MaxConfigFileBytesForScan returns the largest configuration file a scan run
// with --max-file-size maxFileSizeMB parses, or -1 when a negative value
// disables that limit.
func MaxConfigFileBytesForScan(maxFileSizeMB int) int64 {
	if maxFileSizeMB < 0 {
		return -1
	}
	// Zero parses empty files only; the smallest positive cap keeps it a cap.
	return max(int64(maxFileSizeMB)*bytesPerMB, 1)
}

// LoadTFFilesFromDirWithLimit is LoadTFFilesFromDir skipping configuration
// files larger than a positive maxBytes: the scan would not parse them, so
// module calls they declare could never be evaluated.
func LoadTFFilesFromDirWithLimit(
	ctx context.Context, dir, packageRoot string, maxBytes int64,
) (model.FileMetadatas, error) {
	ctx = WithMaxConfigFileBytes(ctx, maxBytes)
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving module dir %q: %w", dir, err)
	}
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return nil, fmt.Errorf("reading module dir %q: %w", absDir, err)
	}
	var files model.FileMetadatas
	for _, entry := range ConfigEntries(entries, tfpath.IsConfig) {
		path, ok := ConfinedFilePath(ctx, entry, absDir, packageRoot)
		if !ok {
			continue
		}
		if ConfigFileTooLarge(path, maxBytes) {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Debug().Msgf("Skipping module calls in %q: larger than %d bytes", path, maxBytes)
			continue
		}
		data, readErr := ReadConfigFile(ctx, vfs.DiskFS{}, path, packageRoot)
		if readErr != nil {
			if errors.Is(readErr, ErrSkippedLinkPlaceholder) {
				continue
			}
			return nil, fmt.Errorf("reading %q: %w", path, readErr)
		}
		files = append(files, &model.FileMetadata{
			FilePath:     filepath.Clean(path),
			OriginalData: string(data),
		})
	}
	return files, nil
}

type maxConfigFileBytesKey struct{}

// WithMaxConfigFileBytes scopes the configuration file cap of
// LoadTFFilesFromDirWithLimit to ctx, for readers deep in module resolution.
func WithMaxConfigFileBytes(ctx context.Context, maxBytes int64) context.Context {
	return context.WithValue(ctx, maxConfigFileBytesKey{}, maxBytes)
}

// MaxConfigFileBytesFromContext returns the cap scoped by WithMaxConfigFileBytes,
// or zero, which reads every file, when there is none.
func MaxConfigFileBytesFromContext(ctx context.Context) int64 {
	maxBytes, _ := ctx.Value(maxConfigFileBytesKey{}).(int64)
	return maxBytes
}

// ConfigFileTooLarge reports whether the file at path exceeds a positive maxBytes.
func ConfigFileTooLarge(path string, maxBytes int64) bool {
	if maxBytes <= 0 {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Size() > maxBytes
}
