package tfmodules

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/hclexpr"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/cespare/xxhash/v2"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/sync/singleflight"
)

type ParsedModule struct {
	Name           string
	AbsSource      string
	Source         string
	Version        string
	IsLocal        bool
	SourceType     string // local, git, registry, etc.
	RegistryScope  string // public, private, or "" (non-registry)
	AttributesData map[string]ModuleAttributesInfo
	FileName       string
	DefLine        int
}

type UnresolvedError struct {
	Reason string
}

func (e *UnresolvedError) Error() string {
	return "module unresolved: " + e.Reason
}

func IsUnresolved(err error) bool {
	var e *UnresolvedError
	return errors.As(err, &e)
}

type RemoteResolver interface {
	Resolve(ctx context.Context, mod *ParsedModule) (localPath string, err error)
}

type ModuleParseResult struct {
	Index  int
	Module ParsedModule
	Error  error
}

type moduleWorkItem struct {
	index int
	key   string
}

type ModuleAttributesInfo struct {
	Resources []string          `json:"resources"`
	Inputs    map[string]string `json:"inputs"`
}

func resolveModulePath(source, rootDir string) string {
	clean := strings.TrimPrefix(source, "file://")
	clean = strings.TrimPrefix(clean, "git::")

	// If the path is already absolute, don't join with rootDir
	if filepath.IsAbs(clean) {
		return filepath.Clean(clean)
	}

	return filepath.Clean(filepath.Join(rootDir, clean))
}

func isTerraformFile(filePath string) bool {
	return strings.HasSuffix(strings.ToLower(filePath), ".tf")
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
	name    string
	defLine int
	source  hclsyntax.Expression
	version hclsyntax.Expression
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
			mod := moduleBlockExtract{name: block.Labels[0], defLine: block.TypeRange.Start.Line}
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
	if diags.HasErrors() || val.IsNull() || !val.IsKnown() || !val.Type().Equals(cty.String) {
		return "", false
	}
	return val.AsString(), true
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
		if file == nil || !isTerraformFile(file.FilePath) {
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
	return parseModulesByDir(ctx, fsys, files, nil, numWorkers)
}

// parseModulesByDir resolves module blocks one directory at a time. Locals and
// vars are scoped per Terraform module root (a directory), so grouping by
// directory both preserves that scoping — the same name may be defined
// differently in two directories — and bounds how much parsed Terraform is live
// at once: the directories in flight rather than the whole repository.
//
// allowedFiles, when non-nil, restricts which files contribute module blocks;
// every file still contributes locals/vars so resolution stays correct.
func parseModulesByDir(
	ctx context.Context,
	fsys vfs.FS,
	files model.FileMetadatas,
	allowedFiles map[string]bool,
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
			found, err := parseDirModules(ctx, fsys, extracts, group, allowedFiles)
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
	allowedFiles map[string]bool,
) (map[string]ParsedModule, error) {
	contextLogger := logger.FromContext(ctx)
	fileExtracts := make([]*fileExtract, len(group.files))
	localsMap := make(map[string]string)
	varsMap := make(map[string]string)

	for i, file := range group.files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		extract, diags := extractForContent(extracts, getFileContent(file), file.FilePath)
		if diags.HasErrors() {
			contextLogger.Warn().Msgf("Skipping file %s due to HCL parse errors: %s", file.FilePath, diags.Error())
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

	modules := make(map[string]ParsedModule)
	for i, file := range group.files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		extract := fileExtracts[i]
		if extract == nil || len(extract.modules) == 0 {
			continue
		}
		if allowedFiles != nil && !allowedFiles[file.FilePath] {
			continue
		}
		resolveModuleBlocks(ctx, fsys, group.dir, file.FilePath, extract.modules, localsMap, varsMap, modules)
	}
	return modules, nil
}

// resolveModuleBlocks turns a file's extracted module blocks into ParsedModules,
// resolving relative sources against baseDir (the directory holding filePath).
func resolveModuleBlocks(
	ctx context.Context,
	fsys vfs.FS,
	baseDir, filePath string,
	blocks []moduleBlockExtract,
	localsMap, varsMap map[string]string,
	modules map[string]ParsedModule,
) {
	for i := range blocks {
		mod := ParsedModule{
			Name:     blocks[i].name,
			FileName: filePath,
			DefLine:  blocks[i].defLine,
		}
		fillModuleAttrs(ctx, fsys, &mod, &blocks[i], baseDir, localsMap, varsMap)
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
	mod.IsLocal = LooksLikeLocalModuleSource(strings.TrimPrefix(resolved, "git::"))
	if !mod.IsLocal {
		return
	}
	sourcePath := strings.TrimPrefix(resolved, "file://")
	absPath := filepath.Clean(sourcePath)
	if !filepath.IsAbs(sourcePath) {
		absPath = filepath.Join(baseDir, sourcePath)
	}
	var err error
	mod.AbsSource, err = fsys.Abs(absPath)
	if err != nil {
		log.Warn().Msgf("Could not compute absolute path name for %v: %v", absPath, err)
		mod.AbsSource = filepath.Clean(absPath)
	}
	if err = validateModuleSource(ctx, fsys, mod.AbsSource); err != nil {
		log.Warn().Msgf("Invalid local module source %q: %v", mod.Source, err)
	}
}

func moduleIdentityKey(mod *ParsedModule) string {
	return mod.Source + "\x00" + mod.Version + "\x00" + mod.Name + "\x00" + mod.FileName
}

func validateModuleSource(ctx context.Context, fsys vfs.FS, absPath string) error {
	entries, err := fsys.ReadDir(absPath)
	if err != nil {
		return fmt.Errorf("module source path %q is not accessible: %w", absPath, err)
	}

	valid := false
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".tf") {
			valid = true
			break
		}
	}

	if !valid {
		wrn := fmt.Errorf("module at %s does not contain any .tf files", absPath)
		contextLogger := logger.FromContext(ctx)
		contextLogger.Warn().Msg(wrn.Error())
		return wrn
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
	if e.Val.Type().Equals(cty.String) {
		return e.Val.AsString()
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
			switch s.Key.Type() {
			case cty.Number:
				sourceStr += "[" + s.Key.AsBigFloat().String() + "]"
			case cty.String:
				sourceStr += "[" + s.Key.AsString() + "]"
			}
		}
	}
	return sourceStr
}

func resolveExprDefault(expr hclsyntax.Expression) string {
	val, diag := expr.Value(nil)
	if !diag.HasErrors() &&
		val.Type().Equals(cty.String) &&
		!val.IsNull() {
		return val.AsString()
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

	if source == "" {
		return false
	}

	// Handle file:// URL scheme (file:///path/to/module)
	if strings.HasPrefix(source, "file://") {
		return true
	}

	// Unwrap common go-getter schemes like git:: or hg::
	schemes := []string{"git::", "hg::", "http::", "https::"}
	for _, scheme := range schemes {
		if after, ok := strings.CutPrefix(source, scheme); ok {
			source = after
			break
		}
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

// resolveModuleToLocalPath maps mod to a local directory, or returns ("", nil) when the module
// should be silently skipped (no resolver, or remote with nil resolver).
func resolveModuleToLocalPath(
	ctx context.Context, mod *ParsedModule, rootDir string, resolver RemoteResolver,
) (string, error) {
	if mod.IsLocal {
		return resolveModulePath(mod.AbsSource, rootDir), nil
	}
	if resolver == nil {
		return "", nil // no resolver: skip remote silently
	}
	p, err := resolver.Resolve(ctx, mod)
	if err != nil {
		return "", err
	}
	return p, nil
}

// moduleEnrichCache shares equivalent-map parsing across call sites of the same directory.
type moduleEnrichCache struct {
	fsys vfs.FS
	sf   singleflight.Group
	mu   sync.Mutex
	m    map[string]map[string]ModuleAttributesInfo
}

func newModuleEnrichCache(fsys vfs.FS) *moduleEnrichCache {
	if fsys == nil {
		fsys = vfs.DiskFS{}
	}
	return &moduleEnrichCache{fsys: fsys, m: make(map[string]map[string]ModuleAttributesInfo)}
}

func (c *moduleEnrichCache) attributesFor(ctx context.Context, modulePath string) (map[string]ModuleAttributesInfo, error) {
	c.mu.Lock()
	if v, ok := c.m[modulePath]; ok {
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()

	v, err, _ := c.sf.Do(modulePath, func() (interface{}, error) {
		res, genErr := generateEquivalentMap(ctx, c.fsys, modulePath)
		if genErr != nil {
			return nil, genErr
		}
		c.mu.Lock()
		c.m[modulePath] = res
		c.mu.Unlock()
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string]ModuleAttributesInfo), nil
}

func enrichModule(
	ctx context.Context, mod *ParsedModule, rootDir string, resolver RemoteResolver, cache *moduleEnrichCache,
) ModuleParseResult {
	contextLogger := logger.FromContext(ctx)
	localPath, err := resolveModuleToLocalPath(ctx, mod, rootDir, resolver)
	if err != nil {
		contextLogger.Warn().Msgf("Skipping module %s: %v", mod.Name, err)
		return ModuleParseResult{Module: *mod}
	}
	if localPath == "" {
		return ModuleParseResult{Module: *mod}
	}
	mod.AbsSource = localPath
	attributesData, enrichErr := cache.attributesFor(ctx, localPath)
	if enrichErr != nil {
		contextLogger.Warn().Msg("Failed to generate equivalent map")
	} else {
		mod.AttributesData = attributesData
	}
	return ModuleParseResult{Module: *mod, Error: enrichErr}
}

const minParseWorkers = 4

// ParseAllModuleVariables resolves modules to disk and fills AttributesData.
// Resolution failures for individual modules are non-fatal and logged; only a
// context cancellation returns an error.
func ParseAllModuleVariables(
	ctx context.Context, fsys vfs.FS, modules map[string]ParsedModule, rootDir string, resolver RemoteResolver,
) ([]ParsedModule, error) {
	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers < minParseWorkers {
		numWorkers = minParseWorkers
	}

	keys := make([]string, 0, len(modules))
	for key := range modules {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	input := make(chan moduleWorkItem)
	output := make(chan ModuleParseResult)
	enrichCache := newModuleEnrichCache(fsys)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runModuleEnrichWorker(ctx, input, output, modules, rootDir, resolver, enrichCache)
		}()
	}
	go func() {
		wg.Wait()
		close(output)
	}()
	go func() {
		defer close(input)
		for i, key := range keys {
			select {
			case <-ctx.Done():
				return
			case input <- moduleWorkItem{index: i, key: key}:
			}
		}
	}()

	result := collectModuleResults(ctx, output, len(keys))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func runModuleEnrichWorker(
	ctx context.Context,
	input <-chan moduleWorkItem,
	output chan<- ModuleParseResult,
	modules map[string]ParsedModule,
	rootDir string,
	resolver RemoteResolver,
	cache *moduleEnrichCache,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case item, ok := <-input:
			if !ok {
				return
			}
			mod := modules[item.key]
			result := enrichModule(ctx, &mod, rootDir, resolver, cache)
			result.Index = item.index
			select {
			case <-ctx.Done():
				return
			case output <- result:
			}
		}
	}
}

func collectModuleResults(
	ctx context.Context, output <-chan ModuleParseResult, moduleCount int,
) []ParsedModule {
	contextLogger := logger.FromContext(ctx)
	finalModules := make([]ParsedModule, moduleCount)
	for {
		select {
		case <-ctx.Done():
			return nil
		case res, ok := <-output:
			if !ok {
				return finalModules
			}
			if res.Error == nil {
				contextLogger.Debug().Msgf("Enriched module %s", res.Module.Name)
			}
			finalModules[res.Index] = res.Module
		}
	}
}

func generateEquivalentMap(ctx context.Context, fsys vfs.FS, modulePath string) (map[string]ModuleAttributesInfo, error) {
	contextLogger := logger.FromContext(ctx)
	equivalentMap := make(map[string]ModuleAttributesInfo)
	resourceTypesMap := make(map[string]map[string]bool)

	entries, err := fsys.ReadDir(modulePath)
	if err != nil {
		if os.IsNotExist(err) {
			contextLogger.Debug().Msgf("module source directory not found, skipping enrichment: %s", modulePath)
		} else {
			contextLogger.Warn().Msgf("cannot read module source directory: %s: %v", modulePath, err)
		}
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !isTerraformFile(entry.Name()) {
			continue
		}
		path := filepath.Join(modulePath, entry.Name())
		if err := processEquivalentMapFile(ctx, fsys, path, equivalentMap, resourceTypesMap); err != nil {
			return nil, err
		}
	}

	// After iterating through all files and blocks, populate the unique resources
	// slice. Sort it so the result is deterministic across runs: it is built from
	// a map, and unstable ordering otherwise yields byte-different module input
	// data each scan (which defeats the compiled-query cache and makes output
	// non-reproducible).
	for provider, typesSet := range resourceTypesMap {
		modInfo := equivalentMap[provider]
		for rt := range typesSet {
			modInfo.Resources = append(modInfo.Resources, rt)
		}
		sort.Strings(modInfo.Resources)
		equivalentMap[provider] = modInfo
	}
	return equivalentMap, nil
}

func processEquivalentMapFile(
	ctx context.Context,
	fsys vfs.FS,
	path string,
	equivalentMap map[string]ModuleAttributesInfo,
	resourceTypesMap map[string]map[string]bool,
) error {
	contextLogger := logger.FromContext(ctx)

	contents, err := fsys.ReadFile(filepath.Clean(path))
	if err != nil {
		contextLogger.Error().Msgf("Failed to read file: %s", path)
		return err
	}

	hclFile, diag := hclwrite.ParseConfig(contents, "", hcl.InitialPos)
	if diag.HasErrors() {
		parseErr := fmt.Errorf("error parsing input Terraform block in file %s: %s", path, diag.Error())
		contextLogger.Error().Msg(parseErr.Error())
		return parseErr
	}

	for _, block := range hclFile.Body().Blocks() {
		if block.Type() != "resource" {
			continue
		}
		if len(block.Labels()) < 1 {
			contextLogger.Warn().Msgf("Skipping malformed resource block with no labels in file %s", path)
			continue
		}
		resourceType := block.Labels()[0]
		provider, err := GetProviderFromResourceType(resourceType)
		if err != nil {
			contextLogger.Warn().Msgf("Failed to get provider from resource type '%s' in file %s: %v", resourceType, path, err)
			continue
		}
		if _, ok := resourceTypesMap[provider]; !ok {
			resourceTypesMap[provider] = make(map[string]bool)
		}
		resourceTypesMap[provider][resourceType] = true

		modInfo, ok := equivalentMap[provider]
		if !ok {
			modInfo = ModuleAttributesInfo{Resources: []string{}, Inputs: make(map[string]string)}
		}
		maps.Copy(modInfo.Inputs, getVariableAttributes(block))
		equivalentMap[provider] = modInfo
	}
	return nil
}

func getVariableAttributes(block *hclwrite.Block) map[string]string {
	attributeToVariableMap := make(map[string]string)
	for name, attr := range block.Body().Attributes() {
		value := string(attr.Expr().BuildTokens(nil).Bytes())
		if !isVariableReference(value) {
			continue
		}

		if varName := parseVariableReference(value); varName != "" {
			attributeToVariableMap[name] = varName
		}
	}

	// Handle nested blocks too
	for _, nestedBlock := range block.Body().Blocks() {
		maps.Copy(attributeToVariableMap, getVariableAttributes(nestedBlock))
	}
	return attributeToVariableMap
}

func isVariableReference(s string) bool {
	return strings.Contains(s, "var.")
}

var reVarRef = regexp.MustCompile(`^var\.(\w+)$`)

func parseVariableReference(s string) string {
	match := reVarRef.FindStringSubmatch(strings.TrimSpace(s))
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

// ParseTerraformModulesFromFiles is a variant of ParseTerraformModules that accepts an
// optional allowedFiles set to restrict which files contribute module blocks (all files
// still contribute locals/vars for correct resolution). fsys is used for local-source
// path validation; a nil fsys falls back to vfs.DiskFS{}.
func ParseTerraformModulesFromFiles(
	ctx context.Context, fsys vfs.FS, files model.FileMetadatas, allowedFiles map[string]bool,
) (map[string]ParsedModule, error) {
	return parseModulesByDir(ctx, fsys, files, allowedFiles, 0)
}

// LoadTFFilesFromDir returns FileMetadata for top-level .tf files in dir (no recursion —
// a Terraform module is a single directory). When packageRoot is non-empty, symlinked .tf
// files are included only when their targets stay within the package root.
func LoadTFFilesFromDir(dir, packageRoot string) (model.FileMetadatas, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving module dir %q: %w", dir, err)
	}
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return nil, fmt.Errorf("reading module dir %q: %w", absDir, err)
	}
	var files model.FileMetadatas
	for _, entry := range entries {
		path, ok := ScannableTerraformPath(entry, absDir, packageRoot)
		if !ok {
			continue
		}
		data, readErr := os.ReadFile(path) //nolint:gosec
		if readErr != nil {
			return nil, fmt.Errorf("reading %q: %w", path, readErr)
		}
		files = append(files, &model.FileMetadata{
			FilePath:     filepath.Clean(path),
			OriginalData: string(data),
		})
	}
	return files, nil
}

func ScannableTerraformPath(entry fs.DirEntry, dir, packageRoot string) (string, bool) {
	if entry.IsDir() {
		return "", false
	}
	name := entry.Name()
	if !strings.HasSuffix(strings.ToLower(name), ".tf") {
		return "", false
	}
	candidate := filepath.Join(dir, name)
	entryType := entry.Type()
	if entryType.IsRegular() {
		return candidate, true
	}
	if entryType&fs.ModeSymlink == 0 && entryType != 0 {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", false
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	confineRoot := packageRoot
	if confineRoot == "" {
		confineRoot = dir
	}
	resolvedRoot, err := filepath.EvalSymlinks(filepath.Clean(confineRoot))
	if err != nil {
		return "", false
	}
	resolvedTarget, err := filepath.EvalSymlinks(filepath.Clean(resolved))
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(resolvedRoot, resolvedTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", false
	}
	return candidate, true
}

// GetProviderFromResourceType extracts the provider name from a Terraform resource type.
// For example: "aws_s3_bucket" → "aws", "azurerm_network_interface" → "azurerm"
func GetProviderFromResourceType(resourceType string) (string, error) {
	if resourceType == "" {
		return "", errors.New("resource type cannot be empty")
	}
	parts := strings.SplitN(resourceType, "_", 2)
	if len(parts) < 2 {
		return "", errors.New("invalid Terraform resource type format")
	}
	return parts[0], nil
}
