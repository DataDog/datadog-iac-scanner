package tfmodules

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/hclexpr"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
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

type UnresolvedModule struct {
	Module ParsedModule
	Reason string
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
	Module           ParsedModule
	Error            error
	Unresolved       bool
	UnresolvedReason string
}

type ModuleAttributesInfo struct {
	Resources []string          `json:"resources"`
	Inputs    map[string]string `json:"inputs"`
}

var registryPattern = regexp.MustCompile(`^[a-z0-9\-]+/[a-z0-9\-]+/[a-z0-9\-]+$`)

func isValidRegistryFormat(s string) bool {
	return registryPattern.MatchString(s)
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

// bodyCacheKey identifies file content by length plus a 64-bit content hash.
type bodyCacheKey struct {
	len  int
	hash uint64
}

// parseHCLBodyCached parses Terraform bytes, caching by content hash. Cache is
// per-scan (passed in by the caller) so it does not grow across scans.
func parseHCLBodyCached(cache *sync.Map, content, filePath string) (*hclsyntax.Body, hcl.Diagnostics) {
	key := bodyCacheKey{len: len(content), hash: xxhash.Sum64String(content)}
	if cached, ok := cache.Load(key); ok {
		return cached.(*hclsyntax.Body), nil
	}
	hclFile, diags := hclsyntax.ParseConfig([]byte(content), filePath, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, diags
	}
	body, ok := hclFile.Body.(*hclsyntax.Body)
	if !ok {
		return nil, diags
	}
	cache.Store(key, body)
	return body, diags
}

func parseHCLBodies(ctx context.Context, files model.FileMetadatas, numWorkers int) map[string]*hclsyntax.Body {
	contextLogger := logger.FromContext(ctx)
	parsedBodies := make(map[string]*hclsyntax.Body)

	tfFiles := make([]*model.FileMetadata, 0, len(files))
	for _, file := range files {
		if isTerraformFile(file.FilePath) {
			tfFiles = append(tfFiles, file)
		}
	}
	if len(tfFiles) == 0 {
		return parsedBodies
	}

	bodyCache := &sync.Map{}

	bodies := make([]*hclsyntax.Body, len(tfFiles))
	numWorkers = utils.AdjustNumWorkers(numWorkers)
	if numWorkers > len(tfFiles) {
		numWorkers = len(tfFiles)
	}

	indices := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range indices {
				file := tfFiles[i]
				content := getFileContent(file)
				body, diags := parseHCLBodyCached(bodyCache, content, file.FilePath)
				if diags.HasErrors() {
					contextLogger.Warn().Msgf("Skipping file %s due to HCL parse errors: %s", file.FilePath, diags.Error())
					continue
				}
				if body == nil {
					contextLogger.Error().Msgf("Unexpected body type in %s", file.FilePath)
					continue
				}
				bodies[i] = body
			}
		}()
	}
	for i := range tfFiles {
		indices <- i
	}
	close(indices)
	wg.Wait()

	for i, file := range tfFiles {
		if bodies[i] != nil {
			parsedBodies[file.FilePath] = bodies[i]
		}
	}
	return parsedBodies
}

func collectLocalsAndVars(body *hclsyntax.Body, localsMap, varsMap map[string]string) {
	for _, block := range body.Blocks {
		switch block.Type {
		case "locals":
			for name, attr := range block.Body.Attributes {
				val, diag := attr.Expr.Value(nil)
				if !diag.HasErrors() && val.Type().Equals(cty.String) && !val.IsNull() {
					localsMap[name] = val.AsString()
				}
			}
		case "variable":
			if len(block.Labels) != 1 {
				continue
			}
			varName := block.Labels[0]
			if defAttr, ok := block.Body.Attributes["default"]; ok {
				val, diag := defAttr.Expr.Value(nil)
				if !diag.HasErrors() && val.Type().Equals(cty.String) && !val.IsNull() {
					varsMap[varName] = val.AsString()
				}
			}
		}
	}
}

// ParseTerraformModules parses HCL content and extracts module source/version.
// numWorkers: 0 means auto-detect (GOMAXPROCS).
func ParseTerraformModules(ctx context.Context, files model.FileMetadatas, numWorkers int) (map[string]ParsedModule, error) {
	return ParseTerraformModulesFromFiles(ctx, files, nil, numWorkers)
}

// ParseTerraformModulesFromFiles resolves locals/variables from all files, but extracts module blocks
// only from allowed files. numWorkers: 0 means auto-detect.
func ParseTerraformModulesFromFiles(
	ctx context.Context, files model.FileMetadatas, allowedFiles map[string]bool, numWorkers ...int,
) (map[string]ParsedModule, error) {
	workers := 0
	if len(numWorkers) > 0 {
		workers = numWorkers[0]
	}
	parsedBodies := parseHCLBodies(ctx, files, workers)
	modules := make(map[string]ParsedModule)

	// Group files by directory so locals/vars are scoped per Terraform module root,
	// preventing cross-root contamination when the same local/variable name is defined
	// differently in two separate directories.
	type dirEntry struct {
		file *model.FileMetadata
		body *hclsyntax.Body
	}
	byDir := make(map[string][]dirEntry)
	for i := range files {
		file := files[i]
		body := parsedBodies[file.FilePath]
		if body == nil {
			continue
		}
		dir := filepath.Dir(file.FilePath)
		byDir[dir] = append(byDir[dir], dirEntry{file, body})
	}

	for _, entries := range byDir {
		localsMap := make(map[string]string)
		varsMap := make(map[string]string)
		for _, e := range entries {
			collectLocalsAndVars(e.body, localsMap, varsMap)
		}
		for _, e := range entries {
			if allowedFiles != nil && !allowedFiles[e.file.FilePath] {
				continue
			}
			extractModuleBlocks(ctx, e.file.FilePath, e.body, localsMap, varsMap, modules)
		}
	}
	return modules, nil
}

func extractModuleBlocks(
	ctx context.Context,
	filePath string,
	body *hclsyntax.Body,
	localsMap, varsMap map[string]string,
	modules map[string]ParsedModule,
) {
	baseDir := filepath.Dir(filePath)
	for _, block := range body.Blocks {
		if block.Type != "module" || len(block.Labels) == 0 {
			continue
		}
		mod := ParsedModule{
			Name:     block.Labels[0],
			FileName: filePath,
			DefLine:  block.TypeRange.Start.Line,
		}
		fillModuleAttrs(ctx, &mod, block, baseDir, localsMap, varsMap)
		key := moduleIdentityKey(&mod)
		if _, exists := modules[key]; !exists {
			modules[key] = mod
		}
	}
}

func fillModuleAttrs(
	ctx context.Context,
	mod *ParsedModule,
	block *hclsyntax.Block,
	baseDir string,
	localsMap, varsMap map[string]string,
) {
	log := logger.FromContext(ctx)
	for key, attr := range block.Body.Attributes {
		resolved := resolveExpr(attr.Expr, localsMap, varsMap)
		switch key {
		case "source":
			mod.Source = resolved
			mod.SourceType, mod.RegistryScope = DetectModuleSourceType(resolved)
			mod.IsLocal = LooksLikeLocalModuleSource(strings.TrimPrefix(resolved, "git::"))
			if mod.IsLocal {
				absPath := filepath.Join(baseDir, strings.TrimPrefix(resolved, "file://"))
				var err error
				mod.AbsSource, err = filepath.Abs(absPath)
				if err != nil {
					log.Warn().Msgf("Could not compute absolute path name for %v: %v", absPath, err)
					mod.AbsSource = filepath.Clean(absPath)
				}
				if err = validateModuleSource(ctx, mod.AbsSource); err != nil {
					log.Warn().Msgf("Invalid local module source %q: %v", mod.Source, err)
				}
			}
		case "version":
			mod.Version = resolved
		}
	}
}

func moduleIdentityKey(mod *ParsedModule) string {
	return mod.Source + "\x00" + mod.Version + "\x00" + mod.Name + "\x00" + mod.FileName
}

func validateModuleSource(ctx context.Context, absPath string) error {
	entries, err := os.ReadDir(absPath)
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
	registrySource := source
	if idx := strings.Index(registrySource, "//"); idx != -1 {
		registrySource = registrySource[:idx]
	}

	if strings.HasPrefix(source, "data_ref:") {
		return "data_ref", ""
	}

	// Recognize git-based sources
	if strings.HasPrefix(source, "git::") {
		return "git", ""
	}

	// Recognize public registry hostname
	if strings.HasPrefix(registrySource, "registry.terraform.io/") {
		return stringRegistry, stringPublic
	}

	// Recognize private registries by fully qualified domain with 3 parts
	if strings.Count(registrySource, "/") == 3 && strings.Contains(registrySource, ".") {
		return stringRegistry, stringPrivate
	}

	// Recognize implicit public registry format (namespace/name/provider)
	if isValidRegistryFormat(registrySource) {
		return stringRegistry, stringPublic
	}

	if LooksLikeLocalModuleSource(source) {
		return stringLocal, ""
	}

	return stringUnknown, ""
}

// resolveModuleToLocalPath resolves mod to a directory; unresolved+reason on failure. Nil resolver: locals only, remotes unchanged.
func resolveModuleToLocalPath(
	ctx context.Context, mod *ParsedModule, rootDir string, resolver RemoteResolver,
) (localPath string, unresolved bool, reason string) {
	if mod.IsLocal {
		return resolveModulePath(mod.AbsSource, rootDir), false, ""
	}
	if resolver == nil {
		return "", false, "" // nil resolver: leave remote as-is
	}
	p, err := resolver.Resolve(ctx, mod)
	if err != nil {
		r := err.Error()
		var ue *UnresolvedError
		if errors.As(err, &ue) {
			r = ue.Reason
		}
		return "", true, r
	}
	return p, false, ""
}

// moduleEnrichCache shares equivalent-map parsing across call sites of the same directory.
type moduleEnrichCache struct {
	sf singleflight.Group
	mu sync.Mutex
	m  map[string]map[string]ModuleAttributesInfo
}

func newModuleEnrichCache() *moduleEnrichCache {
	return &moduleEnrichCache{m: make(map[string]map[string]ModuleAttributesInfo)}
}

func (c *moduleEnrichCache) attributesFor(ctx context.Context, modulePath string) (map[string]ModuleAttributesInfo, error) {
	c.mu.Lock()
	if v, ok := c.m[modulePath]; ok {
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()

	v, err, _ := c.sf.Do(modulePath, func() (interface{}, error) {
		res, genErr := generateEquivalentMap(ctx, modulePath)
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
	localPath, unresolved, reason := resolveModuleToLocalPath(ctx, mod, rootDir, resolver)
	if unresolved {
		return ModuleParseResult{Module: *mod, Unresolved: true, UnresolvedReason: reason}
	}
	if localPath == "" {
		return ModuleParseResult{Module: *mod}
	}
	contextLogger := logger.FromContext(ctx)
	attributesData, err := cache.attributesFor(ctx, localPath)
	if err != nil {
		contextLogger.Warn().Msg("Failed to generate equivalent map")
	} else {
		mod.AttributesData = attributesData
	}
	return ModuleParseResult{Module: *mod, Error: err}
}

const minParseWorkers = 4

// ParseAllModuleVariables resolves modules to disk and fills AttributesData.
// With a non-nil resolver, failed remote resolves are returned as UnresolvedModule.
func ParseAllModuleVariables(
	ctx context.Context, modules map[string]ParsedModule, rootDir string, resolver RemoteResolver,
) ([]ParsedModule, []UnresolvedModule) {
	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers < minParseWorkers {
		numWorkers = minParseWorkers
	}

	input := make(chan ParsedModule)
	output := make(chan ModuleParseResult)
	enrichCache := newModuleEnrichCache()

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runModuleEnrichWorker(ctx, input, output, rootDir, resolver, enrichCache)
		}()
	}
	go func() {
		wg.Wait()
		close(output)
	}()
	go func() {
		defer close(input)
		for key := range modules {
			select {
			case <-ctx.Done():
				return
			case input <- modules[key]:
			}
		}
	}()

	return collectModuleResults(ctx, output, modules)
}

func runModuleEnrichWorker(
	ctx context.Context,
	input <-chan ParsedModule,
	output chan<- ModuleParseResult,
	rootDir string,
	resolver RemoteResolver,
	cache *moduleEnrichCache,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case mod, ok := <-input:
			if !ok {
				return
			}
			result := enrichModule(ctx, &mod, rootDir, resolver, cache)
			select {
			case <-ctx.Done():
				return
			case output <- result:
			}
		}
	}
}

func collectModuleResults(
	ctx context.Context, output <-chan ModuleParseResult, modules map[string]ParsedModule,
) ([]ParsedModule, []UnresolvedModule) {
	contextLogger := logger.FromContext(ctx)
	finalModules := make([]ParsedModule, 0, len(modules))
	unresolvedModules := make([]UnresolvedModule, 0)
	for {
		select {
		case <-ctx.Done():
			return finalModules, unresolvedModules
		case res, ok := <-output:
			if !ok {
				return finalModules, unresolvedModules
			}
			if res.Unresolved {
				unresolvedModules = append(unresolvedModules, UnresolvedModule{Module: res.Module, Reason: res.UnresolvedReason})
				continue
			}
			if res.Error != nil {
				contextLogger.Warn().Msgf("Failed to parse module %s: %v", res.Module.Name, res.Error)
			}
			finalModules = append(finalModules, res.Module)
		}
	}
}

func generateEquivalentMap(ctx context.Context, modulePath string) (map[string]ModuleAttributesInfo, error) {
	contextLogger := logger.FromContext(ctx)
	equivalentMap := make(map[string]ModuleAttributesInfo)
	resourceTypesMap := make(map[string]map[string]bool)

	entries, err := os.ReadDir(modulePath)
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
		if err := processEquivalentMapFile(ctx, path, equivalentMap, resourceTypesMap); err != nil {
			return nil, err
		}
	}

	for provider, typesSet := range resourceTypesMap {
		modInfo := equivalentMap[provider]
		for rt := range typesSet {
			modInfo.Resources = append(modInfo.Resources, rt)
		}
		equivalentMap[provider] = modInfo
	}
	return equivalentMap, nil
}

func processEquivalentMapFile(
	ctx context.Context,
	path string,
	equivalentMap map[string]ModuleAttributesInfo,
	resourceTypesMap map[string]map[string]bool,
) error {
	contextLogger := logger.FromContext(ctx)

	contents, err := os.ReadFile(filepath.Clean(path))
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

// LoadTFFilesFromDir returns FileMetadata for top-level .tf files in dir only (Terraform module = one directory).
func LoadTFFilesFromDir(dir string) (model.FileMetadatas, error) {
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
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".tf") {
			continue
		}
		absPath := filepath.Clean(filepath.Join(absDir, name))
		data, readErr := os.ReadFile(absPath)
		if readErr != nil {
			return nil, fmt.Errorf("reading %q: %w", absPath, readErr)
		}
		files = append(files, &model.FileMetadata{
			FilePath:     absPath,
			OriginalData: string(data),
		})
	}
	return files, nil
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
