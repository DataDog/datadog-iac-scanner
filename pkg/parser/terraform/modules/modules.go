package tfmodules

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
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
	// HCL parsing is CPU-bound, so the pool draws from the shared CPU budget.
	_ = utils.ForEach(ctx, tfFiles, utils.PoolOptions{Workers: numWorkers, CPUBound: true},
		func(_ context.Context, file *model.FileMetadata, i int) error {
			content := getFileContent(file)
			body, diags := parseHCLBodyCached(bodyCache, content, file.FilePath)
			if diags.HasErrors() {
				contextLogger.Warn().Msgf("Skipping file %s due to HCL parse errors: %s", file.FilePath, diags.Error())
				return nil
			}
			if body == nil {
				contextLogger.Error().Msgf("Unexpected body type in %s", file.FilePath)
				return nil
			}
			bodies[i] = body
			return nil
		})

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

func extractModuleBlocks(
	ctx context.Context,
	fsys vfs.FS,
	filePath string,
	body *hclsyntax.Body,
	localsMap, varsMap map[string]string,
	modules map[string]ParsedModule,
) {
	contextLogger := logger.FromContext(ctx)
	baseDir := filepath.Dir(filePath)
	for _, block := range body.Blocks {
		if block.Type != "module" || len(block.Labels) == 0 {
			continue
		}

		mod := ParsedModule{Name: block.Labels[0]}

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
					mod.AbsSource, err = fsys.Abs(absPath)
					if err != nil {
						contextLogger.Warn().Msgf("Could not compute absolute path name for %v: %v", absPath, err)
						mod.AbsSource = filepath.Clean(absPath)
					}
					err = validateModuleSource(ctx, fsys, mod.AbsSource)
					if err != nil {
						contextLogger.Warn().Msgf("Invalid local module source %q: %v", mod.Source, err)
						continue
					}
				}

			case "version":
				mod.Version = resolved
			}
		}

		// Use the resolved absolute path as the key for local modules so that
		// two roots with identical relative sources (e.g. "./module") are stored
		// as separate entries rather than one silently overwriting the other.
		key := mod.Source
		if mod.IsLocal && mod.AbsSource != "" {
			key = mod.AbsSource
		}
		if _, exists := modules[key]; !exists {
			modules[key] = mod
		}
	}
}

// ParseTerraformModules parses HCL content and extracts module source/version.
// numWorkers: 0 means auto-detect (GOMAXPROCS).
func ParseTerraformModules(ctx context.Context, fsys vfs.FS, files model.FileMetadatas, numWorkers int) (map[string]ParsedModule, error) {
	parsedBodies := parseHCLBodies(ctx, files, numWorkers)
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
		byDir[dir] = append(byDir[dir], dirEntry{file: file, body: body})
	}

	for _, entries := range byDir {
		localsMap := make(map[string]string)
		varsMap := make(map[string]string)
		for _, e := range entries {
			collectLocalsAndVars(e.body, localsMap, varsMap)
		}
		for _, e := range entries {
			extractModuleBlocks(ctx, fsys, e.file.FilePath, e.body, localsMap, varsMap, modules)
		}
	}
	return modules, nil
}

func validateModuleSource(ctx context.Context, fsys vfs.FS, absPath string) error {
	contextLogger := logger.FromContext(ctx)
	// Attempt to read the directory contents
	entries, err := fsys.ReadDir(absPath)
	if err != nil {
		err := fmt.Errorf("module source path %q is not accessible: %w", absPath, err)
		contextLogger.Error().Msg(err.Error())
		return err
	}

	// Check for at least one .tf file
	valid := false
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".tf") {
			valid = true
			break
		}
	}

	if !valid {
		wrn := fmt.Errorf("module at %s does not contain any .tf files", absPath)
		contextLogger.Warn().Msg(wrn.Error())
		return wrn
	}
	return nil
}

func getFileContent(file *model.FileMetadata) string {
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

// nolint:gocritic
func DetectModuleSourceType(source string) (string, string) {
	source = strings.TrimSpace(source)

	if source == "" {
		return stringUnknown, ""
	}

	if strings.HasPrefix(source, "data_ref:") {
		return "data_ref", ""
	}

	// Recognize git-based sources
	if strings.HasPrefix(source, "git::") {
		return "git", ""
	}

	// Recognize public registry hostname
	if strings.HasPrefix(source, "registry.terraform.io/") {
		return stringRegistry, stringPublic
	}

	// Recognize private registries by fully qualified domain with 3 parts
	if strings.Count(source, "/") == 3 && strings.Contains(source, ".") {
		return stringRegistry, stringPrivate
	}

	// Recognize implicit public registry format (namespace/name/provider)
	if isValidRegistryFormat(source) {
		return stringRegistry, stringPublic
	}

	if LooksLikeLocalModuleSource(source) {
		return stringLocal, ""
	}

	return stringUnknown, ""
}

func ParseAllModuleVariables(ctx context.Context, fsys vfs.FS, modules map[string]ParsedModule, rootDir string) []ParsedModule {
	contextLogger := logger.FromContext(ctx)

	// Iterate in a stable key order so the result slice is deterministic across
	// scans (map ranging is randomized, which previously made the output order
	// vary and could defeat the downstream compiled-query cache).
	keys := make([]string, 0, len(modules))
	for k := range modules {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	finalModules := make([]ParsedModule, len(keys))
	// Each module's equivalent-map generation reads files and parses HCL
	// (CPU-bound), so the pool draws from the shared CPU budget. Results are
	// written index-aligned, no shared mutable state between workers.
	_ = utils.ForEach(ctx, keys, utils.PoolOptions{CPUBound: true},
		func(ctx context.Context, key string, i int) error {
			mod := modules[key]
			if !mod.IsLocal {
				finalModules[i] = mod
				return nil
			}
			modulePath := resolveModulePath(mod.AbsSource, rootDir)
			attributesData, err := generateEquivalentMap(ctx, fsys, modulePath)
			if err != nil {
				contextLogger.Warn().Msgf("Failed to parse module %s: %v", mod.Name, err)
			} else {
				mod.AttributesData = attributesData
			}
			finalModules[i] = mod
			return nil
		})
	return finalModules
}

func generateEquivalentMap(ctx context.Context, fsys vfs.FS, modulePath string) (map[string]ModuleAttributesInfo, error) {
	contextLogger := logger.FromContext(ctx)
	equivalentMap := make(map[string]ModuleAttributesInfo)
	resourceTypesMap := make(map[string]map[string]bool)

	entries, err := fsys.ReadDir(modulePath)
	if err != nil {
		contextLogger.Error().Msgf("Failed to read module source directory: %s", modulePath)
		return nil, err
	}

	for _, entry := range entries {
		path := filepath.Join(modulePath, entry.Name())

		if entry.IsDir() {
			contextLogger.Debug().Msgf("Skipping directory: %s", path)
			continue
		}

		if !isTerraformFile(entry.Name()) {
			contextLogger.Debug().Msgf("Skipping non-Terraform file: %s", path)
			continue
		}

		contents, err := fsys.ReadFile(filepath.Clean(path))
		if err != nil {
			contextLogger.Error().Msgf("Failed to read file: %s", path)
			return nil, err
		}

		hclFile, diag := hclwrite.ParseConfig(contents, "", hcl.InitialPos)
		if diag.HasErrors() {
			err := fmt.Errorf("error parsing input Terraform block in file %s: %s", path, diag.Error())
			contextLogger.Error().Msg(err.Error())
			return nil, err
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

			// Store resource type to the set
			if _, ok := resourceTypesMap[provider]; !ok {
				resourceTypesMap[provider] = make(map[string]bool)
			}
			resourceTypesMap[provider][resourceType] = true

			// Create or update the module info object for current provider
			modInfo, ok := equivalentMap[provider]
			if !ok {
				modInfo = ModuleAttributesInfo{
					Resources: []string{},
					Inputs:    make(map[string]string),
				}
			}

			// Update inputs mapping with all attributes referencing a variable
			maps.Copy(modInfo.Inputs, getVariableAttributes(block))

			// Assign the updated modInfo back to the map
			equivalentMap[provider] = modInfo
		}
	}

	// After iterating through all files and blocks, populate the unique resources slice
	for provider, typesSet := range resourceTypesMap {
		modInfo := equivalentMap[provider]
		for rt := range typesSet {
			modInfo.Resources = append(modInfo.Resources, rt)
		}
		equivalentMap[provider] = modInfo
	}

	return equivalentMap, nil
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
