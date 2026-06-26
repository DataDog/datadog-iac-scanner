/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/comment"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/registry"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/utils"
	masterUtils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/pkg/errors"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
	"golang.org/x/sync/singleflight"
)

const (
	// RetriesDefaultValue is default number of times a parser will retry to execute
	RetriesDefaultValue     = 50
	terraformDataIdentifier = "data"
)

// Converter returns content json, error line, error
type Converter func(ctx context.Context, file *hcl.File, inputVariables converter.VariableMap) (model.Document, error)

// Parser struct that contains the function to parse file and the number of retries if something goes wrong
type Parser struct {
	convertFunc       Converter
	numOfRetries      int
	terraformVarsPath string
	sciInfo           model.SCIInfo

	// fsys is the filesystem used for cross-file resolution (sibling .tf files,
	// .tfvars, data sources). Defaults to the real disk; the HTTP server injects
	// an in-memory FS populated from pushed content.
	fsys vfs.FS

	// dirVarsCache memoizes per-directory variable/locals resolution (O(N²) without
	// it). Scoped to the Parser instance, which is created once per scan.
	dirVarsCache sync.Map // dir -> converter.VariableMap
	dirVarsSF    singleflight.Group

	// Registry keeps track of the plan addresses and links them to files
	registry *registry.AddressRegistry
}

// NewDefault initializes a parser with Parser default values
// DEPRECATED: Use New() with a registry instance instead
func NewDefault() *Parser {
	return &Parser{
		numOfRetries: RetriesDefaultValue,
		convertFunc:  converter.DefaultConverted,
		fsys:         vfs.DiskFS{},
		registry:     nil, // No registry - will log error if used
	}
}

// New creates a new parser with an instance registry
func New(reg *registry.AddressRegistry) *Parser {
	return &Parser{
		numOfRetries: RetriesDefaultValue,
		convertFunc:  converter.DefaultConverted,
		registry:     reg,
	}
}

// nolint:gocritic
// DEPRECATED: Use NewWithParams() with a registry instance instead
func NewDefaultWithParams(fsys vfs.FS, terraformVarsPath string, sciInfo model.SCIInfo) *Parser {
	parser := NewDefault()
	if fsys != nil {
		parser.fsys = fsys
	}
	parser.terraformVarsPath = terraformVarsPath
	parser.sciInfo = sciInfo
	return parser
}

// NewWithParams creates a parser with registry, vars path, and sci info
func NewWithParams(fsys vfs.FS, reg *registry.AddressRegistry, terraformVarsPath string, sciInfo model.SCIInfo) *Parser {
	return &Parser{
		numOfRetries:      RetriesDefaultValue,
		convertFunc:       converter.DefaultConverted,
		registry:          reg,
		terraformVarsPath: terraformVarsPath,
		sciInfo:           sciInfo,
	}
}

// Resolve - replace or modifies in-memory content before parsing
func (p *Parser) Resolve(ctx context.Context,
	fileContent []byte,
	filename string, _ bool, _ int) (resolved []byte, vars converter.VariableMap, err error) {
	// handle panic during resolve process
	defer func() {
		if r := recover(); r != nil {
			errMessage := "Recovered from panic during resolve of file " + filename
			masterUtils.HandlePanic(ctx, r, errMessage)
		}
	}()
	vars = p.resolveDirVars(ctx, filepath.Dir(filename), fileContent)
	return fileContent, vars, nil
}

// resolveDirVars returns the variable/locals/data-source map for a directory,
// memoized per directory. Files carrying an inline terraform vars path directive
// are resolved per-file (uncached) because their result depends on file content.
func (p *Parser) resolveDirVars(ctx context.Context, dir string, fileContent []byte) converter.VariableMap {
	if p.terraformVarsPath == "" && strings.Contains(string(fileContent), terraformVarsPathDirective) {
		inputVars := getInputVariables(ctx, p.fsys, dir, string(fileContent), p.terraformVarsPath)
		return getDataSourcePolicy(ctx, p.fsys, dir, inputVars)
	}

	if v, ok := p.dirVarsCache.Load(dir); ok {
		return cloneVariableMap(v.(converter.VariableMap))
	}
	v, _, _ := p.dirVarsSF.Do(dir, func() (interface{}, error) {
		inputVars := getInputVariables(ctx, p.fsys, dir, string(fileContent), p.terraformVarsPath)
		vars := getDataSourcePolicy(ctx, p.fsys, dir, inputVars)
		p.dirVarsCache.Store(dir, vars)
		return vars, nil
	})
	// Return a shallow clone: the converter adds per-file top-level keys to the
	// variable map during evaluation, so each file must get its own map. The
	// cty.Value entries are immutable and safe to share by reference.
	return cloneVariableMap(v.(converter.VariableMap))
}

func cloneVariableMap(src converter.VariableMap) converter.VariableMap {
	dst := make(converter.VariableMap, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func processContent(ctx context.Context, elements model.Document, content, path string) {
	var certInfo map[string]interface{}
	if content != "" {
		certInfo = utils.AddCertificateInfo(ctx, path, content)
		if certInfo != nil {
			elements["certificate_body"] = certInfo
		}
	}
}

func processElements(ctx context.Context, elements model.Document, path string) {
	for k, v3 := range elements { // resource elements
		if k != "certificate_body" {
			continue
		}
		switch value := v3.(type) {
		case string:
			content := utils.CheckCertificate(value)
			processContent(ctx, elements, content, path)
		case ctyjson.SimpleJSONValue:
			if value.Type() != cty.String {
				continue
			}
			content := utils.CheckCertificate(value.AsString())
			processContent(ctx, elements, content, path)
		}
	}
}

func processResourcesElements(ctx context.Context, resourcesElements model.Document, path string) error {
	for _, v2 := range resourcesElements {
		switch t := v2.(type) {
		case []interface{}:
			return errors.New("failed to process resources")
		case interface{}:
			if elements, ok := t.(model.Document); ok {
				processElements(ctx, elements, path)
			}
		}
	}
	return nil
}

func processResources(ctx context.Context, doc model.Document, path string) error {
	var resourcesElements model.Document

	defer func() {
		if r := recover(); r != nil {
			errMessage := "Recovered from panic during process of resources in file " + path
			masterUtils.HandlePanic(ctx, r, errMessage)
		}
	}()

	for _, resources := range doc {
		switch t := resources.(type) {
		case []interface{}: // support the case of nameless resources - where we get a list of resources
			for _, value := range t {
				resourcesElements = value.(model.Document)
				err := processResourcesElements(ctx, resourcesElements, path)
				if err != nil {
					return err
				}
			}

		case interface{}:
			resourcesElements = t.(model.Document)
			err := processResourcesElements(ctx, resourcesElements, path)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func addExtraInfo(ctx context.Context, json []model.Document, path string) ([]model.Document, error) {
	// handle panic during resource processing
	defer func() {
		if r := recover(); r != nil {
			errMessage := "Recovered from panic during resource processing for file " + path
			masterUtils.HandlePanic(ctx, r, errMessage)
		}
	}()
	for _, documents := range json { // iterate over documents
		if resources, ok := documents["resource"].(model.Document); ok {
			err := processResources(ctx, resources, path)
			if err != nil {
				return []model.Document{}, err
			}
		}
	}

	return json, nil
}

func parseFileContent(content []byte, filename string, shouldReplaceDataSource bool) (*hcl.File, hcl.Diagnostics) {
	parsedFile, diagnostics := hclsyntax.ParseConfig(content, filename, hcl.Pos{Line: 1, Column: 1})
	if diagnostics.HasErrors() || !shouldReplaceDataSource {
		return parsedFile, diagnostics
	}
	content = quoteDataSourceTraversals(content, parsedFile)
	return hclsyntax.ParseConfig(content, filename, hcl.Pos{Line: 1, Column: 1})
}

func quoteDataSourceTraversals(source []byte, file *hcl.File) []byte {
	type sourceRange struct {
		start int
		end   int
	}
	var ranges []sourceRange
	_ = hclsyntax.VisitAll(file.Body.(*hclsyntax.Body), func(node hclsyntax.Node) hcl.Diagnostics {
		expr, ok := node.(*hclsyntax.ScopeTraversalExpr)
		if !ok || expr.Traversal.RootName() != terraformDataIdentifier {
			return nil
		}
		exprRange := expr.Range()
		ranges = append(ranges, sourceRange{start: exprRange.Start.Byte, end: exprRange.End.Byte})
		return nil
	})
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start > ranges[j].start
	})
	for _, sourceRange := range ranges {
		quoted := strconv.Quote(string(source[sourceRange.start:sourceRange.end]))
		updated := make([]byte, 0, len(source)+len(quoted))
		updated = append(updated, source[:sourceRange.start]...)
		updated = append(updated, quoted...)
		updated = append(updated, source[sourceRange.end:]...)
		source = updated
	}
	return source
}

// extractAndRegisterAddresses extracts Terraform resource and module addresses from the parsed HCL file
// and registers them in the address registry for later tfplan mapping
func extractAndRegisterAddresses(ctx context.Context, file *hcl.File, filePath string, reg *registry.AddressRegistry) {
	// If no registry provided, silently skip address registration
	// This allows NewDefault() to be used for non-scan scenarios (e.g., unit tests)
	if reg == nil {
		return
	}

	contextLogger := logger.FromContext(ctx)

	// Get the body as hclsyntax.Body
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		contextLogger.Debug().Str("file", filePath).Msg("Could not cast HCL body to hclsyntax.Body")
		return
	}

	resourceCount := 0
	moduleCount := 0

	// Iterate through all blocks in the file
	for _, block := range body.Blocks {
		switch block.Type {
		case "resource":
			// Resource blocks have format: resource "type" "name"
			if len(block.Labels) >= 2 {
				address := fmt.Sprintf("%s.%s", block.Labels[0], block.Labels[1])
				defRange := block.DefRange()
				location := registry.Location{
					FilePath: filePath,
					Line:     defRange.Start.Line,
					Column:   defRange.Start.Column,
				}
				reg.Register(address, location)
				contextLogger.Info().
					Str("address", address).
					Str("file", filePath).
					Int("line", location.Line).
					Msg("HCL: Registered resource address")
				resourceCount++
			}

		case "module":
			// Module blocks have format: module "name"
			if len(block.Labels) >= 1 {
				address := fmt.Sprintf("module.%s", block.Labels[0])
				defRange := block.DefRange()
				location := registry.Location{
					FilePath: filePath,
					Line:     defRange.Start.Line,
					Column:   defRange.Start.Column,
				}
				reg.Register(address, location)
				contextLogger.Info().
					Str("address", address).
					Str("file", filePath).
					Int("line", location.Line).
					Msg("HCL: Registered module address")
				moduleCount++
			}

		case "variable":
			// Variable blocks have format: variable "name"
			// Register as "var.<name>" so the tfplan detector can resolve module_default
			// findings to the variable's default = ... line in variables.tf
			if len(block.Labels) >= 1 {
				address := fmt.Sprintf("var.%s", block.Labels[0])
				defRange := block.DefRange()
				location := registry.Location{
					FilePath: filePath,
					Line:     defRange.Start.Line,
					Column:   defRange.Start.Column,
				}
				reg.Register(address, location)
				contextLogger.Debug().
					Str("address", address).
					Str("file", filePath).
					Int("line", location.Line).
					Msg("HCL: Registered variable address")
			}
		}
	}

	contextLogger.Info().
		Str("file", filePath).
		Int("resources", resourceCount).
		Int("modules", moduleCount).
		Int("totalRegistry", reg.GetMappingCount()).
		Msg("HCL: Completed address registration for file")
}

// Parse execute parser for the content in a file
func (p *Parser) Parse(ctx context.Context, fileContent []byte, path string,
	resolveReferences bool, maxResolverDepth int) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	contextLogger := logger.FromContext(ctx)
	resolved, inputVariables, err := p.Resolve(ctx, fileContent, path, resolveReferences, maxResolverDepth)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	file, diagnostics := hclsyntax.ParseConfig(resolved, filepath.Base(path), hcl.Pos{Byte: 0, Line: 1, Column: 1})
	defer func() {
		if r := recover(); r != nil {
			errMessage := "Recovered from panic during parsing of file " + path
			masterUtils.HandlePanic(ctx, r, errMessage)
		}
	}()
	if diagnostics != nil && diagnostics.HasErrors() && len(diagnostics.Errs()) > 0 {
		err := diagnostics.Errs()[0]
		return nil, nil, nil, nil, err
	}

	// Extract and register Terraform addresses for tfplan mapping
	extractAndRegisterAddresses(ctx, file, path, p.registry)

	ignore, err := comment.ParseComments(resolved, path)
	if err != nil {
		contextLogger.Err(err).Msg("failed to parse comments")
	}

	linesToIgnore := comment.GetIgnoreLines(ignore, file.Body.(*hclsyntax.Body))

	fc, parseErr := p.convertFunc(ctx, file, inputVariables)
	json, err := addExtraInfo(ctx, []model.Document{fc}, path)
	if err != nil {
		return []byte{}, json, []int{}, map[string]model.ResolvedFile{}, errors.Wrap(err, "failed terraform parse")
	}

	return resolved, json, linesToIgnore, resolvedFiles, errors.Wrap(parseErr, "failed terraform parse")
}

// SupportedExtensions returns Terraform extensions
func (p *Parser) SupportedExtensions() []string {
	return []string{".tf", ".tfvars"}
}

// SupportedTypes returns types supported by this parser, which are terraform
func (p *Parser) SupportedTypes() map[string]bool {
	return map[string]bool{"terraform": true}
}

// GetKind returns Terraform kind parser
func (p *Parser) GetKind() model.FileKind {
	return model.KindTerraform
}

// GetCommentToken return the comment token of Terraform - #
func (p *Parser) GetCommentToken() string {
	return "#"
}

// StringifyContent converts original content into string formatted version
func (p *Parser) StringifyContent(content []byte) (string, error) {
	return string(content), nil
}
