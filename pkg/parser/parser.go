/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package parser

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// contentKindParser is an optional parser capability to refine the file kind
// based on the resolved content (e.g. JSON that is actually a Terraform plan).
type contentKindParser interface {
	KindForContent(content []byte) (model.FileKind, bool)
}

// lineInfoParser is an optional parser capability to build the documents of
// a line-info reparse (see WithLineInfoOnly) for less than a full parse. ok
// is false when the content needs a full parse, and true only for a Terraform
// plan.
type lineInfoParser interface {
	ParseLineInfo(content []byte, filePath string) (documents []model.Document, ok bool)
}

// lineInfoSectionParser is an optional parser capability to build a section
// of the line-info document that ParseLineInfo leaves out, when a finding
// needs it. ok is false when the parser has no such section for the content.
type lineInfoSectionParser interface {
	ParseLineInfoSection(content []byte, filePath, name string) (section interface{}, ok bool)
}

// unannotatedParser is an optional parser capability to build documents
// without line markers, for parses marked WithLazyLineInfo. ok is false when
// the content needs a full parse, and true only for a Terraform plan.
type unannotatedParser interface {
	ParseUnannotated(content []byte, filePath string) (documents []model.Document, ok bool)
}

// planParser is an optional parser capability to parse like Parse while
// reporting whether the content parsed as a Terraform plan. Content can keep
// the plan kind and still fall back to plain documents, so the kind alone does
// not tell.
type planParser interface {
	ParsePlan(ctx context.Context, fileContent []byte, filename string, _ bool, _ int) (model.ParseOutput, error)
}

// directoryDependentParser is an optional parser capability declaring that the
// parser's output can depend on files other than the one being parsed (e.g.
// Docker Compose resolves .env, override and extends targets from the file's
// directory). Parsers implementing it must not have their parses shared across
// files with identical content in different directories.
type directoryDependentParser interface {
	DirectoryDependent() bool
}

type kindParser interface {
	GetKind() model.FileKind
	GetCommentToken() string
	SupportedExtensions() []string
	SupportedTypes() map[string]bool
	Parse(ctx context.Context,
		fileContent []byte,
		filename string, _ bool, _ int) ([]byte, []model.Document, []int, map[string]model.ResolvedFile, error)
	StringifyContent(content []byte) (string, error)
}

// Builder is a representation of parsers that will be construct
type Builder struct {
	parsers []kindParser
	fsys    vfs.FS
}

// NewBuilder creates a new Builder's reference
func NewBuilder(ctx context.Context) *Builder {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("parser.NewBuilder()")
	return &Builder{}
}

// WithFS sets the filesystem used for extension detection during parsing. The
// CLI omits it (defaults to the real disk); the HTTP server injects an in-memory
// FS so pushed content (not on disk) is recognized. A nil fsys is ignored.
func (b *Builder) WithFS(fsys vfs.FS) *Builder {
	if fsys != nil {
		b.fsys = fsys
	}
	return b
}

// Add is a function that adds a new parser to the caller and returns it
func (b *Builder) Add(p kindParser) *Builder {
	b.parsers = append(b.parsers, p)
	return b
}

// Build prepares parsers and associates a parser to its extension and returns it
func (b *Builder) Build(types, cloudProviders []string) ([]*Parser, error) {
	// When types[0] == "" the caller requests all platforms; otherwise restrict
	// Parser.Platform to the intersection so that the engine only runs queries
	// for the platforms that were explicitly selected.
	allTypes := len(types) > 0 && types[0] == ""
	requestedSet := make(map[string]bool, len(types))
	for _, t := range types {
		requestedSet[strings.ToLower(t)] = true
	}

	parserSlice := make([]*Parser, 0, len(b.parsers))
	for _, parser := range b.parsers {
		supportedTypes := parser.SupportedTypes()
		if contains(types, supportedTypes) {
			extensions := make(model.Extensions, len(b.parsers))
			for _, ext := range parser.SupportedExtensions() {
				extensions[ext] = struct{}{}
			}
			var platforms []string
			for key := range supportedTypes {
				if allTypes || requestedSet[key] {
					platforms = append(platforms, key)
				}
			}
			parserSlice = append(parserSlice, &Parser{
				Parsers:          parser,
				extensions:       extensions,
				Platform:         platforms,
				documentPlatform: strings.Join(slices.Sorted(maps.Keys(supportedTypes)), ","),
				fsys:             b.fsys,
			})
		}
	}

	return parserSlice, nil
}

// ErrNotSupportedFile represents an error when a file is not supported by the scanner
var ErrNotSupportedFile = errors.New("unsupported file to parse")

// Parser is a struct that associates a parser to its supported extensions
type Parser struct {
	// Parsers is public because necessary for testing purposes
	Parsers          kindParser
	extensions       model.Extensions
	Platform         []string
	SCIInfo          model.SCIInfo
	fsys             vfs.FS
	documentPlatform string
}

// Contract identifies parse behavior that can share results for identical bytes.
func (c *Parser) Contract(path string) string {
	if p, ok := c.Parsers.(interface{ ParseContract(string) string }); ok {
		return p.ParseContract(path)
	}
	return ""
}

// DocumentPlatform identifies the parser's platform set independently of the
// platforms selected for a particular scan.
func (c *Parser) DocumentPlatform() string {
	return c.documentPlatform
}

// FS returns the filesystem used for extension detection. The HTTP server
// injects an in-memory FS for pushed content; the CLI defaults to the real
// disk. Never returns nil so callers can use it directly.
func (c *Parser) FS() vfs.FS {
	if c.fsys == nil {
		return vfs.DiskFS{}
	}
	return c.fsys
}

// ParsedDocument is a struct containing data retrieved from parsing
type ParsedDocument struct {
	Docs          []model.Document
	Kind          model.FileKind
	Content       string
	IgnoreLines   []int
	CountLines    int
	ResolvedFiles map[string]model.ResolvedFile
	IsMinified    bool
	// TerraformPlan marks a file the parser parsed as a Terraform plan. It is
	// false for content that only looks like a plan and falls back to plain
	// documents, though such content keeps the plan kind.
	TerraformPlan bool
	// DirectoryDependent marks parses whose output depends on sibling files
	// (see directoryDependentParser); the runner must not share them across
	// files with identical content.
	DirectoryDependent bool
}

// CommentsCommands gets commands on comments in the file beginning, before the code starts
func (c *Parser) CommentsCommands(ctx context.Context, filePath string, fileContent []byte) model.CommentsCommands {
	if !c.isValidExtension(ctx, filePath) {
		return nil
	}
	return c.commentsCommands(filePath, string(fileContent))
}

// CommentsCommandsFromString reads file directives from content already stored
// as a string, without copying the complete source back to bytes.
func (c *Parser) CommentsCommandsFromString(ctx context.Context, filePath, fileContent string) model.CommentsCommands {
	if !c.isValidExtension(ctx, filePath) {
		return nil
	}
	return c.commentsCommands(filePath, fileContent)
}

func (c *Parser) commentsCommands(filePath, fileContent string) model.CommentsCommands {
	commentsCommands := make(model.CommentsCommands)
	commentToken := c.Parsers.GetCommentToken()
	if commentToken != "" {
		lines := strings.Split(fileContent, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.HasSuffix(filePath, ".yaml") && strings.HasPrefix(line, "---") {
				continue
			}

			if !strings.HasPrefix(line, commentToken) {
				break
			}

			fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, commentToken)))
			if len(fields) > 1 && fields[0] == "dd-iac-scan" && fields[1] != "" {
				commandParameters := strings.SplitN(fields[1], "=", 2)
				if len(commandParameters) > 1 {
					commentsCommands[commandParameters[0]] = commandParameters[1]
				} else {
					commentsCommands[commandParameters[0]] = ""
				}
			}
		}
	}
	return commentsCommands
}

// Parse executes a parser on the fileContent and returns the file content as a Document, the file kind and
// an error, if an error has occurred
func (c *Parser) Parse(
	ctx context.Context,
	filePath string,
	fileContent []byte,
	openAPIResolveReferences, isMinified bool,
	maxResolverDepth int) (ParsedDocument, error) {
	if !c.isValidExtension(ctx, filePath) {
		return unsupportedDocument(), ErrNotSupportedFile
	}
	return c.parseContent(ctx, filePath, fileContent, openAPIResolveReferences, isMinified, maxResolverDepth)
}

// ParseContent uses the selected parser regardless of the file extension.
func (c *Parser) ParseContent(
	ctx context.Context,
	filePath string,
	fileContent []byte,
	openAPIResolveReferences, isMinified bool,
	maxResolverDepth int) (ParsedDocument, error) {
	return c.parseContent(ctx, filePath, fileContent, openAPIResolveReferences, isMinified, maxResolverDepth)
}

func (c *Parser) parseContent(
	ctx context.Context,
	filePath string,
	fileContent []byte,
	openAPIResolveReferences, isMinified bool,
	maxResolverDepth int) (ParsedDocument, error) {
	contextLogger := logger.FromContext(ctx)
	fileContent = utils.DecryptAnsibleVault(ctx, fileContent, utils.GetVaultPassword())

	if lp, ok := c.Parsers.(lineInfoParser); ok && IsLineInfoOnly(ctx) && !IsLineInfoExport(ctx) {
		// A line-info reparse only reads the documents. Only a Terraform plan
		// parses for line info alone.
		if docs, ok := lp.ParseLineInfo(fileContent, filePath); ok {
			return ParsedDocument{
				Docs: docs, Kind: c.contentKind(fileContent), IsMinified: isMinified, TerraformPlan: true,
			}, nil
		}
	}

	out, err := c.parseDocuments(ctx, fileContent, filePath, openAPIResolveReferences, maxResolverDepth)
	if err != nil {
		return ParsedDocument{}, err
	}
	resolved := out.Resolved

	// Terraform resolves checkout symlink placeholders to source bytes while
	// retaining the logical filename. Keep that source for detection and snippets.
	if c.Parsers.GetKind() == model.KindTerraform {
		fileContent = resolved
	}
	// A line-info reparse only reads the documents; the stringified content
	// would be a discarded copy of the whole file.
	cont := ""
	if !IsLineInfoOnly(ctx) {
		cont, err = c.Parsers.StringifyContent(fileContent)
		if err != nil {
			contextLogger.Error().Msgf("failed to stringify original content: %s", err)
			cont = string(fileContent)
		}
	}
	kind := c.contentKind(resolved)

	directoryDependent := false
	if dd, ok := c.Parsers.(directoryDependentParser); ok && dd.DirectoryDependent() {
		directoryDependent = true
	}

	return ParsedDocument{
		Docs:               out.Documents,
		Kind:               kind,
		Content:            cont,
		IgnoreLines:        out.IgnoreLines,
		CountLines:         bytes.Count(resolved, []byte{'\n'}) + 1,
		ResolvedFiles:      out.ResolvedFiles,
		IsMinified:         isMinified,
		TerraformPlan:      out.TerraformPlan,
		DirectoryDependent: directoryDependent,
	}, nil
}

// ParseLineInfoSection builds a line-info section of content that a
// line-info reparse leaves out, when the parser can.
func (c *Parser) ParseLineInfoSection(filePath string, content []byte, name string) (section interface{}, ok bool) {
	if sp, isSectionParser := c.Parsers.(lineInfoSectionParser); isSectionParser {
		return sp.ParseLineInfoSection(content, filePath, name)
	}
	return nil, false
}

// parseDocuments parses fileContent with the parser, without line markers
// when the parse is marked WithLazyLineInfo and the parser can. The output's
// TerraformPlan reports whether the content parsed as a Terraform plan.
func (c *Parser) parseDocuments(
	ctx context.Context,
	fileContent []byte,
	filePath string,
	openAPIResolveReferences bool,
	maxResolverDepth int,
) (model.ParseOutput, error) {
	if up, ok := c.Parsers.(unannotatedParser); ok && IsLazyLineInfo(ctx) {
		if docs, ok := up.ParseUnannotated(fileContent, filePath); ok {
			return model.ParseOutput{
				Resolved: fileContent, Documents: docs, ResolvedFiles: map[string]model.ResolvedFile{}, TerraformPlan: true,
			}, nil
		}
	}
	if pp, ok := c.Parsers.(planParser); ok {
		return pp.ParsePlan(ctx, fileContent, filePath, openAPIResolveReferences, maxResolverDepth)
	}
	resolved, docs, ignoreLines, resolvedFiles, err := c.Parsers.Parse(
		ctx, fileContent, filePath, openAPIResolveReferences, maxResolverDepth)
	return model.ParseOutput{
		Resolved: resolved, Documents: docs, IgnoreLines: ignoreLines, ResolvedFiles: resolvedFiles,
	}, err
}

// contentKind returns the parser's kind, refined for content when the
// parser can.
func (c *Parser) contentKind(content []byte) model.FileKind {
	if ck, ok := c.Parsers.(contentKindParser); ok {
		if refined, override := ck.KindForContent(content); override {
			return refined
		}
	}
	return c.Parsers.GetKind()
}

func unsupportedDocument() ParsedDocument {
	return ParsedDocument{
		Kind:        "break",
		IgnoreLines: []int{},
	}
}

// SupportedExtensions returns extensions supported by the scanner
func (c *Parser) SupportedExtensions() model.Extensions {
	return c.extensions
}

func contains(types []string, supportedTypes map[string]bool) bool {
	if len(types) == 0 {
		return false
	}
	if types[0] == "" {
		return true
	}

	for _, t := range types {
		if _, ok := supportedTypes[strings.ToLower(t)]; ok {
			return true
		}
	}

	return false
}

func (c *Parser) isValidExtension(ctx context.Context, filePath string) bool {
	if ext := utils.ExtensionFromPath(filePath); ext != "" {
		_, ok := c.extensions[ext]
		return ok
	}
	fsys := c.fsys
	if fsys == nil {
		fsys = vfs.DiskFS{}
	}
	ext, _ := utils.GetExtensionWithFS(ctx, fsys, filePath)
	_, ok := c.extensions[ext]
	return ok
}
