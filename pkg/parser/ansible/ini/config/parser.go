/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package ansibleconfig

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/ansible/ini/comments"
	"github.com/bigkevmcd/go-configparser"
)

// Parser defines a parser type
type Parser struct{}

// Parse parses .cfg/.conf file and returns it as a Document
func (p *Parser) Parse(ctx context.Context, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	// Files in Ansible 'files/' directories are raw host artifacts, not IaC config.
	if isInsideFilesDir(filePath) {
		return fileContent, []model.Document{}, []int{}, nil, nil
	}

	reader := strings.NewReader(string(fileContent))
	configparser.Delimiters("=")
	inline := configparser.InlineCommentPrefixes([]string{";"})

	config, err := configparser.ParseReaderWithOptions(reader, inline)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	doc := make(map[string]interface{})
	doc["groups"] = refactorConfig(config)

	ignoreLines = comments.GetIgnoreLines(strings.Split(string(fileContent), "\n"))

	return fileContent, []model.Document{doc}, ignoreLines, nil, nil
}

// refactorConfig removes all extra information and tries to convert
func refactorConfig(config *configparser.ConfigParser) (doc *model.Document) {
	doc = emptyDocument()
	for _, section := range config.Sections() {
		dict, err := config.Items(section)
		if err != nil {
			continue
		}
		dictRefact := make(map[string]interface{})
		for key, value := range dict {
			if boolValue, err := strconv.ParseBool(value); err == nil {
				dictRefact[key] = boolValue
			} else if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
				dictRefact[key] = floatValue
			} else if strings.Contains(value, ",") {
				elements := strings.Split(value, ",")

				for i := 0; i < len(elements); i++ {
					elements[i] = strings.TrimSpace(elements[i])
				}

				dictRefact[key] = elements
			} else if value == "[]" {
				dictRefact[key] = []string{}
			} else {
				dictRefact[key] = value
			}
		}
		(*doc)[section] = dictRefact
	}

	return doc
}

// SupportedExtensions returns extensions supported by this parser, which are only ini extension
func (p *Parser) SupportedExtensions() []string {
	return []string{".cfg", ".conf"}
}

// SupportedTypes returns types supported by this parser, which is ansible
func (p *Parser) SupportedTypes() map[string]bool {
	return map[string]bool{
		"ansible": true,
	}
}

// GetKind returns CFG constant kind
func (p *Parser) GetKind() model.FileKind {
	return model.KindCFG
}

// GetCommentToken return the comment token of CFG/CONF - #
func (p *Parser) GetCommentToken() string {
	return "#"
}

// StringifyContent converts original content into string formatted version
func (p *Parser) StringifyContent(content []byte) (string, error) {
	return string(content), nil
}

func emptyDocument() *model.Document {
	return &model.Document{}
}

// isInsideFilesDir reports whether filePath has a "files" path component.
// A broad match on "files" is safe here because SupportedTypes() returns only "ansible",
// so only Ansible-typed repos reach this parser.
func isInsideFilesDir(filePath string) bool {
	for _, part := range strings.FieldsFunc(filepath.Clean(filePath), func(r rune) bool {
		if r > unicode.MaxLatin1 {
			return false
		}
		return os.IsPathSeparator(uint8(r))
	}) {
		if part == "files" {
			return true
		}
	}
	return false
}
