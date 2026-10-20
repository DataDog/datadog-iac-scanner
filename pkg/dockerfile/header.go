package dockerfile

import (
	"io"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/command"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// HasFrom validates candidate syntax with one BuildKit parse. The first
// non-ARG instruction must be FROM; malformed bodies are excluded as well.
// Parsing once avoids reparsing growing prefixes of continued instructions.
func HasFrom(reader io.Reader) bool {
	parsed, err := parser.Parse(reader)
	if err != nil {
		return false
	}
	for _, node := range parsed.AST.Children {
		if strings.EqualFold(node.Value, command.Arg) {
			continue
		}
		return strings.EqualFold(node.Value, command.From) && node.Next != nil
	}
	return false
}
