package dockerfile

import (
	"bufio"
	"bytes"
	"io"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/command"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// HasFrom checks only the header, through the first non-ARG instruction. BuildKit
// decides instruction boundaries, directives and argument syntax. The line hints
// only avoid retrying at comments and ordinary ARG lines; they never classify a
// file themselves. The full parser validates the body later in the scan.
func HasFrom(reader io.Reader) bool {
	scanner := bufio.NewScanner(reader)
	var header bytes.Buffer
	for scanner.Scan() {
		line := scanner.Bytes()
		header.Write(line)
		header.WriteByte('\n')
		hint := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("\xef\xbb\xbf")))
		if len(hint) == 0 || hint[0] == '#' {
			continue
		}
		end := bytes.IndexAny(hint, " \t")
		if end < 0 {
			end = len(hint)
		}
		if bytes.EqualFold(hint[:end], []byte(command.Arg)) {
			continue
		}
		parsed, err := parser.Parse(bytes.NewReader(header.Bytes()))
		if err != nil {
			continue
		}
		// BuildKit accepts incomplete continuations at EOF. Wait for their next
		// physical line instead of prematurely accepting or rejecting this prefix.
		if continuesLine(line, byte(parsed.EscapeToken)) {
			continue
		}
		for _, node := range parsed.AST.Children {
			if strings.EqualFold(node.Value, command.Arg) {
				continue
			}
			return strings.EqualFold(node.Value, command.From) && node.Next != nil
		}
	}
	return false
}

func continuesLine(line []byte, escape byte) bool {
	line = bytes.TrimRight(line, " \t\r")
	n := len(line)
	return n > 0 && line[n-1] == escape && (n == 1 || line[n-2] != escape)
}
