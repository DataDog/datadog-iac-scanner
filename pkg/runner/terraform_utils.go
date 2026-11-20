package runner

import (
	"bytes"
	"regexp"
)

// terraformResourceHeader matches a resource block header at the start of
// its input; a header is preceded by a word boundary.
var terraformResourceHeader = regexp.MustCompile(`^resource\s+"[^"]+"\s+"[^"]+"\s*\{`)

// GetCountTerraformResources counts the resource block headers of
// fileContent, as the non-overlapping matches of
// \bresource[\s]+"[^"]+"[\s]+"[^"]+"[\s]*\{. Every header starts with the
// literal "resource", so the expression only runs from those positions
// instead of from every byte of the file.
func GetCountTerraformResources(fileContent []byte) int {
	count := 0
	for offset := 0; ; {
		i := bytes.Index(fileContent[offset:], []byte("resource"))
		if i < 0 {
			return count
		}
		i += offset
		offset = i + 1
		if i > 0 && isWordByte(fileContent[i-1]) {
			continue
		}
		if loc := terraformResourceHeader.FindIndex(fileContent[i:]); loc != nil {
			count++
			offset = i + loc[1]
		}
	}
}

// isWordByte reports whether c is a word character of a regexp \b.
func isWordByte(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}
