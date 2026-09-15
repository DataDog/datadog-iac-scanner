/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"crypto/md5"  //nolint:gosec // Terraform filemd5()
	"crypto/sha1" //nolint:gosec // Terraform filesha1()
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

func makeFileFunc(baseDir, rootDir string, fsys vfs.FS, encBase64 bool) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{{Name: "path", Type: cty.String}},
		Type:   function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			src, err := readConfinedFile(baseDir, rootDir, fsys, args[0].AsString())
			if err != nil {
				return cty.NilVal, function.NewArgError(0, err)
			}
			if encBase64 {
				return cty.StringVal(base64.StdEncoding.EncodeToString(src)), nil
			}
			if !utf8.Valid(src) {
				return cty.NilVal, function.NewArgErrorf(0, "contents of %s are not valid UTF-8; use filebase64", args[0].AsString())
			}
			return cty.StringVal(string(src)), nil
		},
	})
}

func makeFileExistsFunc(baseDir, rootDir string, fsys vfs.FS) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{{Name: "path", Type: cty.String}},
		Type:   function.StaticReturnType(cty.Bool),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			full, err := confinePath(baseDir, rootDir, fsys, args[0].AsString())
			if err != nil {
				return cty.NilVal, function.NewArgError(0, err)
			}
			info, err := fsys.Stat(full)
			if err != nil {
				if isNotExist(err) {
					return cty.False, nil
				}
				return cty.NilVal, err
			}
			if !info.Mode().IsRegular() {
				return cty.NilVal, function.NewArgErrorf(0, "%s is not a regular file", args[0].AsString())
			}
			return cty.True, nil
		},
	})
}

func makeFileSetFunc(baseDir, rootDir string, fsys vfs.FS) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "path", Type: cty.String},
			{Name: "pattern", Type: cty.String},
		},
		Type: function.StaticReturnType(cty.Set(cty.String)),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			root, err := confinePath(baseDir, rootDir, fsys, args[0].AsString())
			if err != nil {
				return cty.NilVal, function.NewArgError(0, err)
			}
			pattern := args[1].AsString()
			files, err := walkRegularFiles(fsys, root)
			if err != nil {
				if isNotExist(err) {
					return cty.SetValEmpty(cty.String), nil
				}
				return cty.NilVal, err
			}
			matchers, err := compileGlob(pattern)
			if err != nil {
				return cty.NilVal, function.NewArgError(1, err)
			}
			var matches []cty.Value
			for _, full := range files {
				rel, err := filepath.Rel(root, full)
				if err != nil || !confinedRel(rel) {
					continue
				}
				rel = filepath.ToSlash(rel)
				ok, err := matchCompiledGlob(matchers, rel)
				if err != nil {
					return cty.NilVal, function.NewArgError(1, err)
				}
				if ok {
					matches = append(matches, cty.StringVal(rel))
				}
			}
			if len(matches) == 0 {
				return cty.SetValEmpty(cty.String), nil
			}
			return cty.SetVal(matches), nil
		},
	})
}

func makeFileHashFunc(baseDir, rootDir string, fsys vfs.FS, newHash func() hash.Hash, asBase64 bool) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{{Name: "path", Type: cty.String}},
		Type:   function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			src, err := readConfinedFile(baseDir, rootDir, fsys, args[0].AsString())
			if err != nil {
				return cty.NilVal, function.NewArgError(0, err)
			}
			h := newHash()
			_, _ = h.Write(src)
			sum := h.Sum(nil)
			if asBase64 {
				return cty.StringVal(base64.StdEncoding.EncodeToString(sum)), nil
			}
			return cty.StringVal(hex.EncodeToString(sum)), nil
		},
	})
}

func readConfinedFile(baseDir, rootDir string, fsys vfs.FS, rel string) ([]byte, error) {
	full, err := confinePath(baseDir, rootDir, fsys, rel)
	if err != nil {
		return nil, err
	}
	return fsys.ReadFile(full)
}

// confinePath resolves rel against baseDir and rejects any result that leaves that tree.
func confinePath(baseDir, rootDir string, fsys vfs.FS, rel string) (string, error) {
	base := filepath.Clean(baseDir)
	if base == "" {
		base = "."
	}
	root := filepath.Clean(rootDir)
	if root == "" {
		root = base
	}
	joined := joinUnderRoots(base, root, rel)
	for _, allowed := range []string{base, root} {
		relToRoot, err := filepath.Rel(allowed, joined)
		if err == nil && confinedRel(relToRoot) && verifyResolvedConfined(fsys, allowed, joined) == nil {
			return joined, nil
		}
	}
	return "", fmt.Errorf("path %q is outside the configuration directory", rel)
}

func joinUnderRoots(base, root, rel string) string {
	if filepath.IsAbs(rel) {
		return filepath.Clean(rel)
	}
	cleaned := filepath.Clean(rel)
	for _, allowed := range []string{base, root} {
		if cleaned == allowed || strings.HasPrefix(cleaned, allowed+string(filepath.Separator)) {
			return cleaned
		}
	}
	return filepath.Clean(filepath.Join(base, rel))
}

func verifyResolvedConfined(fsys vfs.FS, root, joined string) error {
	if _, ok := fsys.(*vfs.MemFS); ok {
		return nil
	}
	realRoot := root
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		realRoot = resolved
	}
	candidate := filepath.Clean(joined)
	rootClean := filepath.Clean(root)
	for {
		if resolved, err := filepath.EvalSymlinks(candidate); err == nil {
			rel, err := filepath.Rel(realRoot, resolved)
			if err != nil || !confinedRel(rel) {
				return fmt.Errorf("path %q is outside the configuration directory", joined)
			}
			return nil
		}
		if candidate == rootClean {
			return nil
		}
		relToRoot, err := filepath.Rel(rootClean, candidate)
		if err != nil || !confinedRel(relToRoot) {
			return nil
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return nil
		}
		candidate = parent
	}
}

func confinedRel(rel string) bool {
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

func walkRegularFiles(fsys vfs.FS, root string) ([]string, error) {
	var out []string
	var walk func(string) error
	walk = func(dir string) error {
		entries, err := fsys.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			if e.IsDir() {
				if err := walk(p); err != nil {
					return err
				}
				continue
			}
			if mode := e.Type(); mode != 0 && !mode.IsRegular() {
				continue
			}
			out = append(out, p)
		}
		return nil
	}
	if err := walk(root); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// globMatcher is a single brace-expanded alternative of a fileset pattern,
// precompiled so repeated matches against many files stay cheap.
type globMatcher struct {
	// pattern is set for alternatives handled by path.Match (no double-star).
	pattern string
	// re is set for double-star alternatives, which path.Match cannot express.
	re *regexp.Regexp
}

// compileGlob expands brace alternations once and precompiles matchers, so the
// per-file match step does not redo the expansion or regexp compilation.
func compileGlob(pattern string) ([]globMatcher, error) {
	// The pattern is deliberately NOT passed through filepath.ToSlash: on
	// Windows that would rewrite the glob escape character (backslash) into a
	// path separator, breaking escapes like `\{a}.txt`. Terraform fileset
	// patterns always use `/` as the path separator on every OS, so the
	// pattern is used as-is; only candidate names are normalized to `/` in
	// matchCompiledGlob.
	var matchers []globMatcher
	for _, alt := range expandBraces(pattern) {
		if !strings.Contains(alt, "**") {
			matchers = append(matchers, globMatcher{pattern: alt})
			continue
		}
		re, err := globToRegexp(alt)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, globMatcher{re: re})
	}
	return matchers, nil
}

func matchCompiledGlob(matchers []globMatcher, name string) (bool, error) {
	name = filepath.ToSlash(name)
	for _, m := range matchers {
		if m.re != nil {
			if m.re.MatchString(name) {
				return true, nil
			}
			continue
		}
		ok, err := path.Match(m.pattern, name)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func expandBraces(pattern string) []string {
	start, end, ok := findBraceGroup(pattern)
	if !ok {
		return []string{pattern}
	}
	prefix := pattern[:start]
	suffix := pattern[end+1:]
	var out []string
	for _, alt := range splitBraceAlts(pattern[start+1 : end]) {
		out = append(out, expandBraces(prefix+alt+suffix)...)
	}
	return out
}

// braceScanner tracks pattern context — backslash escapes and [...] classes —
// so brace alternation syntax is only recognized where the glob syntax treats
// it as special.
type braceScanner struct {
	inClass bool
	escaped bool
}

// at returns true if pattern[i] is a literal character, i.e. not an escape
// sequence and not inside a bracket class.
func (s *braceScanner) at(pattern string, i int) bool {
	if s.escaped {
		s.escaped = false
		return false
	}
	c := pattern[i]
	switch {
	case c == '\\':
		s.escaped = true
		return false
	case s.inClass:
		if c == ']' {
			s.inClass = false
		}
		return false
	case c == '[':
		s.inClass = true
		return false
	default:
		return true
	}
}

func findBraceGroup(pattern string) (start, end int, ok bool) {
	var s braceScanner
	depth := 0
	for i := 0; i < len(pattern); i++ {
		if !s.at(pattern, i) {
			continue
		}
		switch pattern[i] {
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 {
				return start, i, true
			}
		}
	}
	return 0, 0, false
}

func splitBraceAlts(inner string) []string {
	var alts []string
	var s braceScanner
	depth, start := 0, 0
	for i := 0; i < len(inner); i++ {
		if !s.at(inner, i) {
			continue
		}
		switch inner[i] {
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				alts = append(alts, inner[start:i])
				start = i + 1
			}
		}
	}
	return append(alts, inner[start:])
}

func globToRegexp(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch {
		case i+1 < len(pattern) && pattern[i] == '*' && pattern[i+1] == '*':
			if doublestarComponent(pattern, i) {
				if i+2 < len(pattern) && pattern[i+2] == '/' {
					b.WriteString("(?:.*/)?")
					i += 2
				} else {
					b.WriteString(".*")
					i++
				}
			} else {
				b.WriteString("[^/]*")
				i++
			}
		case pattern[i] == '*':
			b.WriteString("[^/]*")
		case pattern[i] == '?':
			b.WriteString("[^/]")
		case pattern[i] == '[':
			end := indexGlobClassEnd(pattern[i+1:])
			if end < 0 {
				return nil, path.ErrBadPattern
			}
			appendGlobClass(&b, pattern[i+1:i+1+end])
			i += 1 + end
		case pattern[i] == '\\' && i+1 < len(pattern):
			b.WriteString(regexp.QuoteMeta(string(pattern[i+1])))
			i++
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	b.WriteByte('$')
	return regexp.Compile(b.String())
}

func doublestarComponent(pattern string, i int) bool {
	prevOK := i == 0 || pattern[i-1] == '/'
	nextOK := i+2 == len(pattern) || pattern[i+2] == '/'
	return prevOK && nextOK
}

func indexGlobClassEnd(rest string) int {
	if rest == "" {
		return -1
	}
	start := 0
	if rest[0] == '^' || rest[0] == '!' {
		start = 1
	}
	if start < len(rest) && rest[start] == ']' {
		start++
	}
	for j := start; j < len(rest); j++ {
		if rest[j] == ']' {
			return j
		}
	}
	return -1
}

func appendGlobClass(b *strings.Builder, class string) {
	b.WriteByte('[')
	if strings.HasPrefix(class, "!") || strings.HasPrefix(class, "^") {
		b.WriteByte('^')
		class = class[1:]
	}
	for i := 0; i < len(class); i++ {
		if class[i] == '\\' || class[i] == ']' {
			b.WriteByte('\\')
		}
		b.WriteByte(class[i])
	}
	b.WriteByte(']')
}

func fileHashFuncs(baseDir, rootDir string, fsys vfs.FS) map[string]function.Function {
	return map[string]function.Function{
		"filemd5":          makeFileHashFunc(baseDir, rootDir, fsys, md5.New, false),
		"filesha1":         makeFileHashFunc(baseDir, rootDir, fsys, sha1.New, false),
		"filesha256":       makeFileHashFunc(baseDir, rootDir, fsys, sha256.New, false),
		"filesha512":       makeFileHashFunc(baseDir, rootDir, fsys, sha512.New, false),
		"filebase64sha256": makeFileHashFunc(baseDir, rootDir, fsys, sha256.New, true),
		"filebase64sha512": makeFileHashFunc(baseDir, rootDir, fsys, sha512.New, true),
	}
}
