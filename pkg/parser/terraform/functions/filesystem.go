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

func makeFileFunc(baseDir string, fsys vfs.FS, encBase64 bool) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{{Name: "path", Type: cty.String}},
		Type:   function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			src, err := readConfinedFile(baseDir, fsys, args[0].AsString())
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

func makeFileExistsFunc(baseDir string, fsys vfs.FS) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{{Name: "path", Type: cty.String}},
		Type:   function.StaticReturnType(cty.Bool),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			full, err := confinePath(baseDir, args[0].AsString())
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

func makeFileSetFunc(baseDir string, fsys vfs.FS) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "path", Type: cty.String},
			{Name: "pattern", Type: cty.String},
		},
		Type: function.StaticReturnType(cty.Set(cty.String)),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			root, err := confinePath(baseDir, args[0].AsString())
			if err != nil {
				return cty.NilVal, function.NewArgError(0, err)
			}
			pattern := filepath.ToSlash(args[1].AsString())
			files, err := walkRegularFiles(fsys, root)
			if err != nil {
				if isNotExist(err) {
					return cty.SetValEmpty(cty.String), nil
				}
				return cty.NilVal, err
			}
			var matches []cty.Value
			for _, full := range files {
				rel, err := filepath.Rel(root, full)
				if err != nil || !confinedRel(rel) {
					continue
				}
				rel = filepath.ToSlash(rel)
				ok, err := matchGlob(pattern, rel)
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

func makeFileHashFunc(baseDir string, fsys vfs.FS, newHash func() hash.Hash, asBase64 bool) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{{Name: "path", Type: cty.String}},
		Type:   function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			src, err := readConfinedFile(baseDir, fsys, args[0].AsString())
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

func readConfinedFile(baseDir string, fsys vfs.FS, rel string) ([]byte, error) {
	full, err := confinePath(baseDir, rel)
	if err != nil {
		return nil, err
	}
	return fsys.ReadFile(full)
}

// confinePath resolves rel against baseDir and rejects any result that leaves that tree.
func confinePath(baseDir, rel string) (string, error) {
	root := filepath.Clean(baseDir)
	if root == "" {
		root = "."
	}
	joined := joinUnderRoot(root, rel)
	relToRoot, err := filepath.Rel(root, joined)
	if err != nil || !confinedRel(relToRoot) {
		return "", fmt.Errorf("path %q is outside the configuration directory", rel)
	}
	if err := verifyResolvedConfined(root, joined); err != nil {
		return "", err
	}
	return joined, nil
}

func joinUnderRoot(root, rel string) string {
	if filepath.IsAbs(rel) {
		return filepath.Clean(rel)
	}
	cleaned := filepath.Clean(rel)
	if relToRoot, err := filepath.Rel(root, cleaned); err == nil && confinedRel(relToRoot) {
		if cleaned == root || strings.HasPrefix(cleaned, root+string(filepath.Separator)) {
			return cleaned
		}
	}
	return filepath.Clean(filepath.Join(root, rel))
}

func verifyResolvedConfined(root, joined string) error {
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

func matchGlob(pattern, name string) (bool, error) {
	pattern = filepath.ToSlash(pattern)
	name = filepath.ToSlash(name)
	if !strings.Contains(pattern, "**") {
		return path.Match(pattern, name)
	}
	re, err := globToRegexp(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(name), nil
}

func globToRegexp(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch {
		case i+1 < len(pattern) && pattern[i] == '*' && pattern[i+1] == '*':
			if i+2 < len(pattern) && pattern[i+2] == '/' {
				b.WriteString("(?:.*/)?")
				i += 2
			} else {
				b.WriteString(".*")
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
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	b.WriteByte('$')
	return regexp.Compile(b.String())
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

func fileHashFuncs(baseDir string, fsys vfs.FS) map[string]function.Function {
	return map[string]function.Function{
		"filemd5":          makeFileHashFunc(baseDir, fsys, md5.New, false),
		"filesha1":         makeFileHashFunc(baseDir, fsys, sha1.New, false),
		"filesha256":       makeFileHashFunc(baseDir, fsys, sha256.New, false),
		"filesha512":       makeFileHashFunc(baseDir, fsys, sha512.New, false),
		"filebase64sha256": makeFileHashFunc(baseDir, fsys, sha256.New, true),
		"filebase64sha512": makeFileHashFunc(baseDir, fsys, sha512.New, true),
	}
}
