package ruletest

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	positivePrefix = "positive"
	negativePrefix = "negative"
	dirPerm        = 0o700
	filePerm       = 0o600
)

// root is one evaluation: files are written into a fresh directory and the
// ones named in parse are given to the engine.
type root struct {
	files []File
	parse []string
}

// fixtureRoots groups the fixtures whose base name starts with prefix into
// roots: one per top-level fixture file, and one per top-level subdirectory
// holding such fixtures. Every root also gets the top-level files that are not
// fixtures. Roots are ordered by first appearance in files. With legacy, all
// files form one root in which every such fixture is evaluated.
func fixtureRoots(files []File, prefix string, legacy bool) []root {
	if legacy {
		r := root{files: files}
		for _, f := range files {
			if strings.HasPrefix(path.Base(f.Name), prefix) {
				r.parse = append(r.parse, f.Name)
			}
		}
		if len(r.parse) == 0 {
			return nil
		}
		return []root{r}
	}

	var support []File
	for _, f := range files {
		if !strings.Contains(f.Name, "/") && !isFixture(f.Name) {
			support = append(support, f)
		}
	}

	var roots []root
	dirRoots := map[string]int{}
	for _, f := range files {
		if !strings.HasPrefix(path.Base(f.Name), prefix) {
			continue
		}
		dir, _, nested := strings.Cut(f.Name, "/")
		if !nested {
			roots = append(roots, root{files: append(support[:len(support):len(support)], f), parse: []string{f.Name}})
			continue
		}
		idx, ok := dirRoots[dir]
		if !ok {
			idx = len(roots)
			dirRoots[dir] = idx
			r := root{files: support[:len(support):len(support)]}
			for _, g := range files {
				if strings.HasPrefix(g.Name, dir+"/") {
					r.files = append(r.files, g)
				}
			}
			roots = append(roots, r)
		}
		roots[idx].parse = append(roots[idx].parse, f.Name)
	}
	return roots
}

func isFixture(name string) bool {
	base := path.Base(name)
	return strings.HasPrefix(base, positivePrefix) || strings.HasPrefix(base, negativePrefix)
}

// write materializes the root under dir and returns the paths to parse.
func (r root) write(dir string) ([]string, error) {
	for _, f := range r.files {
		dest, err := confinedPath(dir, f.Name)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(dest), dirPerm); err != nil {
			return nil, err
		}
		if err := os.WriteFile(dest, f.Content, filePerm); err != nil {
			return nil, err
		}
	}
	paths := make([]string, len(r.parse))
	for i, name := range r.parse {
		paths[i] = filepath.Join(dir, filepath.FromSlash(name))
	}
	return paths, nil
}

func confinedPath(dir, name string) (string, error) {
	dest := filepath.Join(dir, filepath.FromSlash(name))
	rel, err := filepath.Rel(dir, dest)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(name) {
		return "", fmt.Errorf("test file path %q escapes fixture root", name)
	}
	return dest, nil
}
