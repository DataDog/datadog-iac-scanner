package kustomize

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// TransitiveLocalPaths returns local file paths referenced by a kustomization (best-effort for Excluded).
func TransitiveLocalPaths(root string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	addAbs := func(abs string) {
		abs = filepath.Clean(abs)
		if _, ok := seen[abs]; ok {
			return
		}
		seen[abs] = struct{}{}
		out = append(out, abs)
	}
	err := WalkLocalKustomizations(root, func(kustPath string, raw []byte) error {
		addAbs(kustPath)
		kustDir := filepath.Dir(kustPath)
		var doc map[string]interface{}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return err
		}
		add := func(p string) {
			if p == "" || strings.Contains(p, "://") {
				return
			}
			addAbs(filepath.Join(kustDir, filepath.Clean(p)))
		}
		appendDeclaredLocalPathStrings(doc, add)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TransitiveRelativeLocalPaths lists relative local refs from the kustomization graph (no abs paths: keeps inference in-tree).
func TransitiveRelativeLocalPaths(root string) ([]string, error) {
	root = filepath.Clean(root)
	seen := map[string]struct{}{root: {}}
	out := []string{root}
	err := WalkLocalKustomizations(root, func(kustPath string, raw []byte) error {
		kustDir := filepath.Dir(kustPath)
		if _, ok := seen[kustDir]; !ok {
			seen[kustDir] = struct{}{}
			out = append(out, kustDir)
		}
		var doc map[string]interface{}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return err
		}
		add := func(p string) {
			if p == "" || strings.Contains(p, "://") || filepath.IsAbs(p) {
				return
			}
			abs := filepath.Clean(filepath.Join(kustDir, p))
			if _, ok := seen[abs]; ok {
				return
			}
			seen[abs] = struct{}{}
			out = append(out, abs)
		}
		appendDeclaredLocalPathStrings(doc, add)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// appendDeclaredLocalPathStrings calls add for each local path in doc (resources, patches, generators, …).
// Paths are as written in YAML, relative to the kustomization directory.
func appendDeclaredLocalPathStrings(doc map[string]interface{}, add func(string)) {
	stringListKeys := []string{
		"resources", "components", "bases",
		"patchesStrategicMerge", "crds", "configurations",
	}
	for _, k := range stringListKeys {
		v, ok := doc[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case []interface{}:
			for _, item := range t {
				switch x := item.(type) {
				case string:
					add(x)
				case map[string]interface{}:
					if p, ok := x["path"].(string); ok {
						add(p)
					}
				}
			}
		}
	}

	if v, ok := doc["replacements"]; ok {
		collectReplacementFileRefs(v, add)
	}

	for _, k := range []string{"patches", "generators", "transformers", "validators"} {
		v, ok := doc[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case []interface{}:
			for _, item := range t {
				switch x := item.(type) {
				case string:
					add(x)
				case map[string]interface{}:
					if p, ok := x["path"].(string); ok {
						add(p)
					}
				}
			}
		}
	}

	if om, ok := doc["openapi"].(map[string]interface{}); ok {
		if p, ok := om["path"].(string); ok {
			add(p)
		}
	}

	if list, ok := doc["helmCharts"].([]interface{}); ok {
		chartHome := "charts"
		if g, ok := doc["helmGlobals"].(map[string]interface{}); ok {
			if ch, ok := g["chartHome"].(string); ok && ch != "" {
				chartHome = ch
			}
		}
		for _, item := range list {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if name, ok := m["name"].(string); ok && name != "" {
				add(filepath.Join(chartHome, name))
			}
			if vf, ok := m["valuesFile"].(string); ok {
				add(vf)
			}
			if av, ok := m["additionalValuesFiles"].([]interface{}); ok {
				for _, item := range av {
					if s, ok := item.(string); ok {
						add(s)
					}
				}
			}
		}
	}

	if list, ok := doc["patchesJson6902"].([]interface{}); ok {
		for _, item := range list {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if p, ok := m["path"].(string); ok {
				add(p)
			}
		}
	}

	for _, k := range []string{"configMapGenerator", "secretGenerator"} {
		v, ok := doc[k]
		if !ok {
			continue
		}
		if list, ok := v.([]interface{}); ok {
			for _, item := range list {
				m, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				if files, ok := m["files"].([]interface{}); ok {
					for _, f := range files {
						if s, ok := f.(string); ok {
							parts := strings.SplitN(s, "=", 2)
							add(parts[len(parts)-1])
						}
					}
				}
				if envs, ok := m["envs"].([]interface{}); ok {
					for _, f := range envs {
						if s, ok := f.(string); ok {
							add(s)
						}
					}
				}
			}
		}
	}
}

// BuildMetadataStageRelPaths lists repo-relative files to copy into scratch for buildMetadata (full kustom tree + declared locals under repoRoot).
func BuildMetadataStageRelPaths(repoRoot, kustomRoot string) ([]string, error) {
	repoRoot = filepath.Clean(repoRoot)
	kustomRoot = filepath.Clean(kustomRoot)
	set := make(map[string]struct{})
	if err := WalkLocalKustomizations(kustomRoot, func(kustPath string, raw []byte) error {
		kustDir := filepath.Dir(kustPath)
		if err := treeFilesUnderIntoRelSet(repoRoot, kustDir, set); err != nil {
			return err
		}
		var doc map[string]interface{}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return err
		}
		add := func(p string) {
			if p == "" || strings.Contains(p, "://") {
				return
			}
			abs := filepath.Join(kustDir, filepath.Clean(p))
			_ = stageAbsPathFilesIntoRelSet(repoRoot, abs, set)
		}
		appendDeclaredLocalPathStrings(doc, add)
		return nil
	}); err != nil {
		return nil, err
	}

	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out, nil
}

// StageRelPathsForKustomRoot is repo-relative paths to stage one kustom root in scratch (delegates to BuildMetadataStageRelPaths).
func StageRelPathsForKustomRoot(repoRoot, kustomRoot string) ([]string, error) {
	return BuildMetadataStageRelPaths(repoRoot, kustomRoot)
}

// WalkLocalKustomizations walks local bases/components/resources (no remote URLs).
func WalkLocalKustomizations(root string, visit func(kustPath string, raw []byte) error) error {
	root = filepath.Clean(root)
	type item struct {
		dir string
	}
	queue := []item{{dir: root}}
	seen := map[string]struct{}{}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		dir := filepath.Clean(cur.dir)
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}

		kf := kustomizationEntryFile(dir)
		kustPath := filepath.Join(dir, kf)
		raw, err := os.ReadFile(kustPath)
		if err != nil {
			return err
		}
		if err := visit(kustPath, raw); err != nil {
			return err
		}

		var doc map[string]interface{}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return err
		}
		var next []string
		addRef := func(p string) {
			p = strings.TrimSpace(p)
			if p == "" || isRemoteKustomizeRef(p) {
				return
			}
			abs := filepath.Clean(filepath.Join(dir, p))
			if st, err := os.Lstat(abs); err == nil && st.Mode()&fs.ModeSymlink == 0 && st.IsDir() {
				if _, ok := Detect(abs); ok {
					next = append(next, abs)
				}
			}
		}

		for _, key := range []string{"resources", "components", "bases"} {
			v, ok := doc[key]
			if !ok {
				continue
			}
			list, ok := v.([]interface{})
			if !ok {
				continue
			}
			for _, item := range list {
				switch x := item.(type) {
				case string:
					addRef(x)
				case map[string]interface{}:
					if p, ok := x["path"].(string); ok {
						addRef(p)
					}
				}
			}
		}

		for _, dir := range next {
			queue = append(queue, item{dir: dir})
		}
	}
	return nil
}

func treeFilesUnderIntoRelSet(repoRoot, root string, set map[string]struct{}) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return nil
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil
		}
		set[rel] = struct{}{}
		return nil
	})
}

func stageAbsPathFilesIntoRelSet(repoRoot string, abs string, set map[string]struct{}) error {
	abs = filepath.Clean(abs)
	rel, err := filepath.Rel(filepath.Clean(repoRoot), abs)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return nil
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil
	}
	if fi.IsDir() {
		return treeFilesUnderIntoRelSet(repoRoot, abs, set)
	}
	set[rel] = struct{}{}
	return nil
}

// collectReplacementFileRefs feeds add with replacement file paths only (top-level list strings and map `path`; ignores other scalars).
func collectReplacementFileRefs(v interface{}, add func(string)) {
	collectReplacementFileRefsRec(v, add, true)
}

func collectReplacementFileRefsRec(v interface{}, add func(string), topLevel bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		if p, ok := t["path"].(string); ok {
			add(p)
		}
	case []interface{}:
		for _, it := range t {
			switch x := it.(type) {
			case string:
				if topLevel {
					add(x)
				}
			default:
				collectReplacementFileRefsRec(x, add, false)
			}
		}
	}
}
