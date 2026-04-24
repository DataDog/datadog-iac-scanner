package kustomize

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func isRemoteKustomizeRef(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return true
	}
	if strings.HasPrefix(s, "git::") || strings.HasPrefix(s, "git@") {
		return true
	}
	if strings.HasPrefix(s, "ssh://") {
		return true
	}
	if strings.HasPrefix(s, "oci://") {
		return true
	}
	// go-getter / GitHub-style refs (e.g. host/repo//path?ref=branch).
	if strings.Contains(s, "//") && strings.Contains(s, ".") && !strings.HasPrefix(s, ".") && !filepath.IsAbs(s) {
		return true
	}
	// .git remotes (https, git@, …)
	if strings.Contains(s, ".git") && (strings.Contains(s, "://") || strings.HasPrefix(s, "git@")) {
		return true
	}
	return false
}

// CollectRemoteRefsFromKustomization lists remote-like refs in a kustomization document.
func CollectRemoteRefsFromKustomization(data []byte) ([]string, error) {
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []string
	add := func(s string) {
		if isRemoteKustomizeRef(s) {
			out = append(out, s)
		}
	}
	for _, key := range []string{"resources", "components", "bases"} {
		v, ok := doc[key]
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
					for _, subk := range []string{"repo", "url", "path"} {
						if s, ok := x[subk].(string); ok {
							add(s)
						}
					}
				}
			}
		}
	}
	for _, key := range []string{"patches", "generators", "transformers", "validators", "patchesJson6902"} {
		v, ok := doc[key]
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
					if s, ok := x["path"].(string); ok {
						add(s)
					}
					if s, ok := x["repo"].(string); ok {
						add(s)
					}
					if s, ok := x["url"].(string); ok {
						add(s)
					}
				}
			}
		}
	}
	if openapi, ok := doc["openapi"].(map[string]interface{}); ok {
		if s, ok := openapi["path"].(string); ok {
			add(s)
		}
		if s, ok := openapi["repo"].(string); ok {
			add(s)
		}
		if s, ok := openapi["url"].(string); ok {
			add(s)
		}
	}
	if charts, ok := doc["helmCharts"].([]interface{}); ok {
		for _, item := range charts {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if s, ok := m["repo"].(string); ok {
				add(s)
			}
		}
	}
	return out, nil
}

// DetectKRMInlineFunctions is true when generators/transformers/validators use inline KRM objects (not executed here).
func DetectKRMInlineFunctions(doc map[string]interface{}) bool {
	for _, key := range []string{"generators", "transformers", "validators"} {
		v, ok := doc[key]
		if !ok {
			continue
		}
		list, ok := v.([]interface{})
		if !ok {
			continue
		}
		for _, item := range list {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if _, hasPath := m["path"]; hasPath {
				continue
			}
			if m["apiVersion"] != nil && m["kind"] != nil {
				return true
			}
		}
	}
	return false
}

// DirTotalSize returns the sum of regular file sizes under root (best-effort).
func DirTotalSize(root string) (int64, error) {
	var n int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			n += info.Size()
		}
		return nil
	})
	return n, err
}
