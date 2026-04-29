package kustomize

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func appendRemoteRefsFromResourceItems(v interface{}, add func(string)) {
	t, ok := v.([]interface{})
	if !ok {
		return
	}
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

func appendRemoteRefsFromPatchLikeItems(v interface{}, add func(string)) {
	t, ok := v.([]interface{})
	if !ok {
		return
	}
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

func appendRemoteRefsFromOpenAPI(openapi map[string]interface{}, add func(string)) {
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

// CollectRemoteRefsFromKustomization lists remote-like refs in a kustomization
// document. helmCharts are intentionally excluded; the Helm prepass owns
// chart repos and gracefully handles the inflation-disabled path.
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
		if v, ok := doc[key]; ok {
			appendRemoteRefsFromResourceItems(v, add)
		}
	}
	for _, key := range []string{"patches", "generators", "transformers", "validators", "patchesJson6902"} {
		if v, ok := doc[key]; ok {
			appendRemoteRefsFromPatchLikeItems(v, add)
		}
	}
	if openapi, ok := doc["openapi"].(map[string]interface{}); ok {
		appendRemoteRefsFromOpenAPI(openapi, add)
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
