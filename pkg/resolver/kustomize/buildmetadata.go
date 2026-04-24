package kustomize

import (
	"bytes"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func buildMetadataSupplementsNeeded(data []byte) (bool, error) {
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return false, err
	}
	meta, ok := doc["buildMetadata"].([]interface{})
	if !ok || len(meta) == 0 {
		return true, nil
	}
	has := func(want string) bool {
		for _, m := range meta {
			if s, ok := m.(string); ok && s == want {
				return true
			}
		}
		return false
	}
	return !has("originAnnotations") || !has("transformerAnnotations"), nil
}

// ensureBuildMetadataIfNeeded adds originAnnotations / transformerAnnotations when missing; writes only if bytes change.
func ensureBuildMetadataIfNeeded(dir string) error {
	kf := kustomizationEntryFile(dir)
	p := filepath.Join(dir, kf)
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	need, err := buildMetadataSupplementsNeeded(data)
	if err != nil || !need {
		return err
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	meta, ok := doc["buildMetadata"].([]interface{})
	if !ok || len(meta) == 0 {
		doc["buildMetadata"] = []interface{}{"originAnnotations", "transformerAnnotations"}
	} else {
		has := func(want string) bool {
			for _, m := range meta {
				if s, ok := m.(string); ok && s == want {
					return true
				}
			}
			return false
		}
		if !has("originAnnotations") {
			meta = append(meta, "originAnnotations")
		}
		if !has("transformerAnnotations") {
			meta = append(meta, "transformerAnnotations")
		}
		doc["buildMetadata"] = meta
	}
	b, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if bytes.Equal(data, b) {
		return nil
	}
	return os.WriteFile(p, b, 0o600)
}
