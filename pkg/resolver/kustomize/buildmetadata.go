package kustomize

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/rootfile"
	"gopkg.in/yaml.v3"
)

const buildMetadataFilePerm = 0o600

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

func ensureBuildMetadataEntries(doc map[string]interface{}) {
	meta, ok := doc["buildMetadata"].([]interface{})
	if !ok || len(meta) == 0 {
		doc["buildMetadata"] = []interface{}{"originAnnotations", "transformerAnnotations"}
		return
	}
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

// ensureBuildMetadataIfNeeded adds originAnnotations / transformerAnnotations when missing; writes only if bytes change.
func ensureBuildMetadataIfNeeded(dir string) error {
	kf := kustomizationEntryFile(dir)
	cleanDir := filepath.Clean(dir)
	p := filepath.Join(cleanDir, kf)
	p = filepath.Clean(p)
	if !isUnderRoot(p, cleanDir) {
		return fmt.Errorf("invalid kustomization path under %q", cleanDir)
	}
	data, err := rootfile.ReadFile(p)
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
	ensureBuildMetadataEntries(doc)
	b, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if bytes.Equal(data, b) {
		return nil
	}
	root, err := os.OpenRoot(cleanDir)
	if err != nil {
		return err
	}
	werr := root.WriteFile(filepath.ToSlash(kf), b, buildMetadataFilePerm)
	cerr := root.Close()
	return errors.Join(werr, cerr)
}
