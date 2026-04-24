package kustomize

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	zlog "github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// generatorConfigLine returns the best 1-based line for a generator-produced resource in the kustomization file.
func generatorConfigLine(origin *model.KustomizeOrigin, resourceName string) (int, string) {
	if origin == nil || origin.GeneratorConfigFile == "" || resourceName == "" {
		return 1, ""
	}
	p := filepath.Clean(origin.GeneratorConfigFile)
	data, err := os.ReadFile(p)
	if err != nil {
		return 1, p
	}
	lines := strings.Split(string(data), "\n")
	inGen := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inGen {
			if trimmed == "configMapGenerator:" || trimmed == "secretGenerator:" {
				inGen = true
			}
			continue
		}
		// Top-level key ends the generator block unless it starts another generator key.
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if trimmed == "configMapGenerator:" || trimmed == "secretGenerator:" {
				inGen = true
				continue
			}
			inGen = false
			continue
		}
		item := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		if strings.HasPrefix(item, "name:") {
			rest := strings.TrimSpace(strings.TrimPrefix(item, "name:"))
			rest = strings.Trim(rest, `"'`)
			for _, candidate := range generatorNameCandidates(resourceName) {
				if rest == candidate {
					return i + 1, p
				}
			}
		}
	}
	// Fallback: any matching name line in file
	for i, line := range lines {
		for _, candidate := range generatorNameCandidates(resourceName) {
			if strings.Contains(line, "name:") && strings.Contains(line, candidate) {
				return i + 1, p
			}
		}
	}
	return 1, p
}

// transformerConfigLine returns a 1-based line in the kustomization for transformer-related config.
func transformerConfigLine(origin *model.KustomizeOrigin) (int, string) {
	if origin == nil || origin.GeneratorConfigFile == "" {
		return 1, ""
	}
	p := filepath.Clean(origin.GeneratorConfigFile)
	f, err := os.Open(p)
	if err != nil {
		return 1, p
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	keys := []string{"transformers:", "patches:", "patchesStrategicMerge:", "patchesJson6902:"}
	for lineNo := 1; sc.Scan(); lineNo++ {
		t := strings.TrimSpace(sc.Text())
		for _, k := range keys {
			if strings.HasPrefix(t, k) {
				return lineNo, p
			}
		}
	}
	return 1, p
}

// transformerPatchReferenceLine is the 1-based line in the kustomization that cites the patch path.
func transformerPatchReferenceLine(origin *model.KustomizeOrigin) (int, string) {
	if origin == nil || origin.GeneratorConfigFile == "" || len(origin.Transformations) == 0 {
		return 0, ""
	}
	for _, tr := range origin.Transformations {
		kustPath := transformerDeclaredConfigPath(origin, tr)
		kustDir := filepath.Dir(kustPath)
		data, err := os.ReadFile(kustPath)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, candidate := range transformerPatchCandidatePaths(origin, tr) {
			rel, err := filepath.Rel(kustDir, filepath.Clean(candidate))
			if err != nil {
				continue
			}
			rel = filepath.ToSlash(rel)
			variants := []string{rel}
			if !strings.HasPrefix(rel, "./") {
				variants = append(variants, "./"+rel)
			}
			for lineNo, line := range lines {
				t := strings.TrimSpace(line)
				for _, want := range variants {
					if !strings.Contains(t, want) {
						continue
					}
					if strings.Contains(t, "path:") || strings.HasPrefix(t, "-") {
						return lineNo + 1, kustPath
					}
				}
			}
		}
	}
	return 0, ""
}

func transformerLineForOrigin(origin *model.KustomizeOrigin) (int, string) {
	if origin == nil {
		return 1, ""
	}
	if ln, p := transformerPatchReferenceLine(origin); ln > 0 {
		return ln, p
	}
	return transformerConfigLine(origin)
}

func transformerDeclaredConfigPath(origin *model.KustomizeOrigin, tr model.KustomizeTransformation) string {
	if tr.ConfiguredIn != "" {
		return filepath.Clean(tr.ConfiguredIn)
	}
	if origin == nil {
		return ""
	}
	return filepath.Clean(origin.GeneratorConfigFile)
}

func transformerPatchCandidatePaths(origin *model.KustomizeOrigin, tr model.KustomizeTransformation) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(p string) {
		p = filepath.Clean(p)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	kustPath := transformerDeclaredConfigPath(origin, tr)
	kustDir := filepath.Dir(kustPath)
	declared := patchPathsDeclaredInKustomization(kustPath)
	declaredAbs := make(map[string]struct{}, len(declared))
	for _, rel := range declared {
		if kustDir == "" {
			continue
		}
		declaredAbs[filepath.Clean(filepath.Join(kustDir, rel))] = struct{}{}
	}
	if tr.FieldPath != "" && kustDir != "" {
		add(filepath.Join(kustDir, tr.FieldPath))
	}
	if tr.TransformerPath != "" {
		cleanTransformerPath := filepath.Clean(tr.TransformerPath)
		if len(declaredAbs) == 0 {
			if tr.FieldPath != "" || cleanTransformerPath != filepath.Clean(kustDir) {
				add(cleanTransformerPath)
			}
		} else if _, ok := declaredAbs[cleanTransformerPath]; ok {
			add(cleanTransformerPath)
		}
	}
	if len(out) == 0 {
		// Single declared patch only: multiple patches would make this fallback ambiguous.
		if len(declared) == 1 && kustDir != "" {
			add(filepath.Join(kustDir, declared[0]))
		}
	}
	return out
}

func patchPathsDeclaredInKustomization(kustPath string) []string {
	data, err := os.ReadFile(filepath.Clean(kustPath))
	if err != nil {
		return nil
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || strings.Contains(p, "://") {
			return
		}
		out = append(out, p)
	}

	if list, ok := doc["patches"].([]interface{}); ok {
		for _, item := range list {
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
	if list, ok := doc["patchesStrategicMerge"].([]interface{}); ok {
		for _, item := range list {
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
	if list, ok := doc["patchesJson6902"].([]interface{}); ok {
		for _, item := range list {
			if m, ok := item.(map[string]interface{}); ok {
				if p, ok := m["path"].(string); ok {
					add(p)
				}
			}
		}
	}
	return out
}

// transformerPatchFileLine maps a finding into the transformer patch file; returns Line 0 when not mappable.
func transformerPatchFileLine(ctx context.Context, origin *model.KustomizeOrigin, searchKey string, outputLines int) model.VulnerabilityLines {
	if origin == nil || len(origin.Transformations) == 0 || strings.TrimSpace(searchKey) == "" {
		return model.VulnerabilityLines{}
	}
	// Prefer the last transformation in the chain (nearest final state).
	for i := len(origin.Transformations) - 1; i >= 0; i-- {
		tr := origin.Transformations[i]
		for _, p := range transformerPatchCandidatePaths(origin, tr) {
			info, err := os.Stat(p)
			if err != nil {
				zlog.Ctx(ctx).Debug().Err(err).Str("transformer_patch", p).Msg("kustomize transformer patch path not usable")
				continue
			}
			if info.IsDir() {
				continue
			}
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			if ln := astLineForSearchKey(data, searchKey); ln > 0 {
				fileLines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
				if ln <= len(fileLines) {
					t := strings.TrimSpace(strings.TrimRight(fileLines[ln-1], "\r"))
					return model.VulnerabilityLines{
						Line:                  ln,
						VulnLines:             detector.GetAdjacentVulnLines(ln-1, outputLines, fileLines),
						LineWithVulnerability: t,
						ResolvedFile:          p,
						VulnerablilityLocation: model.ResourceLocation{
							Start: model.ResourceLine{Line: ln, Col: 1},
							End:   model.ResourceLine{Line: ln, Col: 1},
						},
					}
				}
			}
		}
	}
	return model.VulnerabilityLines{}
}
