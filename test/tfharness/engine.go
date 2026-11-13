/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfharness

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	scanUtils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/google/uuid"
)

// inspect parses every Terraform file under dir and runs the engine over
// them with the probe rules.
func inspect(t *testing.T, dir, rulesDir, librariesPath string, configure func(Inspector)) Run {
	t.Helper()
	files := parseTerraformTree(t, dir)
	ins := newInspector(t, rulesDir, librariesPath, dir)
	if configure != nil {
		configure(ins)
	}
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"Terraform"})
	if err != nil {
		t.Fatal(err)
	}
	failed := ins.GetFailedQueries()
	if len(failed) > 0 {
		t.Fatalf("probe rules failed to evaluate: %v", failed)
	}
	return Run{Vulns: vulns, Findings: normalize(t, dir, vulns)}
}

// newInspector builds an Inspector over the probe rules and the shared
// libraries.
func newInspector(t *testing.T, rulesDir, librariesPath, repoPath string) *engine.Inspector {
	t.Helper()
	ctx := context.Background()
	queriesSource := source.NewFilesystemSource(ctx, []string{rulesDir}, []string{"Terraform"}, nil, librariesPath, false)
	ins, err := engine.NewInspector(ctx, queriesSource, engine.DefaultVulnerabilityBuilder, &tracker.CITracker{},
		&source.QueryInspectorParameters{FlagEvaluator: featureflags.NewLocalEvaluator()}, nil, repoPath, false, false, 4,
		featureflags.NewLocalEvaluator(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	return ins
}

// parseTerraformTree parses every .tf file under dir.
func parseTerraformTree(t *testing.T, dir string) model.FileMetadatas {
	t.Helper()
	var paths []string
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(path, ".tf") || strings.HasSuffix(path, ".tf.json")) {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var out model.FileMetadatas
	for _, path := range paths {
		content, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		_, docs, ignore, resolved, err := terraformParser.NewDefault().Parse(context.Background(), content, path, true, 15)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, doc := range docs {
			out = append(out, &model.FileMetadata{
				ID:                uuid.NewString(),
				ScanID:            "test",
				Document:          doc,
				LineInfoDocument:  doc,
				OriginalData:      string(content),
				Kind:              model.KindTerraform,
				FilePath:          path,
				LinesIgnore:       ignore,
				ResolvedFiles:     resolved,
				LinesOriginalData: scanUtils.SplitLines(string(content)),
			})
		}
	}
	return out
}

// normalize turns the engine's findings into Finding values.
func normalize(t *testing.T, dir string, vulns []model.Vulnerability) []Finding {
	t.Helper()
	out := make([]Finding, 0, len(vulns))
	for i := range vulns {
		v := &vulns[i]
		rel, err := filepath.Rel(dir, v.FileName)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, Finding{
			Rule:         v.QueryID,
			File:         filepath.ToSlash(rel),
			Line:         v.Line,
			ResourceType: v.ResourceType,
			ResourceName: v.ResourceName,
			SearchKey:    v.SearchKey,
			IdentityKey:  v.IdentityKey,
			CallChain:    v.ModuleCallChain,
			ResourceID:   v.ResourceID,
		})
	}
	return out
}
