package engine

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// TestInspectorSimilarityID pins the full-pipeline simID contract via a
// synthetic Terraform rule in testdata/simid/ so the assertions survive the
// removal of assets/queries/. Three delta scenarios are covered:
//
//   - id-change    → different simID
//   - path-change  → different simID
//   - content-change (same path) → same simID
func TestInspectorSimilarityID(t *testing.T) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: io.Discard})

	ruleID := "synthetic-simid-test-rule"
	altRuleID := "synthetic-simid-test-rule-alt"

	baseDir := "testdata/simid"
	positivePath := baseDir + "/positive.tf"
	altPath := baseDir + "/positive_alt.tf"

	query := synthSimIDQuery(t, ruleID, baseDir)
	queryAlt := synthSimIDQuery(t, altRuleID, baseDir)

	t.Run("id change → different simID", func(t *testing.T) {
		ids1 := inspectSimIDs(t, query, positivePath, nil)
		ids2 := inspectSimIDs(t, queryAlt, positivePath, nil)
		require.NotEmpty(t, ids1)
		requireDisjoint(t, ids1, ids2)
	})

	t.Run("path change → different simID", func(t *testing.T) {
		// positive.tf and positive_alt.tf have the same resource name "synth"
		// so searchKey is identical — only the path differs.
		ids1 := inspectSimIDs(t, query, positivePath, nil)
		ids2 := inspectSimIDs(t, query, altPath, nil)
		require.NotEmpty(t, ids1)
		requireDisjoint(t, ids1, ids2)
	})

	t.Run("content change same path → same simID", func(t *testing.T) {
		altContent, err := os.ReadFile(altPath)
		require.NoError(t, err)
		// Pass positive_alt.tf content but label it as positivePath so the
		// path component of the hash is identical.
		ids1 := inspectSimIDs(t, query, positivePath, nil)
		ids2 := inspectSimIDs(t, query, positivePath, altContent)
		require.NotEmpty(t, ids1)
		require.Equal(t, ids1, ids2)
	})
}

// synthSimIDQuery loads the synthetic query.rego from dir and builds a
// QueryMetadata with the given id.
func synthSimIDQuery(t *testing.T, id, dir string) model.QueryMetadata {
	t.Helper()
	content, err := os.ReadFile(dir + "/query.rego")
	require.NoError(t, err)
	return model.QueryMetadata{
		Query:    id,
		Content:  string(content),
		InputData: "{}",
		Platform: "terraform",
		Metadata: map[string]interface{}{
			"id":        id,
			"legacyId":  id,
			"queryName": "Synthetic SimID Rule",
			"severity":  "HIGH",
			"platform":  "Terraform",
		},
	}
}

// inspectSimIDs runs the inspector with q against filePath and returns the
// SimilarityID of every emitted vulnerability. If content is non-nil it is
// used as the file bytes instead of reading filePath from disk.
func inspectSimIDs(t *testing.T, q model.QueryMetadata, filePath string, content []byte) []string {
	t.Helper()

	if content == nil {
		var err error
		content, err = os.ReadFile(filePath)
		require.NoError(t, err)
	}

	files := parseTerraformBytes(t, filePath, content)

	ins := newTestInspector(t, inspectorOpts{
		queries:             []model.QueryMetadata{q},
		vb:                  DefaultVulnerabilityBuilder,
		kicsComputeNewSimID: true,
		repoPath:            "testdata/simid",
	})

	ctx := context.Background()
	vulns, err := ins.Inspect(ctx, "test", files,
		[]string{"testdata/simid"},
		[]string{"Terraform"},
	)
	require.NoError(t, err)

	ids := make([]string, len(vulns))
	for i, v := range vulns {
		ids[i] = v.SimilarityID
	}
	return ids
}

// parseTerraformBytes parses content as a Terraform file at filePath.
func parseTerraformBytes(t *testing.T, filePath string, content []byte) model.FileMetadatas {
	t.Helper()
	ctx := context.Background()
	parsers, err := parser.NewBuilder(ctx).Add(terraformParser.NewDefault()).Build([]string{""}, []string{""})
	require.NoError(t, err)
	var files model.FileMetadatas
	for _, p := range parsers {
		docs, _ := p.Parse(ctx, filePath, content, true, false, 15)
		if !p.Parsers.SupportedTypes()["terraform"] {
			continue
		}
		for _, doc := range docs.Docs {
			files = append(files, &model.FileMetadata{
				ID:                uuid.NewString(),
				ScanID:            "test",
				Document:          doc,
				LineInfoDocument:  doc,
				OriginalData:      docs.Content,
				Kind:              docs.Kind,
				FilePath:          filePath,
				LinesOriginalData: utils.SplitLines(docs.Content),
				ResolvedFiles:     docs.ResolvedFiles,
			})
		}
	}
	return files
}

// requireDisjoint fails if ids1 and ids2 share any element.
func requireDisjoint(t *testing.T, ids1, ids2 []string) {
	t.Helper()
	set := make(map[string]struct{}, len(ids1))
	for _, id := range ids1 {
		set[id] = struct{}{}
	}
	for _, id := range ids2 {
		if _, ok := set[id]; ok {
			t.Fatalf("expected disjoint simID sets but both contain %q", id)
		}
	}
}
