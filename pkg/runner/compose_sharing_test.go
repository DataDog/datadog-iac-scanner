/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	dockerComposeParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/dockercompose"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

// TestShareableParseRejectsDirectoryDependentParses guards the sharing gate
// for directory-dependent parsers (Docker Compose): their output depends on
// sibling .env/override/extends files, so identical content in different
// directories must never share a parse.
func TestShareableParseRejectsDirectoryDependentParses(t *testing.T) {
	require.False(t, shareableParse(&parser.ParsedDocument{
		Content:            "services: {}\n",
		Kind:               model.KindYAML,
		Docs:               []model.Document{{"services": map[string]interface{}{}}},
		DirectoryDependent: true,
	}), "directory-dependent parses must not be shared across files")
}

// TestSinkComposeIdenticalContentIsolated verifies end-to-end that two compose
// files with byte-identical content but different sibling files parse
// independently: the document-sharing cache must not leak one directory's
// override merge into the other's document.
func TestSinkComposeIdenticalContentIsolated(t *testing.T) {
	ctx := context.Background()
	base := []byte("services:\n  web:\n    image: nginx:1.27\n    ports:\n      - 80\n")
	fsys := vfs.NewMemFS(map[string][]byte{
		"a/compose.yaml":          base,
		"a/compose.override.yaml": []byte("services:\n  web:\n    image: nginx:1.28\n"),
		"b/compose.yaml":          base, // identical content, no override sibling
	})
	parsers, err := parser.NewBuilder(ctx).
		WithFS(fsys).
		Add(dockerComposeParser.NewDefaultWithFS(fsys)).
		Build([]string{"dockercompose"}, []string{""})
	require.NoError(t, err)

	svc := &Service{
		Parser:      parsers[0],
		Tracker:     noopTracker{},
		Storage:     nopLineInfoStorage{},
		MaxFileSize: 1 << 20,
		Platforms:   []string{"dockercompose"},
	}
	// Parse both files through the sink in both orders; each file's document
	// must reflect its own directory's siblings.
	for _, order := range [][]string{
		{"a/compose.yaml", "b/compose.yaml"},
		{"b/compose.yaml", "a/compose.yaml"},
	} {
		// The sink holds filesMu while appending; copy out and release before
		// asserting so a failure cannot deadlock the next iteration.
		for _, path := range order {
			content := append([]byte(nil), base...)
			require.NoError(t, svc.sinkContent(ctx, path, "scan1",
				&Content{Content: &content, CountLines: 5}, nil, false, 1))
		}
		svc.filesMu.Lock()
		files := append([]*model.FileMetadata(nil), svc.files...)
		svc.files = nil
		svc.filesMu.Unlock()
		require.Len(t, files, 2)
		for _, f := range files {
			b, err := json.Marshal(f.Document)
			require.NoError(t, err)
			want := `nginx:1.27`
			if f.FilePath == "a/compose.yaml" {
				want = `nginx:1.28`
			}
			require.Containsf(t, string(b), want, "%s must reflect its own override sibling", f.FilePath)
		}
		svc.ClearContentInterner()
		svc.ClearParsedShares()
		svc.ClearTreeCons()
	}
}

type nopLineInfoStorage struct{}

func (nopLineInfoStorage) SaveFile(context.Context, *model.FileMetadata) error { return nil }
func (nopLineInfoStorage) SaveVulnerabilities(context.Context, []model.Vulnerability) error {
	return nil
}
func (nopLineInfoStorage) GetVulnerabilities(context.Context, string) ([]model.Vulnerability, error) {
	return nil, nil
}
