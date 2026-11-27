/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/occurrence"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/cicd"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/cicd/provider"
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

func TestSinkCICDDeclarationParseIsolation(t *testing.T) {
	content := []byte("on: push\njobs: {build: {steps: [{run: echo literal, env: {CONFIG: ./config.yaml}}]}}\n")
	paths := []string{".github/workflows/a.yml", ".github/workflows/b.yml",
		"a/.gitlab-ci.yml", "b/.gitlab-ci.yaml", "pipeline.yml", ".github/workflows/.gitlab-ci.yml"}
	fsFiles := make(map[string][]byte)
	for _, path := range paths {
		fsFiles[path] = content
	}
	fsFiles[".github/workflows/config.yaml"] = []byte("injected: true\n")
	fsys := vfs.NewMemFS(fsFiles)
	orders := [][]string{paths, {paths[3], paths[2], paths[4], paths[5], paths[1], paths[0]}}
	for _, order := range orders {
		ctx := context.Background()
		counted := &countingCIParser{Parser: &cicd.Parser{}, calls: make(map[string]int)}
		parsers, err := parser.NewBuilder(ctx).WithFS(fsys).Add(counted).Build([]string{"cicd"}, []string{""})
		require.NoError(t, err)
		svc := &Service{Parser: parsers[0], Tracker: noopTracker{}, Storage: nopLineInfoStorage{}, Platforms: []string{"cicd"}}
		pointers := make(map[string]uintptr)
		for _, path := range order {
			data := append([]byte(nil), content...)
			require.NoError(t, svc.sinkContent(ctx, path, "scan", &Content{Content: &data}, nil, false, 1))
		}
		require.Len(t, svc.files, len(paths))
		require.Len(t, svc.parsedShares, 2, "identical bytes share only within their parse contract")
		require.Equal(t, map[string]int{provider.LegacyEnriched: 1, provider.GitLabDeclarations: 1}, counted.calls,
			"duplicates must skip parsing, including GitLab declarations")
		for _, f := range svc.files {
			contract := svc.Parser.Contract(f.FilePath)
			encoded, err := json.Marshal(f.Document)
			require.NoError(t, err)
			if provider.Entrypoint(f.FilePath) == provider.GitLab {
				require.NotContains(t, string(encoded), "_parsed_run")
			} else {
				require.Contains(t, string(encoded), "_parsed_run")
			}
			require.Contains(t, string(encoded), "./config.yaml")
			require.NotContains(t, string(encoded), "injected")
			require.Equal(t, f.FilePath, f.Document["_path"], "cache hits retain the receiving file's path")
			pointer := reflect.ValueOf(f.Document["jobs"]).Pointer()
			if previous, ok := pointers[contract]; ok {
				require.Equal(t, previous, pointer, "cached nested documents must be shared")
			}
			pointers[contract] = pointer
			require.NoError(t, f.UseLineInfoDocument(ctx, func(doc map[string]interface{}) error {
				require.Equal(t, f.FilePath, doc["_path"])
				return nil
			}))
		}
		var rows []model.ResourceOccurrence
		occurrence.Documents(ctx, svc.files, func(f *model.FileMetadata, r *model.ResourceOccurrence) {
			if provider.Entrypoint(f.FilePath) == provider.GitLab {
				require.Equal(t, "gitlab_ci_job", r.ResourceType)
				require.Equal(t, "jobs", r.ResourceName)
			} else {
				require.Equal(t, "github_actions_job", r.ResourceType)
				require.Equal(t, "build", r.ResourceName)
			}
			rows = append(rows, *r)
		})
		require.Len(t, rows, len(paths))
	}
}

// Count actual parses without changing behavior. Lazy line-info reparses happen
// after the cache assertions.
type countingCIParser struct {
	*cicd.Parser
	calls map[string]int
}

func (p *countingCIParser) Parse(ctx context.Context, content []byte, path string, resolve bool, depth int) (
	[]byte, []model.Document, []int, map[string]model.ResolvedFile, error) {
	p.calls[p.ParseContract(path)]++
	return p.Parser.Parse(ctx, content, path, resolve, depth)
}
