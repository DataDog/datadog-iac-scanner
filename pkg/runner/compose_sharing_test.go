/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/analyzer"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/occurrence"
	cicdParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/cicd"
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

// TestSinkCICDIdenticalContentAndSharedAliasBomb verifies end-to-end that:
//  1. Byte-identical files with different CI/CD paths (e.g. a GitHub workflow vs
//     a canonical .gitlab-ci.yml) never cross-contaminate via parsedShares.
//  2. A multi-document GitLab CI alias bomb runs through Parse + sinkDocument
//     sanitization in linear time via the shared document sanitizer.
func TestSinkCICDIdenticalContentAndSharedAliasBomb(t *testing.T) {
	ctx := context.Background()
	ambiguous := []byte("on:\n  script:\n    - echo from-on\njobs:\n  script:\n    - echo from-jobs\n")
	fsys := vfs.NewMemFS(map[string][]byte{
		".github/workflows/ci.yml": ambiguous,
		".gitlab-ci.yml":           ambiguous,
	})
	parsers, err := parser.NewBuilder(ctx).
		WithFS(fsys).
		Add(&cicdParser.Parser{FS: fsys}).
		Build([]string{"cicd"}, []string{""})
	require.NoError(t, err)

	svc := &Service{
		Parser:      parsers[0],
		Tracker:     noopTracker{},
		Storage:     nopLineInfoStorage{},
		MaxFileSize: 1 << 20,
		Platforms:   []string{"cicd"},
	}

	for _, order := range [][]string{
		{".github/workflows/ci.yml", ".gitlab-ci.yml"},
		{".gitlab-ci.yml", ".github/workflows/ci.yml"},
	} {
		for _, path := range order {
			content := append([]byte(nil), ambiguous...)
			require.NoError(t, svc.sinkContent(ctx, path, "scan1",
				&Content{Content: &content, CountLines: 6}, nil, true, 15))
		}
		svc.finalizeCompilations(ctx)
		svc.filesMu.Lock()
		files := append([]*model.FileMetadata(nil), svc.files...)
		svc.files = nil
		svc.filesMu.Unlock()
		require.Len(t, files, 2)
		for _, f := range files {
			onJob, ok := f.Document["on"].(map[string]interface{})
			require.True(t, ok)
			if f.FilePath == ".gitlab-ci.yml" {
				require.Contains(t, onJob, "_parsed_script", "canonical .gitlab-ci.yml must run GitLab parsing")
			} else {
				require.NotContains(t, onJob, "_parsed_script", "GitHub workflow must not run GitLab script parsing")
			}
		}
		svc.ClearContentInterner()
		svc.ClearParsedShares()
		svc.ClearTreeCons()
	}

	// 300-document 6-level alias bomb through full sinkContent (parse + sanitize).
	singleBomb := `a0: &a0 ["x", "x", "x", "x", "x", "x"]
a1: &a1 [*a0, *a0, *a0, *a0, *a0, *a0]
a2: &a2 [*a1, *a1, *a1, *a1, *a1, *a1]
a3: &a3 [*a2, *a2, *a2, *a2, *a2, *a2]
a4: &a4 [*a3, *a3, *a3, *a3, *a3, *a3]
a5: &a5 [*a4, *a4, *a4, *a4, *a4, *a4]
job:
  script:
    - echo ok
`
	var multi strings.Builder
	for i := range 300 {
		if i > 0 {
			multi.WriteString("---\n")
		}
		multi.WriteString(singleBomb)
	}
	bombBytes := []byte(multi.String())
	require.NoError(t, svc.sinkContent(ctx, ".gitlab-ci.yml", "scan-bomb",
		&Content{Content: &bombBytes, CountLines: 3000}, nil, true, 15))
	svc.finalizeCompilations(ctx)
	svc.filesMu.Lock()
	bombCount := len(svc.files)
	svc.filesMu.Unlock()
	require.Equal(t, 300, bombCount)
}

func TestSinkGitLabIncludedJobsRetainSource(t *testing.T) {
	ctx := context.Background()
	root := []byte("include: [ci/build.yml]\n")
	source := []byte("spec:\n  inputs: {label: {default: build}}\n---\n# included job\n$[[ inputs.label ]]:\n  # dd-iac-scan ignore-line\n  script: [echo included]\n")
	fsys := vfs.NewMemFS(map[string][]byte{".gitlab-ci.yml": root, "ci/build.yml": source})
	parsers, err := parser.NewBuilder(ctx).WithFS(fsys).Add(&cicdParser.Parser{FS: fsys}).Build([]string{"cicd"}, []string{""})
	require.NoError(t, err)
	svc := &Service{Parser: parsers[0], Tracker: noopTracker{}, Storage: nopLineInfoStorage{}, MaxFileSize: 1 << 20, Platforms: []string{"cicd"}}
	require.NoError(t, svc.sinkContent(ctx, ".gitlab-ci.yml", "scan", &Content{Content: &root, CountLines: 1}, nil, false, 15))
	svc.finalizeCompilations(ctx)
	require.Len(t, svc.files, 1)
	compiled := svc.files[0]
	included, _, found := compiled.FindingSourceAt([]string{"build"})
	require.True(t, found)
	require.Equal(t, "ci/build.yml", filepath.ToSlash(included.FilePath))
	require.Equal(t, string(source), included.OriginalData)
	require.Equal(t, 1, included.SourceDocumentIndex)
	require.Equal(t, "cicd", compiled.Platform)
	require.Contains(t, included.LinesIgnore, 7)
	require.NoError(t, compiled.EnsureLineInfoDocument(ctx))
	require.Equal(t, 5, detector.GetLineBySearchLine([]string{"build"}, compiled))
	var rows []model.ResourceOccurrence
	occurrence.Documents(ctx, svc.files, func(_ *model.FileMetadata, row *model.ResourceOccurrence) { rows = append(rows, *row) })
	require.Len(t, rows, 1)
	require.Equal(t, "ci/build.yml", filepath.ToSlash(rows[0].File))
	require.Equal(t, 5, rows[0].Source.Start.Line)

}

func TestGitLabSourceOwnershipAndRegistration(t *testing.T) {
	for _, layout := range []struct{ extension, directory string }{
		{"yml", ".gitlab/ci"}, {"YML", ".gitlab/ci"}, {"YAML", ".gitlab/ci"},
		{"yml", "ci"}, {"YML", "ci"}, {"YAML", "ci"},
	} {
		extension := layout.extension
		t.Run(layout.directory+"/"+extension, func(t *testing.T) {
			const root = ".gitlab-ci.yml"
			first := layout.directory + "/a." + extension
			second := layout.directory + "/b." + extension
			inputs := map[string][]byte{
				root:   []byte("include: [.gitlab/ci/a.yml, .gitlab/ci/b.yml]\ndefault:\n  before_script:\n    # dd-iac-scan ignore-line\n    - echo global\nbefore_script: [echo setup]\nafter_script: [echo cleanup]\n"),
				first:  []byte("build:\n  script:\n    # dd-iac-scan ignore-line\n    - echo shared\n  # dd-iac-scan ignore-line\n  image: alpine:latest\n  variables:\n    # dd-iac-scan ignore-line\n    MODE: prod\nhelper:\n  script: echo helper\n"),
				second: []byte("build:\n  variables: {ADDED: yes}\n"),
			}
			inputs[root] = []byte(strings.ReplaceAll(strings.ReplaceAll(string(inputs[root]), ".gitlab/ci/a.yml", first), ".gitlab/ci/b.yml", second))
			const literalFilter = `{ $.eventType = "UpdateTrail" }`
			inputs[first] = []byte(strings.ReplaceAll(string(inputs[first]), "    MODE: prod\n", "    MODE: prod\n    FilterPattern: '"+literalFilter+"'\n    filter_pattern: '"+literalFilter+"'\n"))
			namedLines := make(map[string]int)
			for _, name := range []string{"id", "file", "gitlab", "_parsed_before_script", "_parsed_after_script", "_parsed_script", "_dd_lines", "_path", "gitlab_scripts"} {
				namedLines["named-"+name] = strings.Count(string(inputs[first]), "\n") + 3
				inputs[first] = append(inputs[first], []byte(fmt.Sprintf("%s:\n  # dd-iac-scan ignore-line\n  script: [echo %s]\n", name, name))...)
			}
			wantJobs := 2 + len(namedLines)
			// Suppression must follow the outer alias even when the shared command
			// group itself contains a reference. Exercise the complete rule pipeline.
			inputs[first] = append(inputs[first], []byte(".commands: &commands [!reference [build, script]]\n.template: &job {script: *commands}\n")...)
			for index, use := range []string{"  script: *commands", "  script:\n    - *commands", "  <<: *job"} {
				name := fmt.Sprintf("alias%d", index)
				body := fmt.Sprintf("%s:\n%s\n", name, use)
				lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
				lines = append(lines[:len(lines)-1], "  # dd-iac-scan ignore-line", lines[len(lines)-1])
				body = strings.Join(lines, "\n") + "\n"
				namedLines["named-"+name] = strings.Count(string(inputs[first]), "\n") + strings.Count(body, "\n")
				inputs[first] = append(inputs[first], []byte(body)...)
				wantJobs++
			}
			inputs[second] = append(inputs[second], []byte("alias0: {stage: test}\n")...)
			for _, tc := range []struct {
				name        string
				paths       []string
				filter      provider.FileFilter
				wantJobs    int
				wantScript  bool
				wantGlobals bool
			}{
				{"parent-first", []string{root, first, second}, nil, wantJobs, true, true},
				{"nested-layer", []string{root, first, second}, nil, wantJobs, true, true},
				{"partial-wildcard", []string{root, first, second}, nil, wantJobs, true, true},
				{"complete-wildcard", []string{root, first, second}, nil, wantJobs, true, true},
				{"parent-last", []string{second, first, root}, nil, wantJobs, true, true},
				{"ignore-override", []string{root, first, second}, provider.NewPathFilter([]string{second}, nil), wantJobs, true, true},
				{"ignore-source", []string{root, first, second}, provider.NewPathFilter([]string{first}, nil), 2, false, true},
				{"only-paths", []string{root, first, second}, provider.NewPathFilter(nil, []string{root, second}), 2, false, true},
				{"gitignore", []string{root, first, second}, nil, 2, false, true},
				{"gitignore-disabled", []string{root, first, second}, nil, wantJobs, true, true},
				{"standalone", []string{first}, nil, wantJobs, true, false},
				{"whole-ignore-root", []string{root, first, second}, nil, wantJobs, true, false},
				{"whole-ignore-source", []string{root, first, second}, nil, wantJobs, false, true},
			} {
				if tc.name == "standalone" && layout.directory == "ci" {
					continue // Generic filenames are compiled through their parent include.
				}
				for _, protocol := range []string{"legacy", "source"} {
					for _, release := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/%s/release=%t", tc.name, protocol, release), func(t *testing.T) {
							ctx := t.Context()
							caseInputs := make(map[string][]byte, len(inputs))
							for path, content := range inputs {
								caseInputs[path] = content
							}
							switch tc.name {
							case "nested-layer":
								caseInputs[".gitlab/ci/parent.yml"] = []byte(fmt.Sprintf("include: [%s, %s]\n", first, second))
								caseInputs[root] = []byte(strings.ReplaceAll(string(inputs[root]), fmt.Sprintf("[%s, %s]", first, second), "[.gitlab/ci/parent.yml]"))
							case "partial-wildcard", "complete-wildcard":
								caseInputs[root] = []byte(strings.ReplaceAll(string(inputs[root]), fmt.Sprintf("[%s, %s]", first, second), "["+layout.directory+"/*."+extension+"]"))
							case "whole-ignore-root":
								caseInputs[root] = append([]byte("# dd-iac-scan ignore\n"), inputs[root]...)
							case "whole-ignore-source":
								caseInputs[first] = append([]byte("# dd-iac-scan ignore\n"), inputs[first]...)
							}
							fsys := vfs.NewMemFS(caseInputs)
							if tc.name == "complete-wildcard" {
								fsys.MarkDirectoryComplete(layout.directory)
							}
							parsers, err := parser.NewBuilder(ctx).WithFS(fsys).Add(&cicdParser.Parser{FS: fsys}).Build([]string{"cicd"}, []string{""})
							require.NoError(t, err)
							store := storage.NewMemoryStorage()
							service := &Service{Parser: parsers[0], Tracker: noopTracker{}, Storage: store, MaxFileSize: 1 << 20, Platforms: []string{"cicd"}, RenderedFileFilter: tc.filter}
							if strings.HasPrefix(tc.name, "gitignore") {
								repo := t.TempDir()
								require.NoError(t, os.WriteFile(filepath.Join(repo, ".gitignore"), []byte(first+"\n"), 0o600))
								a := &analyzer.Analyzer{RepoPath: repo, Paths: []string{repo}, Types: []string{"cicd"}, GitIgnoreFileName: ".gitignore", ExcludeGitIgnore: tc.name == "gitignore-disabled", MaxFileSize: -1}
								_, err := analyzer.Analyze(ctx, a)
								require.NoError(t, err)
								service.SourceExcluded = func(path string) bool { return a.GitIgnored(filepath.Join(repo, filepath.FromSlash(path))) }
							}
							for _, path := range tc.paths {
								if (tc.filter != nil && tc.filter.ExcludesAny(path)) || (service.SourceExcluded != nil && service.SourceExcluded(path)) {
									continue
								}
								content := append([]byte(nil), caseInputs[path]...)
								require.NoError(t, service.sinkContent(ctx, path, "sources", &Content{Content: &content, CountLines: strings.Count(string(content), "\n")}, nil, false, 15))
							}
							service.finalizeCompilations(ctx)
							if tc.name == "partial-wildcard" {
								require.Contains(t, fsys.MissingFiles(), layout.directory)
							} else {
								require.Empty(t, fsys.MissingFiles())
							}
							stored, err := store.GetFiles(ctx, "sources")
							require.NoError(t, err)
							require.Len(t, stored, len(service.files))
							var rows []model.ResourceOccurrence
							occurrence.Documents(ctx, service.files, func(_ *model.FileMetadata, row *model.ResourceOccurrence) { rows = append(rows, *row) })
							require.Len(t, rows, tc.wantJobs)
							declarations := make(map[string]bool)
							for _, row := range rows {
								identity := fmt.Sprintf("%s:%s:%d", filepath.ToSlash(row.File), row.ResourceName, row.Source.Start.Line)
								require.False(t, declarations[identity], identity)
								declarations[identity] = true
								if tc.filter != nil {
									require.False(t, tc.filter.ExcludesAny(row.File), "inventory must use an in-scope declaration")
								}
							}
							queries := make([]model.QueryMetadata, 0, 6+len(namedLines))
							type queryField struct {
								id         string
								expression string
								key        string
								path       string
							}
							fields := []queryField{
								{"script", "doc.build.script[0]", "build.script.0", `["build","script",0]`},
								{"cross-job", "doc.build.script[0]; _ := doc.helper.script", "build.script.0", `["build","script",0]`},
								{"image", "doc.build.image", "image={{alpine:latest}}", `["build","image"]`},
								{"unwrapped-image", "doc.build.image", "build.image=alpine:latest", `["build","image"]`},
								{"mode", fmt.Sprintf("doc.build.variables.MODE; doc.build.variables.FilterPattern == %q; doc.build.variables.filter_pattern == %q", literalFilter, literalFilter), `build.variables["MODE"]`, `["build","variables","MODE"]`},
								{"global", "doc.default.before_script[0]; _ := envelope.gitlab_scripts.before_script.commands[0]; _ := envelope.gitlab_scripts.after_script.commands[0]", "default.before_script.0", `["default","before_script",0]`},
							}
							if protocol == "legacy" {
								fields = append(fields, queryField{"pathless", "doc.build.script[0]", "", ""})
							}
							for id := range namedLines {
								name := strings.TrimPrefix(id, "named-")
								fields = append(fields, queryField{id, fmt.Sprintf("doc[%q].script[0]", name), name + ".script.0", fmt.Sprintf(`[%q,"script",0]`, name)})
							}
							for _, field := range fields {
								result := fmt.Sprintf(`{"documentId":envelope.id,"searchKey":%q,"resourceType":"gitlab_ci_job","resourceName":%q}`, "gitlab."+field.key, field.id)
								if field.id == "pathless" {
									result = `{"documentId":envelope.id}`
								}
								if protocol == "source" {
									path := `["gitlab",` + strings.TrimPrefix(field.path, "[")
									result = fmt.Sprintf(`{"_dd_id":envelope.id,"path":%s,"resourceType":"gitlab_ci_job","resourceName":%q}`, path, field.id)
								}
								query := fmt.Sprintf("package datadog\nDatadogPolicy contains result if {\n some envelope in input.document\n doc := envelope.gitlab\n _ := %s\n result := %s\n}\n", field.expression, result)
								queries = append(queries, model.QueryMetadata{Query: field.id, Content: query, InputData: "{}", Platform: "cicd", Metadata: map[string]interface{}{"id": field.id, "platform": "CICD"}, Aggregation: 1})
							}
							trk, err := tracker.NewTracker(3)
							require.NoError(t, err)
							inspector, err := engine.NewInspector(ctx, &stubQueriesSource{queries: queries}, engine.DefaultVulnerabilityBuilder, trk, &source.QueryInspectorParameters{}, nil, ".", false, false, 1, featureflags.NewLocalEvaluator(), fsys, false)
							require.NoError(t, err)
							inspector.SetReleaseDocumentsAfterPayload(release)
							inspector.SetReleasePostEvalData(release)
							inspector.SetInventory(inventory.NewCollector("."))
							findings, err := inspector.Inspect(ctx, "sources", service.files, []string{"cicd"})
							require.NoError(t, err)
							require.Empty(t, inspector.GetFailedQueries())
							for _, file := range service.files {
								if release {
									require.Empty(t, file.OriginalData)
									require.Nil(t, file.LinesOriginalData)
									require.Nil(t, file.SourceFiles)
									require.Nil(t, file.LineOverlay)
								} else if file.DocumentDialect == model.GitLabDialect {
									require.NotEmpty(t, file.SourceFiles)
									require.NotNil(t, file.LineOverlay)
								}
							}
							scripts, globals, images, modes, crossJobs := 0, 0, 0, 0, 0
							pathless := 0
							named := make(map[string]int)
							for _, finding := range findings {
								if finding.QueryID == "pathless" {
									pathless++
									require.Equal(t, 1, finding.Line)
									expected := root
									if tc.name == "standalone" {
										expected = first
									}
									require.Equal(t, expected, filepath.ToSlash(finding.FileName))
									continue
								}
								require.True(t, finding.IsSuppressed, "the declaring source's directive must apply: %+v", finding)
								if finding.QueryID != "global" {
									require.Len(t, finding.ResourceOccurrences, 1, "both protocols must link the concrete job, including relative selectors")
								}
								switch finding.QueryID {
								case "script":
									scripts++
									require.Equal(t, first, filepath.ToSlash(finding.FileName))
									require.Equal(t, 4, finding.Line)
								case "cross-job":
									crossJobs++
									require.Equal(t, first, filepath.ToSlash(finding.FileName))
									require.Equal(t, 4, finding.Line)
								case "image", "unwrapped-image":
									images++
									require.Equal(t, first, filepath.ToSlash(finding.FileName))
									require.Equal(t, 6, finding.Line)
								case "mode":
									modes++
									require.Equal(t, first, filepath.ToSlash(finding.FileName))
									require.Equal(t, 9, finding.Line)
								default:
									require.Contains(t, namedLines, finding.QueryID)
									named[finding.QueryID]++
									require.Equal(t, first, filepath.ToSlash(finding.FileName))
									require.Equal(t, namedLines[finding.QueryID], finding.Line)
								case "global":
									globals++
									require.Equal(t, root, filepath.ToSlash(finding.FileName))
									require.Equal(t, 5, finding.Line)
								}
							}
							for id := range namedLines {
								if tc.wantScript {
									require.Equal(t, 1, named[id], id)
								} else {
									require.Zero(t, named[id], id)
								}
							}
							wantPathless := protocol == "legacy" && tc.name != "whole-ignore-root"
							if wantPathless {
								require.Equal(t, 1, pathless)
							} else {
								require.Zero(t, pathless)
							}
							if tc.wantScript {
								require.Equal(t, 1, scripts)
								require.Equal(t, 1, crossJobs)
								require.Equal(t, 2, images)
								require.Equal(t, 1, modes)
							} else {
								require.Zero(t, scripts)
								require.Zero(t, crossJobs)
								require.Zero(t, images)
								require.Zero(t, modes)
							}
							if tc.wantGlobals {
								require.Equal(t, 1, globals)
							} else {
								require.Zero(t, globals)
							}
						})
					}
				}
			}
			for _, standalone := range []bool{false, true} {
				for _, complete := range []bool{false, true} {
					t.Run(fmt.Sprintf("failed-default/standalone=%t/complete=%t", standalone, complete), func(t *testing.T) {
						inputs := map[string][]byte{
							".gitlab/ci/a.yml": []byte("spec:\n  inputs:\n    target: {default: .gitlab/ci/missing.yml}\n---\ninclude: ['$[[ inputs.target ]]']\ntemplate: {script: echo template}\n"),
							".gitlab/ci/c.yml": []byte("override_input: {script: echo override}\n"),
							".gitlab-ci.yml":   []byte("include:\n  - local: .gitlab/ci/a.yml\n    inputs: {target: .gitlab/ci/c.yml}\nparent: {script: echo parent}\n"),
						}
						for _, reverse := range []bool{false, true} {
							fsys := vfs.NewMemFS(inputs)
							if complete {
								fsys.MarkDirectoryComplete(".gitlab/ci")
							}
							parsers, err := parser.NewBuilder(t.Context()).WithFS(fsys).Add(&cicdParser.Parser{FS: fsys, RepoRoot: "."}).Build([]string{"cicd"}, []string{""})
							require.NoError(t, err)
							trk, err := tracker.NewTracker(3)
							require.NoError(t, err)
							service := &Service{Parser: parsers[0], Tracker: trk, Storage: nopLineInfoStorage{}, Platforms: []string{"cicd"}}
							order := []string{".gitlab/ci/a.yml"}
							if !standalone {
								order = append(order, ".gitlab-ci.yml", ".gitlab/ci/c.yml")
							}
							if reverse {
								for left, right := 0, len(order)-1; left < right; left, right = left+1, right-1 {
									order[left], order[right] = order[right], order[left]
								}
							}
							for _, path := range order {
								data := append([]byte(nil), inputs[path]...)
								require.NoError(t, service.sinkContent(t.Context(), path, "variants", &Content{Content: &data}, nil, false, 15))
							}
							require.Empty(t, trk.FailedFiles, "diagnostics wait for invocation selection")
							service.finalizeCompilations(t.Context())
							if standalone && complete {
								require.Equal(t, model.ParseFailureInvalidInclude, trk.FailedFiles[".gitlab/ci/a.yml"])
								require.Empty(t, service.files)
							} else if standalone {
								require.Empty(t, trk.FailedFiles)
								require.Contains(t, fsys.MissingFiles(), ".gitlab/ci/missing.yml")
								require.NotEmpty(t, service.files)
							} else {
								require.Empty(t, trk.FailedFiles)
								require.Empty(t, fsys.MissingFiles(), "discarded invocations cannot request unused defaults")
								var jobs []string
								occurrence.Documents(t.Context(), service.files, func(_ *model.FileMetadata, row *model.ResourceOccurrence) { jobs = append(jobs, row.ResourceName) })
								require.ElementsMatch(t, []string{"override_input", "template", "parent"}, jobs)
							}
						}
					})
				}
			}
		})
	}
}

func TestSinkCompiledDocumentsScale(t *testing.T) {
	allocations := func(count int) float64 {
		content := []byte(strings.Repeat("job: {script: [echo ok]}\n---\n", count))
		return testing.AllocsPerRun(3, func() {
			fsys := vfs.NewMemFS(map[string][]byte{".gitlab-ci.yml": content})
			parsers, err := parser.NewBuilder(t.Context()).WithFS(fsys).Add(&cicdParser.Parser{FS: fsys}).Build([]string{"cicd"}, []string{""})
			require.NoError(t, err)
			service := &Service{Parser: parsers[0], Tracker: noopTracker{}, Storage: nopLineInfoStorage{}, Platforms: []string{"cicd"}}
			data := append([]byte(nil), content...)
			require.NoError(t, service.sinkContent(t.Context(), ".gitlab-ci.yml", "scale", &Content{Content: &data}, nil, false, 15))
			service.finalizeCompilations(t.Context())
			require.Len(t, service.files, count)
			var snapshot *model.SourceSnapshot
			var metadata *model.FileMetadata
			for _, file := range service.files {
				for source, sourceMetadata := range file.SourceFiles {
					if snapshot == nil {
						snapshot = source
						metadata = sourceMetadata
					}
					require.Same(t, snapshot, source)
					require.Same(t, metadata, sourceMetadata)
				}
			}
		})
	}
	small, large := allocations(50), allocations(200)
	t.Logf("50 documents: %.0f allocations; 200 documents: %.0f; growth %.2fx", small, large, large/small)
	require.Less(t, large/small, 5.5, "four times the input must not reparse the full stream per document")
}

func TestGitLabCompilationCyclesRetainCoverage(t *testing.T) {
	for _, twoCycles := range []bool{false, true} {
		t.Run(fmt.Sprintf("cycle before downstream/two=%t", twoCycles), func(t *testing.T) {
			bodies := map[string]string{
				".gitlab/ci/a.yml": "leaf: {script: echo leaf}\n",
				".gitlab/ci/b.yml": "include: [.gitlab/ci/c.yml, .gitlab/ci/a.yml]\nsecond: {script: echo second}\n",
				".gitlab/ci/c.yml": "include: [.gitlab/ci/b.yml]\nthird: {script: echo third}\n",
			}
			expected := []string{"leaf", "second", "third"}
			if twoCycles {
				bodies[".gitlab/ci/y.yml"] = "include: [.gitlab/ci/z.yml, .gitlab/ci/b.yml]\nupstream: {script: echo upstream}\n"
				bodies[".gitlab/ci/z.yml"] = "include: [.gitlab/ci/y.yml]\nother: {script: echo other}\n"
				expected = append(expected, "upstream", "other")
			}
			files := make(map[string][]byte, len(bodies))
			for path, body := range bodies {
				files[path] = []byte(body)
			}
			for _, reverse := range []bool{false, true} {
				fsys := vfs.NewMemFS(files)
				order := fsys.Paths()
				if reverse {
					for left, right := 0, len(order)-1; left < right; left, right = left+1, right-1 {
						order[left], order[right] = order[right], order[left]
					}
				}
				parsers, err := parser.NewBuilder(t.Context()).WithFS(fsys).Add(&cicdParser.Parser{FS: fsys, RepoRoot: "."}).Build([]string{"cicd"}, []string{""})
				require.NoError(t, err)
				service := &Service{Parser: parsers[0], Tracker: noopTracker{}, Storage: nopLineInfoStorage{}, Platforms: []string{"cicd"}}
				for _, path := range order {
					data := append([]byte(nil), files[path]...)
					require.NoError(t, service.sinkContent(t.Context(), path, "cycles", &Content{Content: &data}, nil, false, 15))
				}
				service.finalizeCompilations(t.Context())
				require.Len(t, service.files, 1, "cycle leaders must precede downstream compilations")
				var jobs []string
				occurrence.Documents(t.Context(), service.files, func(_ *model.FileMetadata, row *model.ResourceOccurrence) { jobs = append(jobs, row.ResourceName) })
				require.ElementsMatch(t, expected, jobs)
			}
		})
	}
	inputs := map[string][]byte{
		".gitlab/ci/a.yml": []byte("include: [.gitlab/ci/b.yml]\nfirst: {script: echo first}\n"),
		".gitlab/ci/b.yml": []byte("include: [.gitlab/ci/a.yml]\nsecond: {script: echo second}\n"),
	}
	for _, order := range [][]string{{".gitlab/ci/a.yml", ".gitlab/ci/b.yml"}, {".gitlab/ci/b.yml", ".gitlab/ci/a.yml"}} {
		fsys := vfs.NewMemFS(inputs)
		parsers, err := parser.NewBuilder(t.Context()).WithFS(fsys).Add(&cicdParser.Parser{FS: fsys, RepoRoot: "."}).Build([]string{"cicd"}, []string{""})
		require.NoError(t, err)
		service := &Service{Parser: parsers[0], Tracker: noopTracker{}, Storage: nopLineInfoStorage{}, Platforms: []string{"cicd"}}
		for _, path := range order {
			data := append([]byte(nil), inputs[path]...)
			require.NoError(t, service.sinkContent(t.Context(), path, "cycle", &Content{Content: &data}, nil, false, 15))
		}
		service.finalizeCompilations(t.Context())
		var jobs []string
		occurrence.Documents(t.Context(), service.files, func(_ *model.FileMetadata, row *model.ResourceOccurrence) { jobs = append(jobs, row.ResourceName) })
		require.ElementsMatch(t, []string{"first", "second"}, jobs)
	}
	t.Run("input-dependent includes", func(t *testing.T) {
		inputs := map[string][]byte{
			".gitlab/ci/a.yml": []byte("spec:\n  inputs:\n    target: {default: .gitlab/ci/b.yml}\n---\ninclude: ['$[[ inputs.target ]]']\ntemplate: {script: echo template}\n"),
			".gitlab/ci/b.yml": []byte("default_input: {script: echo default}\n"),
			".gitlab/ci/c.yml": []byte("override_input: {script: echo override}\n"),
			".gitlab/ci/z.yml": []byte("include:\n  - local: .gitlab/ci/a.yml\n    inputs: {target: .gitlab/ci/c.yml}\nparent: {script: echo parent}\n"),
		}
		for _, order := range [][]string{
			{".gitlab/ci/a.yml", ".gitlab/ci/b.yml", ".gitlab/ci/c.yml", ".gitlab/ci/z.yml"},
			{".gitlab/ci/z.yml", ".gitlab/ci/c.yml", ".gitlab/ci/b.yml", ".gitlab/ci/a.yml"},
			{".gitlab/ci/a.yml", ".gitlab/ci/z.yml"},
			{".gitlab/ci/z.yml", ".gitlab/ci/a.yml"},
		} {
			fsys := vfs.NewMemFS(inputs)
			parsers, err := parser.NewBuilder(t.Context()).WithFS(fsys).Add(&cicdParser.Parser{FS: fsys, RepoRoot: "."}).Build([]string{"cicd"}, []string{""})
			require.NoError(t, err)
			trk, err := tracker.NewTracker(3)
			require.NoError(t, err)
			service := &Service{Parser: parsers[0], Tracker: trk, Storage: nopLineInfoStorage{}, Platforms: []string{"cicd"}}
			for _, path := range order {
				data := append([]byte(nil), inputs[path]...)
				require.NoError(t, service.sinkContent(t.Context(), path, "variants", &Content{Content: &data}, nil, false, 15))
			}
			service.finalizeCompilations(t.Context())
			var jobs []string
			occurrence.Documents(t.Context(), service.files, func(_ *model.FileMetadata, row *model.ResourceOccurrence) { jobs = append(jobs, row.ResourceName) })
			expected := []string{"override_input", "template", "parent"}
			parsedPaths, foundPaths := make(map[string]bool), make(map[string]bool)
			for path := range trk.BagOfFilesParse {
				parsedPaths[filepath.ToSlash(path)] = true
			}
			for path := range trk.BagOfFilesFound {
				foundPaths[filepath.ToSlash(path)] = true
			}
			if len(order) == 4 {
				expected = append(expected, "default_input")
				require.Contains(t, parsedPaths, ".gitlab/ci/b.yml")
				require.Equal(t, 4, trk.ParsedFiles)
			} else {
				require.NotContains(t, parsedPaths, ".gitlab/ci/b.yml", "discarded default-only sources were not scanned")
				require.NotContains(t, foundPaths, ".gitlab/ci/b.yml")
				require.Equal(t, 3, trk.ParsedFiles)
			}
			require.Contains(t, parsedPaths, ".gitlab/ci/c.yml")
			require.ElementsMatch(t, expected, jobs)
		}
	})
}
