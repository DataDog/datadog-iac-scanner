/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/kustomize"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type mockkindDetectLine struct {
}

type mockDefaultDetector struct {
}

func (m mockkindDetectLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string, outputLines int) model.VulnerabilityLines {
	return model.VulnerabilityLines{
		Line: 1,
	}
}

func (m mockDefaultDetector) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string, outputLines int) model.VulnerabilityLines {
	return model.VulnerabilityLines{
		Line: 5,
	}
}

func TestDetector_SetupLogs(t *testing.T) {
	det := initDetector()
	type args struct {
		log zerolog.Logger
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "test_setup_logs",
			args: args{
				log: log.With().
					Str("scanID", "Test").
					Str("fileName", "Test_file_name").
					Str("queryName", "Test_Query_name").
					Logger(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			det.SetupLogs(&tt.args.log)
			got := det.logWithFields
			if !reflect.DeepEqual(*got, tt.args.log) {
				t.Errorf("SetupLogs() = %v, want = %v", got, tt.args.log)
			}
		})
	}
}

func TestDetector_DetectLine(t *testing.T) {
	ctx := context.Background()
	var mock mockkindDetectLine
	var defaultmock mockDefaultDetector
	det := initDetector().Add(mock, model.KindCOMMON)
	det.defaultDetector = defaultmock

	type args struct {
		file      *model.FileMetadata
		searchKey string
	}
	tests := []struct {
		name string
		args args
		want model.VulnerabilityLines
	}{
		{
			name: "test_kind_detect_line",
			args: args{
				file: &model.FileMetadata{
					Kind: model.KindCOMMON,
				},
				searchKey: "",
			},
			want: model.VulnerabilityLines{
				Line: 1,
			},
		},
		{
			name: "test_default_detect_line",
			args: args{
				file: &model.FileMetadata{
					Kind: model.KindTerraform,
				},
				searchKey: "",
			},
			want: model.VulnerabilityLines{
				Line: 5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := det.DetectLine(ctx, tt.args.file, tt.args.searchKey)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DetectLine() = %v, want = %v", got, tt.want)
			}
		})
	}
}

var OriginalData0 = `resource "aws_s3_bucket" "b" {
	bucket = "my-tf-test-bucket"
	acl    = "authenticated-read"
	}`

func initDetector() *DetectLine {
	return NewDetectLine(3)
}

func TestKustomizeDetectLine(t *testing.T) {
	base := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          securityContext:\n            privileged: true\n"
	file := &model.FileMetadata{
		FilePath: "base/deployment.yaml", OriginalData: base, Kind: model.KindKUSTOMIZE,
		Kustomize: &model.KustomizeAttribution{Kind: "Deployment", SourceName: "web", RenderedName: "dev-web",
			RenderedNamespace: "dev"},
	}
	got := KustomizeDetectLine{}.DetectLine(context.Background(), file,
		"metadata.name={{dev-web}}.spec.template.spec.containers.name={{web}}.securityContext.privileged", 3)
	if got.Line != 11 {
		t.Errorf("source line: got %d", got.Line)
	}

	kust := "configMapGenerator:\n  - name: settings\n    literals:\n      - SECRET=canary\n"
	gen := &model.FileMetadata{
		FilePath: "overlays/prod/kustomization.yaml", OriginalData: kust, Kind: model.KindKUSTOMIZE,
		Kustomize: &model.KustomizeAttribution{Kind: "ConfigMap", RenderedName: "settings-abc",
			Generator: &model.KustomizeGenerator{Kind: "ConfigMapGenerator", Name: "settings"}},
	}
	// The snippet is the entry's name alone: the literals line never shows.
	got = KustomizeDetectLine{}.DetectLine(context.Background(), gen, "metadata.name={{settings-abc}}.data.SECRET", 3)
	if got.Line != 2 || got.LineWithVulnerability != "name: settings" || len(*got.VulnLines) != 1 {
		t.Errorf("generator line: %+v", got)
	}

	// A container named like the rendered resource keeps its anchor.
	renamed := &model.FileMetadata{
		FilePath: file.FilePath, OriginalData: strings.Replace(base, "privileged: true", "privileged: false", 1) +
			"        - name: dev-web\n          securityContext:\n            privileged: true\n",
		Kind: model.KindKUSTOMIZE, Kustomize: file.Kustomize,
	}
	got = KustomizeDetectLine{}.DetectLine(context.Background(), renamed,
		"metadata.name={{dev-web}}.spec.template.spec.containers.name={{dev-web}}.securityContext.privileged", 3)
	if got.Line != 14 {
		t.Errorf("container anchor: got %d", got.Line)
	}

	// An entry written on one line is not found: no source text is shown.
	flow := &model.FileMetadata{
		FilePath: gen.FilePath, Kind: model.KindKUSTOMIZE, Kustomize: gen.Kustomize,
		OriginalData: `{"configMapGenerator":[{"name":"settings","literals":["SECRET=canary"]}]}`,
	}
	got = KustomizeDetectLine{}.DetectLine(context.Background(), flow, "metadata.name={{settings-abc}}.data.SECRET", 3)
	if strings.Contains(fmt.Sprintf("%+v", got), "canary") {
		t.Errorf("generator literal leaked: %+v", got)
	}
}

// A same-name Deployment after a Job must not pull the Job's line: spans are
// bounded by the next document and a miss stays inside the mapped document.
func TestKustomizeDetectLineSpanBounded(t *testing.T) {
	base := "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n" +
		"      containers:\n        - name: j\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n" +
		"spec:\n  template:\n    spec:\n      containers:\n        - name: d\n          securityContext:\n" +
		"            privileged: true\n"
	file := &model.FileMetadata{
		FilePath: "base/jobs.yaml", OriginalData: base, Kind: model.KindKUSTOMIZE,
		Kustomize: &model.KustomizeAttribution{Kind: "Deployment", SourceName: "web", RenderedName: "web",
			SourceDocumentIndex: 1},
	}
	got := KustomizeDetectLine{}.DetectLine(context.Background(), file,
		"metadata.name={{web}}.spec.template.spec.containers.name={{d}}.securityContext.privileged", 3)
	if got.Line != 21 {
		t.Errorf("deployment line: got %d, want 21", got.Line)
	}
	// The Job's mapped document does not hold the Deployment containers: the
	// search must not cross into the Deployment.
	job := &model.FileMetadata{
		FilePath: "base/jobs.yaml", OriginalData: base, Kind: model.KindKUSTOMIZE,
		Kustomize: &model.KustomizeAttribution{Kind: "Job", SourceName: "web", RenderedName: "web",
			SourceDocumentIndex: 0},
	}
	got = KustomizeDetectLine{}.DetectLine(context.Background(), job,
		"metadata.name={{web}}.spec.template.spec.containers.name={{d}}.securityContext.privileged", 3)
	if got.Line >= 10 {
		t.Errorf("job document must not report a Deployment line, got %d", got.Line)
	}
}

// A JSON-format JSON 6902 patch is attributed at the op's line.
func TestKustomizeJSON6902JSONFormatLine(t *testing.T) {
	content := "[\n  {\"op\": \"replace\", \"path\": \"/spec/paused\", \"value\": true},\n" +
		"{\"op\": \"add\", \"path\": \"/spec/replicas\", \"value\": 3}\n]"
	if l := jsonOpLine(content, []string{"spec", "replicas"}); l != 3 {
		t.Errorf("json op line: got %d, want 3", l)
	}
	if l := jsonOpLine(content, []string{"spec", "paused"}); l != 2 {
		t.Errorf("json op line: got %d, want 2", l)
	}
}

// A test op asserts a value without writing it: only the mutation's line is
// reported, and a patch of test ops alone owns nothing.
func TestKustomizeJSON6902TestOp(t *testing.T) {
	testOnly := "[{\"op\": \"test\", \"path\": \"/spec/replicas\", \"value\": 3}]"
	if l := jsonOpLine(testOnly, []string{"spec", "replicas"}); l != 0 {
		t.Errorf("test-only patch: got %d, want 0", l)
	}
	afterMutation := "[\n  {\"op\": \"replace\", \"path\": \"/spec/replicas\", \"value\": 3},\n" +
		"  {\"op\": \"test\", \"path\": \"/spec/replicas\", \"value\": 3}\n]"
	if l := jsonOpLine(afterMutation, []string{"spec", "replicas"}); l != 2 {
		t.Errorf("test after mutation: got %d, want 2", l)
	}
}

func TestKustomizeDetectLineWriters(t *testing.T) {
	base := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          image: nginx:1.25\n"
	smp := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          securityContext:\n            privileged: true\n"
	ops := "- op: add\n  path: /spec/template/spec/containers/0/securityContext\n  value: {privileged: true}\n"
	key := "metadata.name={{dev-web}}.spec.template.spec.containers.name={{web}}.securityContext.privileged"
	attr := func(w ...model.KustomizeWriter) *model.FileMetadata {
		return &model.FileMetadata{FilePath: "base/d.yaml", OriginalData: base, Kind: model.KindKUSTOMIZE,
			Kustomize: &model.KustomizeAttribution{Kind: "Deployment", SourceName: "web", RenderedName: "dev-web", Writers: w}}
	}
	cases := []struct {
		name string
		file *model.FileMetadata
		key  string
		want string
		line int
	}{
		{"smp file", attr(model.KustomizeWriter{Kind: model.KustomizeStrategicMerge, File: "p.yaml", Content: smp}), key, "p.yaml", 11},
		{"inline", attr(model.KustomizeWriter{Kind: model.KustomizeStrategicMerge, File: "k.yaml", Content: smp, LineOffset: 10}), key, "k.yaml", 21},
		{"json6902", attr(model.KustomizeWriter{Kind: model.KustomizeJSON6902, File: "o.yaml", Content: ops}), key, "base/d.yaml", 9},
		// An op path without a list index is attributed when its segments
		// match the key's.
		{"json6902 without index", attr(model.KustomizeWriter{Kind: model.KustomizeJSON6902, File: "o.yaml",
			Content: "- op: add\n  path: /spec/template/spec/securityContext\n  value: {seccompProfile: {type: RuntimeDefault}}\n"}),
			"metadata.name={{dev-web}}.spec.template.spec.securityContext", "o.yaml", 2},
		// A list index cannot be proven to select the element the anchor
		// names: two containers may hold it, and patches reorder arrays.
		{"json6902 other index", attr(model.KustomizeWriter{Kind: model.KustomizeJSON6902, File: "o.yaml",
			Content: "- op: replace\n  path: /spec/template/spec/containers/1/securityContext\n  value: {privileged: true}\n"}),
			key, "base/d.yaml", 9},
		{"patch without the field", attr(model.KustomizeWriter{Kind: model.KustomizeStrategicMerge, File: "p.yaml", Content: "kind: Deployment\nmetadata:\n  name: web\n"}),
			"metadata.name={{dev-web}}.spec.template.spec.containers.name={{web}}.image", "base/d.yaml", 10},
		// A key that names only the resource is a missing-field finding: a
		// patch that targets the resource never owns it.
		{"resource anchor only", attr(model.KustomizeWriter{Kind: model.KustomizeStrategicMerge, File: "p.yaml", Content: smp}),
			"metadata.name={{dev-web}}", "base/d.yaml", 4},
		// A key ending at a container anchor is also a missing-field finding:
		// a patch touching that container does not own it.
		{"container anchor only", attr(model.KustomizeWriter{Kind: model.KustomizeStrategicMerge, File: "p.yaml", Content: smp}),
			"metadata.name={{dev-web}}.spec.template.spec.containers.name={{web}}", "base/d.yaml", 9},
		// A patch document naming another namespace does not target the
		// resource.
		{"patch other namespace", attr(model.KustomizeWriter{Kind: model.KustomizeStrategicMerge, File: "p.yaml",
			Content: strings.Replace(smp, "  name: web\n", "  name: web\n  namespace: dev\n", 1)}), key, "base/d.yaml", 9},
		// The same document matches when its namespace is the rendered one.
		{"patch same namespace", func() *model.FileMetadata {
			f := attr(model.KustomizeWriter{Kind: model.KustomizeStrategicMerge, File: "p.yaml",
				Content: strings.Replace(smp, "  name: web\n", "  name: web\n  namespace: dev\n", 1)})
			f.Kustomize.RenderedNamespace = "dev"
			return f
		}(), key, "p.yaml", 12},
		// A document whose own name differs is honored only when the patch
		// entry carried an explicit target.
		{"untargeted patch, other doc name", attr(model.KustomizeWriter{Kind: model.KustomizeStrategicMerge, File: "p.yaml",
			Content: strings.Replace(smp, "name: web", "name: other", 1)}), key, "base/d.yaml", 9},
		{"targeted patch, other doc name", attr(model.KustomizeWriter{Kind: model.KustomizeStrategicMerge, File: "p.yaml",
			Content: strings.Replace(smp, "name: web", "name: other", 1), Targeted: true}), key, "p.yaml", 11},
	}
	for _, c := range cases {
		got := KustomizeDetectLine{}.DetectLine(context.Background(), c.file, c.key, 3)
		if got.ResolvedFile != c.want || got.Line != c.line {
			t.Errorf("%s: got %s:%d", c.name, got.ResolvedFile, got.Line)
		}
	}
}

// A strategic-merge patch file may hold several documents: the line search
// stays inside the document that targets the resource, and a document naming
// another namespace does not target it.
func TestKustomizeSMPPatchDocumentLine(t *testing.T) {
	base := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: c\n          image: nginx:1.25\n"
	patch := "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n" +
		"      containers:\n        - name: c\n          securityContext:\n            privileged: true\n---\n" +
		"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n" +
		"      containers:\n        - name: c\n          securityContext:\n            privileged: true\n"
	files := func(p string) map[string]string {
		return map[string]string{
			"o/kustomization.yaml":    "resources:\n  - ../base\npatches:\n  - path: p.yaml\n",
			"o/p.yaml":                p,
			"base/kustomization.yaml": "resources:\n  - dep.yaml\n  - job.yaml\n",
			"base/dep.yaml":           base,
			"base/job.yaml":           "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: c\n",
		}
	}
	key := "metadata.name={{web}}.spec.template.spec.containers.name={{c}}.securityContext.privileged"
	detect := func(t *testing.T, p string) model.VulnerabilityLines {
		t.Helper()
		res, err := kustomizeRenderForDetector(t, files(p))
		if err != nil {
			t.Fatal(err)
		}
		for i := range res.Documents {
			d := &res.Documents[i]
			if d.Kustomize.Kind != "Deployment" {
				continue
			}
			file := &model.FileMetadata{FilePath: d.FileName, OriginalData: string(d.OriginalData),
				Kind: model.KindKUSTOMIZE, Kustomize: d.Kustomize}
			return KustomizeDetectLine{}.DetectLine(context.Background(), file, key, 3)
		}
		t.Fatal("no deployment rendered")
		return model.VulnerabilityLines{}
	}
	// The Job document comes first and holds the same field: the Deployment
	// document's own line wins.
	got := detect(t, patch)
	if !strings.HasSuffix(got.ResolvedFile, "p.yaml") || got.Line != 23 {
		t.Errorf("selected document: got %s:%d, want p.yaml:23", got.ResolvedFile, got.Line)
	}
}

// A container named like the rendered resource keeps its own anchor in the
// patch search: only the resource's name anchor is rewritten.
func TestKustomizeSMPPatchContainerAnchor(t *testing.T) {
	files := map[string]string{
		"o/kustomization.yaml":    "resources:\n  - ../base\nnamePrefix: dev-\npatches:\n  - path: p.yaml\n",
		"base/kustomization.yaml": "resources:\n  - dep.yaml\n",
		"base/dep.yaml":           "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n        - name: dev-web\n          image: nginx:1.25\n",
		"o/p.yaml":                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: dev-web\n          securityContext:\n            privileged: true\n",
	}
	res, err := kustomizeRenderForDetector(t, files)
	if err != nil {
		t.Fatal(err)
	}
	for i := range res.Documents {
		d := &res.Documents[i]
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		file := &model.FileMetadata{FilePath: d.FileName, OriginalData: string(d.OriginalData),
			Kind: model.KindKUSTOMIZE, Kustomize: d.Kustomize}
		got := KustomizeDetectLine{}.DetectLine(context.Background(), file,
			"metadata.name={{dev-web}}.spec.template.spec.containers.name={{dev-web}}.securityContext.privileged", 3)
		if !strings.HasSuffix(got.ResolvedFile, "p.yaml") || got.Line != 11 {
			t.Errorf("container anchor: got %s:%d, want p.yaml:11", got.ResolvedFile, got.Line)
		}
		return
	}
	t.Fatal("no deployment rendered")
}

// A strategic-merge patch entry with an explicit target is honored even
// when its document's own metadata name differs.
func TestKustomizeSMPPatchExplicitTarget(t *testing.T) {
	files := map[string]string{
		"o/kustomization.yaml":    "resources:\n  - ../base\npatches:\n  - path: p.yaml\n    target:\n      kind: Deployment\n      name: web\n",
		"o/p.yaml":                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: prod-web\nspec:\n  template:\n    spec:\n      containers:\n        - name: c\n          securityContext:\n            privileged: true\n",
		"base/kustomization.yaml": "resources:\n  - dep.yaml\n",
		"base/dep.yaml":           "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: c\n          image: nginx:1.25\n",
	}
	res, err := kustomizeRenderForDetector(t, files)
	if err != nil {
		t.Fatal(err)
	}
	for i := range res.Documents {
		d := &res.Documents[i]
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		file := &model.FileMetadata{FilePath: d.FileName, OriginalData: string(d.OriginalData),
			Kind: model.KindKUSTOMIZE, Kustomize: d.Kustomize}
		got := KustomizeDetectLine{}.DetectLine(context.Background(), file,
			"metadata.name={{web}}.spec.template.spec.containers.name={{c}}.securityContext.privileged", 3)
		if !strings.HasSuffix(got.ResolvedFile, "p.yaml") || got.Line != 11 {
			t.Errorf("explicit target: got %s:%d, want p.yaml:11", got.ResolvedFile, got.Line)
		}
		return
	}
	t.Fatal("no deployment rendered")
}

// A key stopping at an object the patch merely holds, or at a scalar value
// anchor the patch sets, decides between source and patch attribution.
func TestKustomizeSMPTerminalField(t *testing.T) {
	pod := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n" +
		"      containers:\n      - name: first\n        image: old:1\n        securityContext:\n          privileged: true\n" +
		"      - name: second\n        image: old:1\n        securityContext:\n          privileged: false\n"
	patch := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n" +
		"      containers:\n      - name: first\n        securityContext:\n          privileged: true\n"
	kust := "resources: [dep.yaml]\npatches:\n- path: patch.yaml\n"
	prefix := "metadata.name={{web}}.spec.template.spec"
	first := prefix + ".containers.name={{first}}"
	detect := func(t *testing.T, patchContent, key string) model.VulnerabilityLines {
		t.Helper()
		res, err := kustomizeRenderForDetector(t, map[string]string{
			"o/dep.yaml":           pod,
			"o/patch.yaml":         patchContent,
			"o/kustomization.yaml": kust,
		})
		if err != nil {
			t.Fatal(err)
		}
		for i := range res.Documents {
			d := &res.Documents[i]
			if d.Kustomize.Kind != "Deployment" {
				continue
			}
			file := &model.FileMetadata{FilePath: d.FileName, OriginalData: string(d.OriginalData),
				Kind: model.KindKUSTOMIZE, Kustomize: d.Kustomize}
			return KustomizeDetectLine{}.DetectLine(context.Background(), file, key, 3)
		}
		t.Fatal("no deployment rendered")
		return model.VulnerabilityLines{}
	}
	want := func(t *testing.T, got model.VulnerabilityLines, file string, line int) {
		t.Helper()
		if !strings.HasSuffix(filepath.ToSlash(got.ResolvedFile), file) || got.Line != line {
			t.Errorf("got %s:%d, want %s:%d", got.ResolvedFile, got.Line, file, line)
		}
	}
	// A key stopping at an object the patch holds anchors a finding on a
	// field the patch did not set: the source stays the owner.
	want(t, detect(t, patch, first+".securityContext"), "o/dep.yaml", 11)
	want(t, detect(t, patch, prefix), "o/dep.yaml", 7)
	// A scalar value anchor the patch sets is the patch's own finding.
	want(t, detect(t, strings.Replace(patch, "privileged: true",
		"seccompProfile:\n            type: Unconfined", 1),
		first+".securityContext.seccompProfile.type=Unconfined"), "o/patch.yaml", 12)
}

// A patch entry with an explicit target applies whatever namespace its
// document names: the target already selected the resource.
func TestKustomizeSMPPatchTargetNamespace(t *testing.T) {
	files := map[string]string{
		"o/dep.yaml":           "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  namespace: source\nspec:\n  template:\n    spec:\n      containers:\n      - name: first\n        image: old:1\n",
		"o/patch.yaml":         "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: ignored\n  namespace: intermediate\nspec:\n  template:\n    spec:\n      containers:\n      - name: first\n        securityContext:\n          privileged: true\n",
		"o/kustomization.yaml": "resources: [dep.yaml]\nnamespace: final\npatches:\n- path: patch.yaml\n  target:\n    kind: Deployment\n    name: web\n",
	}
	res, err := kustomizeRenderForDetector(t, files)
	if err != nil {
		t.Fatal(err)
	}
	for i := range res.Documents {
		d := &res.Documents[i]
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		file := &model.FileMetadata{FilePath: d.FileName, OriginalData: string(d.OriginalData),
			Kind: model.KindKUSTOMIZE, Kustomize: d.Kustomize}
		got := KustomizeDetectLine{}.DetectLine(context.Background(), file,
			"metadata.name={{web}}.spec.template.spec.containers.name={{first}}.securityContext.privileged", 3)
		if !strings.HasSuffix(filepath.ToSlash(got.ResolvedFile), "o/patch.yaml") || got.Line != 12 {
			t.Errorf("target namespace: got %s:%d, want o/patch.yaml:12", got.ResolvedFile, got.Line)
		}
		return
	}
	t.Fatal("no deployment rendered")
}

// kustomizeRenderForDetector renders one root and returns its documents for
// detector tests.
func kustomizeRenderForDetector(t *testing.T, files map[string]string) (*kustomize.Result, error) {
	t.Helper()
	dir := t.TempDir()
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	for p, c := range files {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			return nil, err
		}
		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			return nil, err
		}
	}
	return kustomize.NewRenderer(vfs.Default(), dir, 5<<20).
		Render(context.Background(), filepath.Join(dir, "o"), nil)
}
