package helm

import (
	"context"
	"strings"
	"testing"

	helmdetector "github.com/DataDog/datadog-iac-scanner/pkg/detector/helm"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/stretchr/testify/require"
)

// helmFileMetadata is the file the runner stores for a rendered document.
func helmFileMetadata(f *model.ResolvedHelm) *model.FileMetadata {
	return &model.FileMetadata{
		Kind:              model.KindHELM,
		FilePath:          f.FileName,
		HelmID:            f.SplitID,
		OriginalData:      string(f.OriginalData),
		LinesOriginalData: utils.SplitLines(string(f.OriginalData)),
		IDInfo:            f.IDInfo,
		HelmAttribution:   model.NewHelmAttribution(f.HelmInvocations, string(f.Content)),
	}
}

// findingLine renders files and returns the line DetectLine reports for
// searchKey in the document of template that contains doc.
func findingLine(t *testing.T, files map[string]string, template, doc, searchKey string) int {
	t.Helper()
	var found *model.ResolvedHelm
	for _, f := range findAllResolvedBySuffix(t, renderChart(t, files), template) {
		if strings.Contains(string(f.Content), doc) {
			require.Nil(t, found, "several documents of %s contain %q", template, doc)
			found = &f
		}
	}
	require.NotNil(t, found, "no document of %s contains %q", template, doc)
	return (helmdetector.DetectKindLine{}).DetectLine(context.Background(), helmFileMetadata(found), searchKey, 1).Line
}

const (
	headerAndLabelsTpl = "{{- define \"header\" -}}\napiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n{{- end -}}\n" +
		"{{- define \"labels\" -}}\napp: x\n{{- end -}}\n"
	podTpl = "{{- define \"pod\" -}}\napiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n" +
		"  containers:\n  - name: c\n    image: nginx\n{{- end -}}\n"
	svcTpl = "{{- define \"svc\" -}}\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n" +
		"spec:\n  type: NodePort\n{{- end -}}\n"
)

// Every finding line of a rendered chart must be the line that wrote the key,
// or the include that emitted it. A line that is not known stays -1: a wrong
// line is worse than none, and is what a reviewer reports first. Each case is a
// shape where attribution can go wrong; add one for every new shape.
func TestHelmFindingLines(t *testing.T) {
	type key struct {
		searchKey string
		want      int
	}
	tests := []struct {
		name     string
		files    map[string]string
		template string
		doc      string
		keys     []key
	}{
		{
			name: "plain manifest",
			files: map[string]string{
				"templates/pod.yaml": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  hostNetwork: true\n" +
					"  containers:\n  - name: c\n    image: nginx\n",
			},
			template: "templates/pod.yaml", doc: "kind: Pod",
			keys: []key{{"metadata.name", 4}, {"spec.hostNetwork", 6}, {"spec.containers.name={{c}}.image", 9}},
		},
		{
			name: "keys written after a header include are not its output",
			files: map[string]string{
				"templates/_parts.tpl": headerAndLabelsTpl,
				"templates/pod.yaml":   "{{ include \"header\" . }}\nspec:\n  hostNetwork: true\n",
			},
			template: "templates/pod.yaml", doc: "kind: Pod",
			keys: []key{{"metadata.name", 1}, {"spec.hostNetwork", -1}},
		},
		{
			name: "keys written after header and labels includes are not their output",
			files: map[string]string{
				"templates/_parts.tpl": headerAndLabelsTpl,
				"templates/pod.yaml": "{{ include \"header\" . }}\n  labels:\n{{ include \"labels\" . | indent 4 }}\n" +
					"spec:\n  hostNetwork: true\n  containers:\n  - name: c\n    image: nginx\n",
			},
			template: "templates/pod.yaml", doc: "kind: Pod",
			keys: []key{
				{"metadata.name", 1}, {"metadata.labels.app", 3},
				{"spec.hostNetwork", -1}, {"spec.containers.name={{c}}.image", -1},
			},
		},
		{
			name: "keys written after a header include are not its output, then another document",
			files: map[string]string{
				"templates/_parts.tpl": headerAndLabelsTpl,
				"templates/pod.yaml": "{{ include \"header\" . }}\nspec:\n  hostNetwork: false\n---\n" +
					"apiVersion: v1\nkind: Pod\nmetadata:\n  name: q\nspec:\n  hostNetwork: true\n",
			},
			template: "templates/pod.yaml", doc: "name: p",
			keys: []key{{"spec.hostNetwork", -1}},
		},
		{
			name: "document emitted by an include after a literal one",
			files: map[string]string{
				"templates/_pod.tpl": podTpl,
				"values.yaml":        "on: true\n",
				"templates/a.yaml": "{{- if .Values.on }}\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n{{- end }}\n---\n" +
					"{{ include \"pod\" . }}\n",
			},
			template: "templates/a.yaml", doc: "kind: Pod",
			keys: []key{{"metadata.name", 8}, {"spec.containers.name={{c}}.image", 8}},
		},
		{
			name: "document composed of several includes",
			files: map[string]string{
				"templates/_parts.tpl": "{{- define \"header\" -}}\napiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n{{- end -}}\n" +
					"{{- define \"spec\" -}}\nspec:\n  containers:\n  - name: c\n    image: nginx\n{{- end -}}\n",
				"templates/pod.yaml": "{{ include \"header\" . }}\n{{ include \"spec\" . }}\n",
			},
			template: "templates/pod.yaml", doc: "kind: Pod",
			keys: []key{{"metadata.name", 1}, {"spec.containers.name={{c}}.image", 2}},
		},
		{
			name: "include after a block scalar that has ended",
			files: map[string]string{
				"templates/_svc.tpl": svcTpl,
				"templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\ndata:\n  script: |\n" +
					"    echo hi\n  other: x\n{{ include \"svc\" . }}\n",
			},
			template: "templates/cm.yaml", doc: "kind: Service",
			keys: []key{{"spec.type", 9}},
		},
		{
			name: "include after a single-line value",
			files: map[string]string{
				"templates/_svc.tpl": svcTpl,
				"templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\ndata:\n  script: hi\n" +
					"  other: x\n{{ include \"svc\" . }}\n",
			},
			template: "templates/cm.yaml", doc: "kind: Service",
			keys: []key{{"spec.type", 8}},
		},
		{
			name: "labels include inside a document written in the file",
			files: map[string]string{
				"templates/_parts.tpl": headerAndLabelsTpl,
				"templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n  labels:\n" +
					"{{ include \"labels\" . | indent 4 }}\ndata:\n  a: b\n",
			},
			template: "templates/cm.yaml", doc: "kind: ConfigMap",
			keys: []key{{"metadata.name", 4}, {"data.a", 8}},
		},
		{
			name: "include of another template, which has includes of its own",
			files: map[string]string{
				"templates/_spec.tpl": "{{- define \"spec\" -}}\nspec:\n  hostNetwork: true\n{{- end -}}\n",
				"templates/u.yaml":    "apiVersion: v1\nkind: Pod\nmetadata:\n  name: inner\n{{ include \"spec\" . }}\n",
				"templates/t.yaml":    "{{ include (print $.Template.BasePath \"/u.yaml\") . }}\n# a\n# b\n# c\n# d\n# e\n",
			},
			template: "templates/t.yaml", doc: "name: inner",
			keys: []key{{"spec.hostNetwork", 1}, {"metadata.name", 1}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range tt.keys {
				require.Equal(t, k.want, findingLine(t, tt.files, tt.template, tt.doc, k.searchKey), k.searchKey)
			}
		})
	}
}
