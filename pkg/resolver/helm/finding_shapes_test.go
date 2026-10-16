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

func shapeLines(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

func withLines(head []string, more ...string) []string {
	return append(append([]string{}, head...), more...)
}

const (
	pHdr     = "{{- define \"header\" -}}\napiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n{{- end -}}\n"
	pHdr2    = "{{- define \"header2\" -}}\napiVersion: v1\nkind: Pod\nmetadata:\n  name: p2\n{{- end -}}\n"
	pHdrN    = "{{- define \"hdr\" -}}\napiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ . }}\n{{- end -}}\n"
	pCmHdr   = "{{- define \"cmhdr\" -}}\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n{{- end -}}\n"
	pLabels  = "{{- define \"labels\" -}}\napp: x\n{{- end -}}\n"
	pExtra   = "{{- define \"extra\" -}}\ndnsPolicy: Default\n{{- end -}}\n"
	pCtr     = "{{- define \"ctr\" -}}\nname: c\nimage: nginx\n{{- end -}}\n"
	pCtr2    = "{{- define \"ctr2\" -}}\n- name: c2\n  image: x\n{{- end -}}\n"
	pCtrs    = "{{- define \"ctrs\" -}}\n- name: d\n  image: busybox\n{{- end -}}\n"
	pImg     = "{{- define \"img\" -}}\nimage: nginx\n{{- end -}}\n"
	pFrag    = "{{- define \"frag\" -}}\necho frag\n{{- end -}}\n"
	pEmpty   = "{{- define \"empty\" -}}\n{{- end -}}\n"
	pHostNet = "{{- define \"hostNetwork\" -}}\nhostNetwork: true\n{{- end -}}\n"
	pAppName = "{{- define \"app.name\" -}}\nname: lbl\n{{- end -}}\n"
	pPod     = "{{- define \"pod\" -}}\napiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n" +
		"  containers:\n  - name: c\n    image: nginx\n{{- end -}}\n"
	pSvc = "{{- define \"svc\" -}}\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n" +
		"spec:\n  type: NodePort\n{{- end -}}\n"
	// Headers whose output ends with a line break, included with "-}}".
	pHdrNl    = "{{- define \"hdrnl\" }}\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n{{ end -}}\n"
	pPodHdrNl = "{{- define \"podhdrnl\" -}}\napiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n{{ end -}}\n"
	pSpec     = "{{- define \"spec\" -}}\nspec:\n  hostNetwork: true\n{{- end -}}\n"
	pLblBlock = "{{- define \"lblblock\" -}}\nlabels:\n  app: x\n{{- end -}}\n"
	pPodSpec  = "{{- define \"podspec\" -}}\napiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n{{- end -}}\n"
	pPodNl    = "{{- define \"podnl\" -}}\napiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  hostNetwork: true\n{{ end -}}\n"
	pMulti    = "{{- define \"multi\" -}}\n{{- range list \"a\" \"b\" }}\n---\n" +
		"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ . }}\n{{- end }}\n{{- end -}}\n"
)

var shapeHelpers = pHdr + pHdr2 + pHdrN + pCmHdr + pLabels + pExtra + pCtr + pCtr2 + pCtrs + pImg + pFrag + pEmpty +
	pHostNet + pAppName + pPod + pSvc + pMulti + pHdrNl + pPodHdrNl + pLblBlock + pSpec + pPodSpec + pPodNl

var pCmHead = []string{"apiVersion: v1", "kind: ConfigMap", "metadata:", "  name: cm"}

type shapeKey struct {
	searchKey string
	want      int
}

// shapeTemplates are the templates a shape needs besides t.yaml.
var shapeTemplates = map[string]map[string]string{
	"75 two document separators in a row":       {"templates/x.tpl": podDefine("dbl", "---", "---")},
	"76 flow mapping in an include":             {"templates/x.tpl": podDefine("fx", "spec:", "  securityContext: {privileged: true}", "  hostNetwork: true")},
	"76b block mapping control":                 {"templates/x.tpl": podDefine("fx", "spec:", "  securityContext:", "    privileged: true", "  hostNetwork: true")},
	"77 flow sequence in an include":            {"templates/x.tpl": podDefine("fx", "spec:", "  containers: [{name: c, image: nginx}]", "  hostNetwork: true")},
	"77b block sequence control":                {"templates/x.tpl": podDefine("fx", "spec:", "  containers:", "  - name: c", "    image: nginx", "  hostNetwork: true")},
	"78 multi-line quoted scalar in an include": {"templates/x.tpl": podDefine("fx", "spec:", "  hostname: \"a", "    b\"", "  hostNetwork: true")},
	"74 include of another template, which has includes of its own": {
		"templates/u.yaml": shapeLines("apiVersion: v1", "kind: Pod", "metadata:", "  name: inner", `{{ include "spec" . }}`),
	},
}

// podDefine returns a template defining name as a Pod: the "---" lines among
// lines ahead of it, the other lines after its metadata, and a hostNetwork spec
// when none is given.
func podDefine(name string, lines ...string) string {
	var separators, rest []string
	for _, l := range lines {
		if strings.HasPrefix(l, "---") {
			separators = append(separators, l)
		} else {
			rest = append(rest, l)
		}
	}
	if len(rest) == 0 {
		rest = []string{"spec:", "  hostNetwork: true"}
	}
	body := append(separators, "apiVersion: v1", "kind: Pod", "metadata:", "  name: p")
	body = append(body, rest...)
	return "{{- define \"" + name + "\" -}}\n" + strings.Join(body, "\n") + "\n{{- end -}}\n"
}

// TestHelmFindingLinesOfShapes renders t.yaml with shapeHelpers for each shape
// and checks the line of each search key in the document containing doc: the
// line that wrote the key, or the include that emitted it. A line the scanner
// cannot attribute with certainty is -1, as a wrong line is worse than none.
// Add a shape for every new way attribution can go wrong.
func TestHelmFindingLinesOfShapes(t *testing.T) {
	shapes := []struct {
		name   string
		tmpl   string
		values string
		doc    string
		keys   []shapeKey
	}{
		{"01 header, keys, trailing nindent include", shapeLines(`{{ include "header" . }}`, "spec:", "  hostNetwork: true",
			`  {{- include "extra" . | nindent 2 }}`), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 1}, {"spec.hostNetwork", 3}, {"spec.dnsPolicy", 4}}},
		{"02 header inside if", shapeLines("{{- if true }}", `{{ include "header" . }}`, "spec:", "  hostNetwork: true", "{{- end }}"), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 2}, {"spec.hostNetwork", 4}}},
		{"03 header inside range, doc b", shapeLines(`{{- range list "a" "b" }}`, "---", `{{ include "hdr" . }}`, "spec:", "  hostNetwork: true", "{{- end }}"), "", "name: b",
			[]shapeKey{{"metadata.name", 3}, {"spec.hostNetwork", 5}}},
		{"04 header inside with", shapeLines("{{- with .Values.x }}", `{{ include "header" $ }}`, "spec:", "  hostNetwork: {{ .a }}", "{{- end }}"), "x:\n  a: true\n", "kind: Pod",
			[]shapeKey{{"metadata.name", 2}, {"spec.hostNetwork", 4}}},
		{"05 labels nindent in literal doc", shapeLines(withLines(pCmHead, "  labels:", `    {{- include "labels" . | nindent 4 }}`, "data:", "  a: b")...), "", "kind: ConfigMap",
			[]shapeKey{{"metadata.name", 4}, {"data.a", 8}}},
		{"06 include as list item", shapeLines("apiVersion: v1", "kind: Pod", "metadata:", "  name: p", "spec:", "  containers:",
			`  - {{- include "ctr" . | nindent 4 }}`, "  - name: d", "    image: busybox"), "", "kind: Pod",
			[]shapeKey{{"spec.containers.name={{d}}.image", 9}}},
		{"07 toYaml block then literal key", shapeLines("apiVersion: v1", "kind: Pod", "metadata:", "  name: p", "spec:",
			"  {{- toYaml .Values.spec | nindent 2 }}", "  dnsPolicy: Default"), "spec:\n  hostNetwork: true\n", "kind: Pod",
			[]shapeKey{{"spec.dnsPolicy", 7}, {"metadata.name", 4}}},
		{"08 header include then toYaml then literal", shapeLines(`{{ include "header" . }}`, "spec:",
			"  {{- toYaml .Values.spec | nindent 2 }}", "  dnsPolicy: Default"), "spec:\n  hostNetwork: true\n", "kind: Pod",
			[]shapeKey{{"spec.dnsPolicy", 4}, {"spec.hostNetwork", 3}, {"metadata.name", 1}}},
		{"09 key dup: include label app vs data.app", shapeLines(`{{ include "cmhdr" . }}`, "  labels:", `{{ include "labels" . | indent 4 }}`, "data:", "  app: y"), "", "kind: ConfigMap",
			[]shapeKey{{"metadata.labels.app", 3}, {"data.app", 5}, {"metadata.name", 1}}},
		{"10 key dup: container named like metadata.name", shapeLines(`{{ include "header" . }}`, "spec:", "  containers:", "  - name: p", "    image: x"), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 1}, {"spec.containers.name={{p}}.image", 5}}},
		{"11 second doc started by include", shapeLines(withLines(pCmHead, "data:", "  a: b", "---", `{{ include "header" . }}`, "spec:", "  hostNetwork: true")...), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 8}, {"spec.hostNetwork", 10}}},
		{"11b same, first doc", shapeLines(withLines(pCmHead, "data:", "  a: b", "---", `{{ include "header" . }}`, "spec:", "  hostNetwork: true")...), "", "kind: ConfigMap",
			[]shapeKey{{"data.a", 6}, {"metadata.name", 4}}},
		{"12 second doc by include, same keys as first", shapeLines("apiVersion: v1", "kind: Pod", "metadata:", "  name: q", "spec:", "  hostNetwork: false",
			"---", `{{ include "header" . }}`, "spec:", "  hostNetwork: true"), "", "name: p",
			[]shapeKey{{"metadata.name", 8}, {"spec.hostNetwork", 10}}},
		{"13 multi-doc include then literal keys, doc b", shapeLines(`{{ include "multi" . }}`, "data:", "  k: v"), "", "name: b",
			[]shapeKey{{"metadata.name", 1}, {"data.k", 3}}},
		// data.k is written after the second document, so doc a has no such key: the
		// include writing doc a owns it.
		{"13b multi-doc include, doc a", shapeLines(`{{ include "multi" . }}`, "data:", "  k: v"), "", "name: a",
			[]shapeKey{{"metadata.name", 1}, {"data.k", 1}}},
		{"14 include inside open block scalar", shapeLines(withLines(pCmHead, "data:", "  script: |", "    echo hi", `    {{ include "frag" . }}`, "  other: x")...), "", "kind: ConfigMap",
			[]shapeKey{{"data.script", 6}, {"data.other", 9}}},
		{"15 include in block scalar after blank line", shapeLines(withLines(pCmHead, "data:", "  script: |", "    echo hi", "", `    {{ include "frag" . }}`, "  other: x")...), "", "kind: ConfigMap",
			[]shapeKey{{"data.script", 6}, {"data.other", 10}}},
		{"16 include in block scalar after col-0 if", shapeLines(withLines(pCmHead, "data:", "  script: |", "    echo hi", "{{- if true }}", `    {{ include "frag" . }}`, "{{- end }}", "  other: x")...), "", "kind: ConfigMap",
			[]shapeKey{{"data.script", 6}, {"data.other", 11}}},
		{"17 include after |- closed", shapeLines(withLines(pCmHead, "data:", "  script: |-", "    echo hi", "", "    echo again", `{{ include "svc" . }}`)...), "", "kind: Service",
			[]shapeKey{{"spec.type", 10}, {"metadata.name", 10}}},
		{"18 include after >+ with trailing blanks", shapeLines(withLines(pCmHead, "data:", "  s: >+", "    a", "", `{{ include "svc" . }}`)...), "", "kind: Service",
			[]shapeKey{{"spec.type", 9}}},
		{"19 include after block scalar in sequence item", shapeLines("apiVersion: v1", "kind: Pod", "metadata:", "  name: p", "spec:", "  containers:",
			"  - name: c", "    image: nginx", "    args:", "    - |", "      echo hi", `{{ include "svc" . }}`), "", "kind: Service",
			[]shapeKey{{"spec.type", 12}}},
		{"19b same, pod doc", shapeLines("apiVersion: v1", "kind: Pod", "metadata:", "  name: p", "spec:", "  containers:",
			"  - name: c", "    image: nginx", "    args:", "    - |", "      echo hi", `{{ include "svc" . }}`), "", "kind: Pod",
			[]shapeKey{{"spec.containers.name={{c}}.image", 8}}},
		{"20 include after nested block scalar", shapeLines(withLines(pCmHead, "data:", "  nested:", "    deeper:", "      s: |", "        x", "  other: y", `{{ include "svc" . }}`)...), "", "kind: Service",
			[]shapeKey{{"spec.type", 11}}},
		{"21 include right after ---", shapeLines("---", `{{ include "pod" . }}`), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 2}, {"spec.containers.name={{c}}.image", 2}}},
		{"22 trim include right after literal doc and ---", shapeLines(withLines(pCmHead, "---", `{{- include "pod" . }}`)...), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 6}}},
		{"23 CRLF header + keys", strings.ReplaceAll(shapeLines(`{{ include "header" . }}`, "  labels:", `{{ include "labels" . | indent 4 }}`, "spec:", "  hostNetwork: true"), "\n", "\r\n"), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 1}, {"metadata.labels.app", 3}, {"spec.hostNetwork", 5}}},
		{"23b CRLF literal + include svc", strings.ReplaceAll(shapeLines(withLines(pCmHead, "data:", "  a: b", `{{ include "svc" . }}`)...), "\n", "\r\n"), "", "kind: Service",
			[]shapeKey{{"spec.type", 7}}},
		{"24 --- inside block scalar, literal", shapeLines(withLines(pCmHead, "data:", "  doc: |", "    a", "    ---", "    b", "  other: x")...), "", "kind: ConfigMap",
			[]shapeKey{{"data.other", 10}}},
		{"25 --- inside block scalar after header include", shapeLines(`{{ include "cmhdr" . }}`, "data:", "  doc: |", "    a", "    ---", "    b", "  other: x"), "", "kind: ConfigMap",
			[]shapeKey{{"data.other", 7}, {"metadata.name", 1}}},
		{"26 template comments around include", shapeLines(`{{/* header */}}`, `{{ include "header" . }}`, `{{- /* spec */}}`, "spec:", "  hostNetwork: true"), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 2}, {"spec.hostNetwork", 5}}},
		{"27 template action header", shapeLines(`{{ template "header" . }}`, "spec:", "  hostNetwork: true"), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 1}, {"spec.hostNetwork", 3}}},
		{"28 tpl action header", shapeLines(`{{ tpl .Values.hdr . }}`, "spec:", "  hostNetwork: true"), "hdr: |\n  apiVersion: v1\n  kind: Pod\n  metadata:\n    name: p\n", "kind: Pod",
			[]shapeKey{{"metadata.name", 1}, {"spec.hostNetwork", 3}}},
		{"29 include named like the key", shapeLines(`{{ include "header" . }}`, "spec:", `  {{- include "hostNetwork" . | nindent 2 }}`, "  dnsPolicy: Default"), "", "kind: Pod",
			[]shapeKey{{"spec.hostNetwork", 3}, {"spec.dnsPolicy", 4}, {"metadata.name", 1}}},
		{"30 include 'app.name' before literal metadata.name", shapeLines("apiVersion: v1", "kind: Pod", "metadata:", "  labels:",
			`    {{- include "app.name" . | nindent 4 }}`, "  name: p"), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 6}}},
		{"30b same after header-less include doc", shapeLines(`{{ include "cmhdr" . }}`, "  labels:",
			`    {{- include "app.name" . | nindent 4 }}`, "data:", "  name: z"), "", "kind: ConfigMap",
			[]shapeKey{{"metadata.name", 1}, {"metadata.labels.name", 3}, {"data.name", 5}}},
		{"31 selector prefix c vs c2", shapeLines("apiVersion: v1", "kind: Pod", "metadata:", "  name: p", "spec:", "  containers:",
			`  {{- include "ctr2" . | nindent 2 }}`, "  - name: c", "    image: nginx"), "", "kind: Pod",
			[]shapeKey{{"spec.containers.name={{c}}.image", 9}}},
		{"32 header, literal container, include containers", shapeLines(`{{ include "header" . }}`, "spec:", "  containers:", "  - name: c", "    image: nginx",
			`  {{- include "ctrs" . | nindent 2 }}`), "", "kind: Pod",
			[]shapeKey{{"spec.containers.name={{c}}.image", 5}, {"spec.containers.name={{d}}.image", 6}}},
		{"33 header via if/else", shapeLines("{{- if false }}", `{{ include "header" . }}`, "{{- else }}", `{{ include "header2" . }}`, "{{- end }}", "spec:", "  hostNetwork: true"), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 4}, {"spec.hostNetwork", 7}}},
		{"34 empty include then header", shapeLines(`{{ include "empty" . }}`, `{{ include "header" . }}`, "spec:", "  hostNetwork: true"), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 2}, {"spec.hostNetwork", 4}}},
		{"36 trimmed header include", shapeLines(`{{- include "header" . }}`, "spec:", "  hostNetwork: true"), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 1}, {"spec.hostNetwork", 3}}},
		{"37 inline nindent labels (not standalone)", shapeLines(withLines(pCmHead, `  labels: {{- include "labels" . | nindent 4 }}`, "data:", "  a: b")...), "", "kind: ConfigMap",
			[]shapeKey{{"metadata.labels.app", 5}, {"data.a", 7}}},
		{"38 header include, keys, then doc via include", shapeLines(`{{ include "header" . }}`, "spec:", "  hostNetwork: true", `{{ include "svc" . }}`), "", "kind: Pod",
			[]shapeKey{{"spec.hostNetwork", 3}, {"metadata.name", 1}}},
		{"38b same, svc doc", shapeLines(`{{ include "header" . }}`, "spec:", "  hostNetwork: true", `{{ include "svc" . }}`), "", "kind: Service",
			[]shapeKey{{"spec.type", 4}, {"metadata.name", 4}}},
		{"39 header in if, key in file only in else branch", shapeLines(`{{ include "header" . }}`, "spec:", "{{- if false }}", "  hostNetwork: false", "{{- else }}", "  hostNetwork: true", "{{- end }}"), "", "kind: Pod",
			[]shapeKey{{"spec.hostNetwork", 6}}},
		{"40 header include, key only emitted by later include also present as text in file comment", shapeLines(`{{ include "header" . }}`, "# dnsPolicy is set by extra", "spec:", `  {{- include "extra" . | nindent 2 }}`), "", "kind: Pod",
			[]shapeKey{{"spec.dnsPolicy", 4}}},
		// The keys are absent from the rendered document: spec owns them.
		{"41 header include, missing key", shapeLines(`{{ include "header" . }}`, "spec:", "  hostNetwork: true"), "", "kind: Pod",
			[]shapeKey{{"spec.dnsPolicy", 2}, {"spec.containers", 2}}},
		{"42 include in block scalar in sequence item", shapeLines(withLines(pCmHead, "data:", "  list:", "  - |", "    echo", "{{- if true }}", `    {{ include "frag" . }}`, "{{- end }}")...), "", "kind: ConfigMap",
			[]shapeKey{{"data.list", 6}}},
		{"43 trimmed include ending a line, templated same key elsewhere", shapeLines(`{{ include "hdrnl" . -}}`, "data:", "  name: {{ .Values.cname }}"), "n: other\n", "kind: ConfigMap",
			[]shapeKey{{"metadata.name", 1}, {"data.name", 3}}},
		{"44 trimmed include ending a line, same text at another path", shapeLines(`{{ include "hdrnl" . -}}`, "data:", "  name: cm"), "", "kind: ConfigMap",
			[]shapeKey{{"metadata.name", 1}, {"data.name", 3}}},
		// The "-}}" trims the indentation of labels, so labels is top-level and
		// metadata.labels.name does not exist: the include writing metadata owns it.
		{"45 trimmed include ending a line, same text under keys it emitted", shapeLines(`{{ include "hdrnl" . -}}`, "  labels:", "    name: cm"), "", "kind: ConfigMap",
			[]shapeKey{{"metadata.labels.name", 1}, {"metadata.name", 1}}},
		{"46 unmarked labels include, templated key elsewhere", shapeLines(`{{ include "header" . }}`, `  {{- include "lblblock" . | nindent 2 }}`, "spec:", "  selector:", "    app: {{ .Values.a }}"), "a: other\n", "kind: Pod",
			[]shapeKey{{"metadata.labels.app", 2}, {"spec.selector.app", 5}}},
		{"47 unmarked labels include, same text elsewhere", shapeLines(`{{ include "header" . }}`, `  {{- include "lblblock" . | nindent 2 }}`, "spec:", "  selector:", "    app: x"), "", "kind: Pod",
			[]shapeKey{{"metadata.labels.app", 2}, {"spec.selector.app", 5}}},
		{"48 trimmed header, unmarked labels include, templated key elsewhere", shapeLines(`{{ include "podhdrnl" . -}}`, `  {{- include "lblblock" . | nindent 2 }}`, "spec:", "  selector:", "    app: {{ .Values.a }}"), "a: other\n", "kind: Pod",
			[]shapeKey{{"metadata.labels.app", 2}, {"spec.selector.app", 5}, {"metadata.name", 1}}},
		{"49 empty include in a manifest", shapeLines(withLines(pCmHead, `{{ include "empty" . }}`, "data:", "  a: b")...), "", "kind: ConfigMap",
			[]shapeKey{{"data.a", 7}}},
		// Both branches render the same text, so the writer of hostNetwork is
		// ambiguous: spec owns it.
		{"50 dead else branch with the text the taken branch rendered", shapeLines(`{{ include "header" . }}`, "spec:",
			"  {{- if .Values.custom }}", "  hostNetwork: {{ .Values.hn }}", "  {{- else }}", "  hostNetwork: true", "  {{- end }}"),
			"custom: true\nhn: true\n", "kind: Pod", []shapeKey{{"spec.hostNetwork", 2}}},
		{"51 list item from an unmarked include, a later literal item with the same text", shapeLines(`{{ include "header" . }}`, "spec:",
			"  containers:", `  {{- include "ctr2" . | nindent 2 }}`, "  - name: b", "    image: x"),
			"", "kind: Pod", []shapeKey{{"spec.containers.name={{c2}}.image", 4}, {"spec.containers.name={{b}}.image", 6}}},
		{"52 trimmed include not ending a line, then an unmarked include", shapeLines(`{{ include "header" . -}}`,
			`{{ include "spec" . | nindent 0 }}`, "  dnsPolicy: Default"),
			"", "kind: Pod", []shapeKey{{"spec.dnsPolicy", 3}, {"spec.hostNetwork", 2}, {"metadata.name", 1}}},
		{"53 inline if on a line of text", shapeLines(`{{ include "header" . }}`, "spec:", "  hostNetwork: true{{ if .Values.x }}",
			"  dnsPolicy: {{ .Values.dp }}", "{{- end }}", "  dnsPolicy: Default"), "x: false\n", "kind: Pod",
			[]shapeKey{{"spec.dnsPolicy", 6}, {"spec.hostNetwork", 3}}},
		// dnsPolicy is printed by a value that spans lines, which the template line
		// does not bound: spec owns it.
		{"54 value printing a line break", shapeLines(`{{ include "header" . }}`, "spec:", "  hostname: {{ .Values.h }}",
			"  {{ .Values.k }}: {{ .Values.v }}"), "h: \"x\\n  dnsPolicy: Default\"\nk: a\nv: b\n", "kind: Pod",
			[]shapeKey{{"spec.hostname", 3}, {"spec.dnsPolicy", 2}}},
		// The range repeats the same lines, and which iteration wrote a line is
		// value-dependent: the container named by the selector owns the image.
		{"55 range closed before literal text with the same lines", shapeLines(`{{ include "header" . }}`, "spec:", "  containers:",
			`  {{- range list "a" "b" }}`, "  - name: {{ . }}", "    image: nginx", "  {{- end }}", "  - name: last", "    image: nginx"),
			"", "kind: Pod", []shapeKey{{"spec.containers.name={{last}}.image", 8}, {"spec.containers.name={{a}}.image", 5}}},
		{"56 include whose end line a trimmed include glues to its own output", shapeLines(`{{ include "hdrnl" . }}`,
			`{{- include "spec" . }}`), "", "kind: ConfigMap",
			[]shapeKey{{"metadata.name", 1}, {"spec.hostNetwork", 2}}},
		{"57 raw-string include argument spanning the next line", shapeLines(`{{ include "podspec" (list `+"`"+`a`,
			`  hostNetwork: true`+"`"+`) }}`, "  hostNetwork: true"), "", "kind: Pod",
			[]shapeKey{{"spec.hostNetwork", 3}}},
		{"58 multi-line comment after the first include", shapeLines(`{{ include "podspec" . }}{{/*`, "  hostNetwork: true", "*/}}",
			"  hostNetwork: true"), "", "kind: Pod", []shapeKey{{"spec.hostNetwork", 4}}},
		{"59 right-trimmed value line glued to the next line", shapeLines(`{{ include "podspec" . }}`, "  nodeSelector: {zone: {{ .Values.z -}}",
			"  }"), "z: a\n", "kind: Pod", []shapeKey{{"spec.nodeSelector.zone", 2}}},
		{"60 YAML comment holding the key before it", shapeLines(`{{ include "podspec" . }}`, "  # hostNetwork: true", `  "hostNetwork": true`),
			"", "kind: Pod", []shapeKey{{"spec.hostNetwork", 3}}},
		{"61 nested key of the same name first", shapeLines(`{{ include "podspec" . }}`, "  nodeSelector:", `    hostNetwork: "x"`,
			"  hostNetwork: true"), "", "kind: Pod", []shapeKey{{"spec.hostNetwork", 4}, {"spec.nodeSelector.hostNetwork", 3}}},
		{"62 block scalar holding the key text", shapeLines(`{{ include "podspec" . }}`, "  nodeSelector:", "    note: |",
			"      hostNetwork: true", "  hostNetwork: true"), "", "kind: Pod", []shapeKey{{"spec.hostNetwork", 5}}},
		{"63 text printed right after an include's output", shapeLines(`{{ include "pod" . }}`, `{{- ":latest" }}`), "", "kind: Pod",
			[]shapeKey{{"spec.containers.name={{c}}.image", 1}}},
		{"64 separator printed right after an include's output", shapeLines(withLines(append([]string{`{{ include "podnl" . }}`, `{{- "---" }}`}, pCmHead...),
			"data:", "  a: b")...), "", "kind: Pod", []shapeKey{{"spec.hostNetwork", 1}}},
		{"64b same, the next document", shapeLines(withLines(append([]string{`{{ include "podnl" . }}`, `{{- "---" }}`}, pCmHead...),
			"data:", "  a: b")...), "", "kind: ConfigMap", []shapeKey{{"data.a", 8}}},
		{"65 value line followed by a left-trimmed comment", shapeLines(`{{ include "podspec" . }}`, "  hostname: {{ .Values.h }}",
			"{{- /* c */}}", "  hostNetwork: true"), "h: a\n", "kind: Pod", []shapeKey{{"spec.hostNetwork", 4}}},
		{"66 plain manifest", shapeLines("apiVersion: v1", "kind: Pod", "metadata:", "  name: p", "spec:", "  hostNetwork: true",
			"  containers:", "  - name: c", "    image: nginx"), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 4}, {"spec.hostNetwork", 6}, {"spec.containers.name={{c}}.image", 9}}},
		{"67 keys written after header and labels includes", shapeLines(`{{ include "header" . }}`, "  labels:",
			`{{ include "labels" . | indent 4 }}`, "spec:", "  hostNetwork: true", "  containers:", "  - name: c", "    image: nginx"),
			"", "kind: Pod", []shapeKey{{"metadata.name", 1}, {"metadata.labels.app", 3}, {"spec.hostNetwork", 5},
				{"spec.containers.name={{c}}.image", 8}}},
		{"68 keys written after a header include, then another document", shapeLines(`{{ include "header" . }}`, "spec:",
			"  hostNetwork: false", "---", "apiVersion: v1", "kind: Pod", "metadata:", "  name: q", "spec:", "  hostNetwork: true"),
			"", "name: p", []shapeKey{{"spec.hostNetwork", 3}}},
		{"69 document emitted by an include after a literal one", shapeLines("{{- if .Values.on }}", "apiVersion: v1",
			"kind: ConfigMap", "metadata:", "  name: cm", "{{- end }}", "---", `{{ include "pod" . }}`), "on: true\n", "kind: Pod",
			[]shapeKey{{"metadata.name", 8}, {"spec.containers.name={{c}}.image", 8}}},
		{"70 document composed of several includes", shapeLines(`{{ include "header" . }}`, `{{ include "spec" . }}`), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 1}, {"spec.hostNetwork", 2}}},
		{"71 include after a block scalar that has ended", shapeLines(withLines(pCmHead, "data:", "  script: |", "    echo hi",
			"  other: x", `{{ include "svc" . }}`)...), "", "kind: Service", []shapeKey{{"spec.type", 9}}},
		{"72 include after a single-line value", shapeLines(withLines(pCmHead, "data:", "  script: hi", "  other: x",
			`{{ include "svc" . }}`)...), "", "kind: Service", []shapeKey{{"spec.type", 8}}},
		{"73 labels include inside a document written in the file", shapeLines(withLines(pCmHead, "  labels:",
			`{{ include "labels" . | indent 4 }}`, "data:", "  a: b")...), "", "kind: ConfigMap",
			[]shapeKey{{"metadata.name", 4}, {"data.a", 8}}},
		{"74 include of another template, which has includes of its own", shapeLines(
			`{{ include (print $.Template.BasePath "/u.yaml") . }}`, "# a", "# b", "# c", "# d", "# e"), "", "name: inner",
			[]shapeKey{{"spec.hostNetwork", 1}, {"metadata.name", 1}}},
		{"75 two document separators in a row", shapeLines(`{{ include "dbl" . }}`), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 1}, {"spec.hostNetwork", 1}}},
		{"76 flow mapping in an include", shapeLines(`{{ include "fx" . }}`), "", "kind: Pod",
			[]shapeKey{{"spec.securityContext.privileged", 1}, {"spec.hostNetwork", 1}}},
		{"76b block mapping control", shapeLines(`{{ include "fx" . }}`), "", "kind: Pod",
			[]shapeKey{{"spec.securityContext.privileged", 1}, {"spec.hostNetwork", 1}}},
		{"77 flow sequence in an include", shapeLines(`{{ include "fx" . }}`), "", "kind: Pod",
			[]shapeKey{{"spec.containers.name={{c}}.image", 1}, {"spec.hostNetwork", 1}}},
		{"77b block sequence control", shapeLines(`{{ include "fx" . }}`), "", "kind: Pod",
			[]shapeKey{{"spec.containers.name={{c}}.image", 1}, {"spec.hostNetwork", 1}}},
		{"78 multi-line quoted scalar in an include", shapeLines(`{{ include "fx" . }}`), "", "kind: Pod",
			[]shapeKey{{"spec.hostname", 1}, {"spec.hostNetwork", 1}}},
		{"79 key after an if block, header include first", shapeLines(`{{ include "header" . }}`, "spec:", "{{- if true }}", "  hostNetwork: true",
			"{{- end }}", "  dnsPolicy: Default"), "", "kind: Pod", []shapeKey{{"spec.hostNetwork", 4}, {"spec.dnsPolicy", 6}}},
		{"80 key after a value action, header include first", shapeLines(`{{ include "header" . }}`, "spec:", "  hostname: {{ .Values.h }}",
			"  dnsPolicy: Default"), "h: a\n", "kind: Pod", []shapeKey{{"spec.hostname", 3}, {"spec.dnsPolicy", 4}}},
		{"81 key after toYaml, header include first", shapeLines(`{{ include "header" . }}`, "spec:",
			"  {{- toYaml .Values.s | nindent 2 }}", "  dnsPolicy: Default"), "s:\n  hostNetwork: true\n", "kind: Pod",
			[]shapeKey{{"spec.hostNetwork", 3}, {"spec.dnsPolicy", 4}}},
		{"82 key after range, header include first", shapeLines(`{{ include "header" . }}`, "spec:", "  containers:",
			`  {{- range list "a" }}`, "  - name: {{ . }}", "    image: nginx", "  {{- end }}", "  dnsPolicy: Default"), "", "kind: Pod",
			[]shapeKey{{"spec.dnsPolicy", 8}}},
		{"83 key after with, header include first", shapeLines(`{{ include "header" . }}`, "spec:", "{{- with .Values.s }}",
			"  hostNetwork: {{ . }}", "{{- end }}", "  dnsPolicy: Default"), "s: true\n", "kind: Pod",
			[]shapeKey{{"spec.dnsPolicy", 6}}},
		// The value actions above may print a line of their own text, so the
		// branch that wrote type is not told: spec owns it.
		{"85 same key in if and else branches, if taken", shapeLines("apiVersion: v1", "kind: Service", "metadata:", "  name: {{ .Values.name }}",
			"spec:", "  {{- if .Values.public }}", "  type: NodePort", "  {{- else }}", "  type: ClusterIP", "  {{- end }}",
			"  ports:", "    - port: {{ .Values.port }}"), "name: web\npublic: true\nport: 80\n", "kind: Service",
			[]shapeKey{{"spec.type", 5}, {"metadata.name", 4}}},
		{"86 literal spec after block scalar and column-0 include, Service doc", shapeLines("apiVersion: v1", "kind: Service", "metadata:",
			"  name: {{ .Values.name }}", "  annotations:", "    notes: |-", "      echo hi", "", "      echo again", `{{ include "svc" . }}`), "name: web\n", "  name: svc",
			[]shapeKey{{"spec.type", 10}}},
		// No include is marked in the template: the keys are resolved on the rendered
		// document, and the later name: of envFrom is not the container's.
		{"87 action-valued container name, later name key", shapeLines("apiVersion: v1", "kind: Pod", "metadata:", "  name: p", "spec:",
			"  containers:", "    - name: {{ .Values.cname }}", "      image: nginx", "      imagePullPolicy: {{ .Values.pp }}", "      envFrom:",
			"        - configMapRef:", "            name: cm"), "cname: web\npp: Always\n", "kind: Pod",
			[]shapeKey{{"spec.containers.name={{web}}.image", 8}, {"spec.containers.name={{web}}.imagePullPolicy", 9}}},
		{"88 two containers, action-valued names, one pull policy each", shapeLines("apiVersion: v1", "kind: Pod", "metadata:", "  name: p", "spec:",
			"  containers:", "    - name: {{ .Values.first }}", "      image: nginx", "      imagePullPolicy: {{ .Values.pp }}", "    - name: {{ .Values.second }}",
			"      image: busybox", "      imagePullPolicy: Never"), "first: web\nsecond: side\npp: Always\n", "kind: Pod",
			[]shapeKey{{"spec.containers.name={{web}}.imagePullPolicy", 9}, {"spec.containers.name={{side}}.imagePullPolicy", 12}}},
		{"84 leading trimmed include, literal key after it", shapeLines(`{{- include "header" . }}`, "spec:", "  hostNetwork: true"), "", "kind: Pod",
			[]shapeKey{{"metadata.name", 1}, {"spec.hostNetwork", 3}}},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			files := map[string]string{"templates/_helpers.tpl": shapeHelpers, "templates/t.yaml": s.tmpl}
			if s.values != "" {
				files["values.yaml"] = s.values
			}
			for name, content := range shapeTemplates[s.name] {
				files[name] = content
			}
			for _, k := range s.keys {
				require.Equal(t, k.want, findingLine(t, files, "templates/t.yaml", s.doc, k.searchKey), k.searchKey)
			}
		})
	}
}
