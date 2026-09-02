/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package helm

import (
	"context"
	"reflect"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/rs/zerolog"
)

var OriginalData1 = `# KICS_HELM_ID_0:
apiVersion: v1
kind: Pod
metadata:
  name: "{{ include "test_helm.fullname" . }}-test-connection"
  labels:
    {{- include "test_helm.labels" . | nindent 4 }}
  annotations:
	"helm.sh/hook": test
spec:
  containers:
    - name: wget
      image: busybox
	  command: ['wget']
	  args: ['{{ include "test_helm.fullname" . }}:{{ .Values.service.port }}']
    restartPolicy: Never
`

var OriginalData2 = `# KICS_HELM_ID_0:
apiVersion: v1
kind: Pod
metadata:
  name: "{{ include "test_helm.fullname" . }}-test-connection"
  labels:
    {{- include "test_helm.labels" . | nindent 4 }}
  annotations:
	"helm.sh/hook": test
spec:
  containers:
    - name: wget
      image: busybox
	  command: ['wget']
	  args: ['{{ include "test_helm.fullname" . }}:{{ .Values.service.port }}']
    restartPolicy: Never
  containers:
    - name: wget2
      image: busybox
	  command: ['wget']
	  args: ['{{ include "test_helm.fullname" . }}:{{ .Values.service.port }}']
    restartPolicy: Never
`

var OriginalDataPartialMatch = `# KICS_HELM_ID_0:
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: app
          securityContext: {}
          image: nginx
`

var OriginalData3 = `# KICS_HELM_ID_0:
apiVersion: v1
kind: Pod
metadata:
  name: "{{ include "test_helm.fullname" . }}-test-connection"
  labels:
    {{- include "test_helm.labels" . | nindent 4 }}
  annotations:
	"helm.sh/hook": test
spec:
  containers:
    - name: wget
      image: busybox
	  command: ['wget']
	  args: ['{{ include "test_helm.fullname" . }}:{{ .Values.service.port }}']
    restartPolicy: Never
---
# KICS_HELM_ID_1:
apiVersion: v1
kind: Pod
metadata:
  name: "{{ include "test_helm.fullname" . }}-test-dups"
  labels:
    {{- include "test_helm.labels" . | nindent 4 }}
  annotations:
	"helm.sh/hook": test
spec:
  containers:
    - name: wget
      image: busybox
	  command: ['wget']
	  args: ['{{ include "test_helm.fullname" . }}:{{ .Values.service.port }}']
    restartPolicy: Never
`

func TestEngine_detectHelmLine(t *testing.T) { //nolint
	type args struct {
		file          *model.FileMetadata
		searchKey     string
		logWithFields *zerolog.Logger
		outputLines   int
	}

	tests := []struct {
		name string
		args args
		want model.VulnerabilityLines
	}{
		{
			name: "test_detect_helm_line",
			args: args{
				file: &model.FileMetadata{
					ID:                "1",
					ScanID:            "console",
					Document:          model.Document{},
					Kind:              model.KindHELM,
					FilePath:          "test-connection.yaml",
					HelmID:            "# KICS_HELM_ID_0",
					OriginalData:      OriginalData1,
					LinesOriginalData: utils.SplitLines(OriginalData1),
				},
				searchKey:     "KICS_HELM_ID_0.metadata.name={{RELEASE-NAME-test_helm-test-connection}}.spec.containers",
				logWithFields: &zerolog.Logger{},
				outputLines:   1,
			},
			want: model.VulnerabilityLines{
				Line: 10,
				VulnLines: &[]model.CodeLine{
					{
						Position: 10,
						Line:     "  containers:",
					},
				},
				LineWithVulnerability: "  containers:",
				ResolvedFile:          "test-connection.yaml",
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 10,
						Col:  0,
					},
					End: model.ResourceLine{
						Line: 10,
						Col:  13,
					},
				},
			},
		},
		{
			name: "test_dup_values",
			args: args{
				file: &model.FileMetadata{
					ID:       "1",
					ScanID:   "console",
					Document: model.Document{},
					Kind:     model.KindHELM,
					FilePath: "test-dup_values.yaml",
					IDInfo: map[int]interface{}{0: map[int]int{0: 0, 1: 1, 2: 2, 3: 3, 4: 4,
						5: 5, 6: 6, 7: 7, 8: 8, 9: 9, 10: 10, 11: 11, 12: 12, 13: 13, 14: 14, 15: 15, 16: 16, 17: 17,
						18: 18, 19: 19, 21: 21, 22: 22}},
					HelmID:            "# KICS_HELM_ID_0",
					OriginalData:      OriginalData2,
					LinesOriginalData: utils.SplitLines(OriginalData2),
				},
				searchKey:     "KICS_HELM_ID_0.metadata.name={{RELEASE-NAME-test_helm-test-connection}}.spec.containers",
				logWithFields: &zerolog.Logger{},
				outputLines:   1,
			},
			want: model.VulnerabilityLines{
				Line: 9,
				VulnLines: &[]model.CodeLine{
					{
						Position: 9,
						Line:     "spec:",
					},
				},
				LineWithVulnerability: "spec:",
				ResolvedFile:          "test-dup_values.yaml",
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 9,
						Col:  0,
					},
					End: model.ResourceLine{
						Line: 9,
						Col:  13,
					},
				},
			},
		},
		{
			name: "test_detect_helm_with_dups",
			args: args{
				file: &model.FileMetadata{
					ID:                "1",
					ScanID:            "console",
					Document:          model.Document{},
					Kind:              model.KindHELM,
					FilePath:          "test-dups.yaml",
					HelmID:            "# KICS_HELM_ID_1",
					OriginalData:      OriginalData3,
					LinesOriginalData: utils.SplitLines(OriginalData3),
				},
				searchKey:     "KICS_HELM_ID_1.metadata.name={{RELEASE-NAME-test_helm-test-connection}}.spec.containers",
				logWithFields: &zerolog.Logger{},
				outputLines:   1,
			},
			want: model.VulnerabilityLines{
				Line: 26,
				VulnLines: &[]model.CodeLine{
					{
						Position: 26,
						Line:     "  containers:",
					},
				},
				LineWithVulnerability: "  containers:",
				ResolvedFile:          "test-dups.yaml",
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 26,
						Col:  0,
					},
					End: model.ResourceLine{
						Line: 26,
						Col:  13,
					},
				},
			},
		},
		{
			name: "test_preserve_location_when_final_key_missing",
			args: args{
				file: &model.FileMetadata{
					ID:                "1",
					ScanID:            "console",
					Document:          model.Document{},
					Kind:              model.KindHELM,
					FilePath:          "deployment.yaml",
					HelmID:            "# KICS_HELM_ID_0",
					OriginalData:      OriginalDataPartialMatch,
					LinesOriginalData: utils.SplitLines(OriginalDataPartialMatch),
				},
				searchKey:     "KICS_HELM_ID_0.spec.template.spec.containers.securityContext.runAsNonRoot",
				logWithFields: &zerolog.Logger{},
				outputLines:   1,
			},
			want: model.VulnerabilityLines{
				Line: 10,
				VulnLines: &[]model.CodeLine{
					{
						Position: 10,
						Line:     "          securityContext: {}",
					},
				},
				LineWithVulnerability: "          securityContext",
				ResolvedFile:          "deployment.yaml",
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 10,
						Col:  0,
					},
					End: model.ResourceLine{
						Line: 10,
						Col:  29,
					},
				},
			},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		detector := DetectKindLine{}
		t.Run(tt.name, func(t *testing.T) {
			got := detector.DetectLine(ctx, tt.args.file, tt.args.searchKey, tt.args.outputLines)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("detectHelmLine() = %v, want = %v", got, tt.want)
			}
		})
	}
}

func TestDetectLastSingleMissingHelmID(t *testing.T) {
	distances := map[int]int{2: 1, 5: 1}
	idInfo := map[int]interface{}{0: map[int]int{2: 2}}

	if !detectLastSingle(2, distances, idInfo, -1) {
		t.Fatal("missing Helm ID mapping should not mark the line as a duplicate")
	}
}

func TestDetectLastSingleUsesHelmIDLineRange(t *testing.T) {
	distances := map[int]int{2: 1, 5: 1}
	idInfo := map[int]interface{}{
		0: model.HelmIDLineRange{Start: 0, End: 3},
		1: model.HelmIDLineRange{Start: 4, End: 7},
	}

	if !detectLastSingle(2, distances, idInfo, 0) {
		t.Fatal("duplicate outside the selected Helm range must remain unique")
	}
	if detectLastSingle(2, map[int]int{2: 1, 3: 1}, idInfo, 0) {
		t.Fatal("duplicate inside the selected Helm range must not be unique")
	}
}

func TestDetectLine_JSONCRD(t *testing.T) {
	original := `{
  "apiVersion": "apiextensions.k8s.io/v1",
  "kind": "CustomResourceDefinition",
  "metadata": {
    "name": "gadgets.example.com"
  }
}`
	file := &model.FileMetadata{
		Kind:              model.KindHELM,
		FilePath:          "crds/gadget.json",
		OriginalData:      original,
		LinesOriginalData: utils.SplitLines(original),
		IDInfo:            map[int]interface{}{-1: map[int]int{}},
	}

	got := (DetectKindLine{}).DetectLine(context.Background(), file, "metadata.name", 1)

	if got.Line != 5 {
		t.Fatalf("DetectLine() line = %d, want 5", got.Line)
	}
	if got.LineWithVulnerability != `    "name"` {
		t.Fatalf("DetectLine() vulnerable line = %q, want JSON name key", got.LineWithVulnerability)
	}
}
