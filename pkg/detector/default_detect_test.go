/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"reflect"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/test"
	"github.com/stretchr/testify/require"
)

var OriginalDataCICD = `name: Web Page To Markdown
on:
  issues:
    types: [opened]
jobs:
  WebPageToMarkdown:
    runs-on: ubuntu-latest
    steps:
      - name: Does the issue need to be converted to markdown
        run: |
          if [ "${{ github.event.issue.body }}" ]; then
            if [[ "${{ github.event.issue.title }}" =~ ^\[Auto\]* ]]; then
              :
            else
              echo "This issue does not need to generate a markdown file." 1>&2
              exit 1;
            fi;
          else
            echo "The description of the issue is empty." 1>&2
            exit 1;
          fi;
        shell: bash
      - name: Checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
      - name: Crawl pages and generate Markdown files
        uses: freeCodeCamp-China/article-webpage-to-markdown-action@v0.1.8
        with:
          newsLink: '${{ github.event.issue.body }}'
          markDownFilePath: './chinese/articles/'
          githubToken: ${{ github.token }}
      - name: Git Auto Commit
        uses: stefanzweifel/git-auto-commit-action@v4.9.2
        with:
          commit_message: '${{ github.event.issue.title }}'
          file_pattern: chinese/articles/*.md
          commit_user_name: PageToMarkdown Bot
          commit_user_email: PageToMarkdown-bot@freeCodeCamp.org
	  `

// Test_detectLine tests the functions [detectLine()] and all the methods called by them
func Test_detectLineCICD(t *testing.T) { //nolint
	type args struct {
		file      *model.FileMetadata
		searchKey string
	}
	type fields struct {
		outputLines int
	}
	tests := []struct {
		name   string
		args   args
		fields fields
		want   model.VulnerabilityLines
	}{
		{
			name: "detect_line",
			args: args{
				file: &model.FileMetadata{
					ScanID:            "scanID",
					ID:                "Test",
					Kind:              model.KindYAML,
					OriginalData:      OriginalDataCICD,
					LinesOriginalData: utils.SplitLines(OriginalDataCICD),
				},
				searchKey: "uses={{freeCodeCamp-China/article-webpage-to-markdown-action@v0.1.8}}",
			},
			fields: fields{
				outputLines: 3,
			},
			want: model.VulnerabilityLines{
				Line: 28,
				VulnLines: &[]model.CodeLine{
					{
						Position: 27,
						Line:     `      - name: Crawl pages and generate Markdown files`,
					},
					{
						Position: 28,
						Line:     `        uses: freeCodeCamp-China/article-webpage-to-markdown-action@v0.1.8`,
					},
					{
						Position: 29,
						Line:     "        with:",
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 28,
						Col:  8,
					},
					End: model.ResourceLine{
						Line: 28,
						Col:  74,
					},
				},
			},
		},
		{
			name: "detect_line_with_curly_brackets",
			args: args{
				file: &model.FileMetadata{
					ScanID:            "scanID",
					ID:                "Test",
					Kind:              model.KindYAML,
					OriginalData:      OriginalDataCICD,
					LinesOriginalData: utils.SplitLines(OriginalDataCICD),
				},
				searchKey: `run={{if [ "${{ github.event.issue.body }}" ]; then
  if [[ "${{ github.event.issue.title }}" =~ ^\[Auto\]* ]]; then
    :
  else
    echo "This issue does not need to generate a markdown file." 1>&2
    exit 1;
  fi;
else
  echo "The description of the issue is empty." 1>&2
  exit 1;
fi;
}}`,
			},
			fields: fields{
				outputLines: 3,
			},
			want: model.VulnerabilityLines{
				Line: 10,
				VulnLines: &[]model.CodeLine{
					{
						Position: 9,
						Line:     `      - name: Does the issue need to be converted to markdown`,
					},
					{
						Position: 10,
						Line:     `        run: |`,
					},
					{
						Position: 11,
						Line:     `          if [ "${{ github.event.issue.body }}" ]; then`,
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 10,
						Col:  8,
					},
					End: model.ResourceLine{
						Line: 21,
						Col:  14,
					},
				},
			},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		detector := NewDetectLine(tt.fields.outputLines)
		t.Run(tt.name, func(t *testing.T) {
			got := detector.defaultDetector.DetectLine(ctx, tt.args.file, tt.args.searchKey, 3)
			gotStrVulnerabilities, err := test.StringifyStruct(got)
			require.Nil(t, err)
			wantStrVulnerabilities, err := test.StringifyStruct(tt.want)
			require.Nil(t, err)
			if !reflect.DeepEqual(gotStrVulnerabilities, wantStrVulnerabilities) {
				t.Errorf("detectLine() = %v, want %v", gotStrVulnerabilities, wantStrVulnerabilities)
			}
		})
	}
}

var OriginalDataK8s = `apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  privileged: true
  allowPrivilegeEscalation: true
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
  hostPID: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'

---
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged2
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  privileged: true
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
  hostPID: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
	  `

// Test_detectLine tests the functions [detectLine()] and all the methods called by them
func Test_detectLineK8s(t *testing.T) { //nolint
	type args struct {
		file      *model.FileMetadata
		searchKey string
	}
	type fields struct {
		outputLines int
	}
	tests := []struct {
		name   string
		args   args
		fields fields
		want   model.VulnerabilityLines
	}{
		{
			name: "detect_line",
			args: args{
				file: &model.FileMetadata{
					ScanID:            "scanID",
					ID:                "Test",
					Kind:              model.KindYAML,
					OriginalData:      OriginalDataK8s,
					LinesOriginalData: utils.SplitLines(OriginalDataK8s),
				},
				searchKey: "metadata.name={{privileged}}.spec.allowPrivilegeEscalation",
			},
			fields: fields{
				outputLines: 3,
			},
			want: model.VulnerabilityLines{
				Line: 9,
				VulnLines: &[]model.CodeLine{
					{
						Position: 8,
						Line:     `  privileged: true`,
					},
					{
						Position: 9,
						Line:     `  allowPrivilegeEscalation: true`,
					},
					{
						Position: 10,
						Line:     "  hostNetwork: true",
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 9,
						Col:  2,
					},
					End: model.ResourceLine{
						Line: 9,
						Col:  32,
					},
				},
			},
		},
		{
			name: "detect_line_2",
			args: args{
				file: &model.FileMetadata{
					ScanID:            "scanID",
					ID:                "Test",
					Kind:              model.KindYAML,
					OriginalData:      OriginalDataK8s,
					LinesOriginalData: utils.SplitLines(OriginalDataK8s),
				},
				searchKey: `metadata.name={{privileged}}.spec.supplementalGroups.rule`,
			},
			fields: fields{
				outputLines: 3,
			},
			want: model.VulnerabilityLines{
				Line: 21,
				VulnLines: &[]model.CodeLine{
					{
						Position: 20,
						Line:     `  supplementalGroups:`,
					},
					{
						Position: 21,
						Line:     `    rule: 'RunAsAny'`,
					},
					{
						Position: 22,
						Line:     `  fsGroup:`,
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 21,
						Col:  4,
					},
					End: model.ResourceLine{
						Line: 21,
						Col:  20,
					},
				},
			},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		detector := NewDetectLine(tt.fields.outputLines)
		t.Run(tt.name, func(t *testing.T) {
			got := detector.defaultDetector.DetectLine(ctx, tt.args.file, tt.args.searchKey, 3)
			gotStrVulnerabilities, err := test.StringifyStruct(got)
			require.Nil(t, err)
			wantStrVulnerabilities, err := test.StringifyStruct(tt.want)
			require.Nil(t, err)
			if !reflect.DeepEqual(gotStrVulnerabilities, wantStrVulnerabilities) {
				t.Errorf("detectLine() = %v, want %v", gotStrVulnerabilities, wantStrVulnerabilities)
			}
		})
	}
}

var content = []byte(
	`content1
content2`)

func Test_defaultDetectLine_prepareResolvedFiles(t *testing.T) {
	type args struct {
		resFiles map[string]model.ResolvedFile
	}
	tests := []struct {
		name string
		args args
		want map[string]model.ResolvedFileSplit
	}{
		{
			name: "prepare_resolved_files",
			args: args{
				resFiles: map[string]model.ResolvedFile{
					"file1": {
						Content:      content,
						Path:         "testing/file1",
						LinesContent: utils.SplitLines(string(content)),
					},
				},
			},
			want: map[string]model.ResolvedFileSplit{
				"file1": {
					Path:  "testing/file1",
					Lines: []string{"content1", "content2"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := defaultDetectLine{}
			if got := d.prepareResolvedFiles(tt.args.resFiles); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("prepareResolvedFiles() = %v, want %v", got, tt.want)
			}
		})
	}
}
