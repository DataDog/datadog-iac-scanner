/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/test"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestSelectLineWithMinimumDistance tests the functions [SelectLineWithMinimumDistance()] and all the methods called by them
func TestSelectLineWithMinimumDistance(t *testing.T) {
	values := []struct {
		distances      map[int]int
		startingFrom   int
		expectedResult int
	}{
		{
			distances: map[int]int{
				12: 0,
			},
			startingFrom:   0,
			expectedResult: 12,
		},
		{
			distances: map[int]int{
				12: 0,
				24: 0,
			},
			startingFrom:   11,
			expectedResult: 12,
		},
		{
			distances: map[int]int{
				1: 26,
				2: 5,
				3: 0,
			},
			startingFrom:   1,
			expectedResult: 3,
		},
	}

	for i, testCase := range values {
		t.Run(fmt.Sprintf("selectLineWithMinimumDistance-%d", i), func(t *testing.T) {
			v := SelectLineWithMinimumDistance(testCase.distances, testCase.startingFrom)
			require.Equal(t, testCase.expectedResult, v)
		})
	}
}

// TestGetBracketValues tests the functions [getBracketValues()] and all the methods called by them
func TestGetBracketValues(t *testing.T) {
	type args struct {
		expr string
	}
	tests := []struct {
		name string
		args args
		want [][]string
	}{
		{
			name: "no_brackets",
			args: args{
				expr: "password",
			},
			want: [][]string{
				{
					"{{password}}",
					"password",
				},
			},
		},
		{
			name: "single_brackets",
			args: args{
				expr: "{{password}}",
			},
			want: [][]string{
				{
					"{{password}}",
					"password",
				},
			},
		},
		{
			name: "double_brackets",
			args: args{
				expr: "{{ {{password}} }}",
			},
			want: [][]string{
				{
					"{{ {{password}} }}",
					" {{password}} ",
				},
			},
		},
		{
			name: "multiple_brackets",
			args: args{
				expr: "FROM={{open-jdk}}.{{ {{password}} }}",
			},
			want: [][]string{
				{
					"{{open-jdk}}",
					"open-jdk",
				},
				{
					"{{ {{password}} }}",
					" {{password}} ",
				},
			},
		},
		{
			name: "single_brackets",
			args: args{
				expr: "paths.{{user/{id}}}",
			},
			want: [][]string{
				{
					"{{user/{id}}}",
					"user/{id}",
				},
			},
		},
		{
			name: "interpolated_brackets",
			args: args{
				expr: "name={{interpolated {{ interpolated.brackets }} brackets {{ interpolated.brackets }}}}.{{interpolated.brackets}}",
			},
			want: [][]string{
				{
					"{{interpolated {{ interpolated.brackets }} brackets {{ interpolated.brackets }}}}",
					"interpolated {{ interpolated.brackets }} brackets {{ interpolated.brackets }}",
				},
				{
					"{{interpolated.brackets}}",
					"interpolated.brackets",
				},
			},
		},
	}

	for _, tt := range tests {
		var got [][]string
		t.Run(tt.name, func(t *testing.T) {
			got = GetBracketValues(tt.args.expr, got, "")
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DefaultVulnerabilityBuilder() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGetAdjacents tests the functions [GetAdjacents()] and all the methods called by them
func TestGetAdjacents(t *testing.T) { //nolint
	type args struct {
		idx   int
		adj   int
		lines []string
	}
	tests := []struct {
		name string
		args args
		want *[]model.CodeLine
	}{
		{
			name: "test_start_of_file",
			args: args{
				idx: 0,
				adj: 3,
				lines: []string{
					"firstline",
					"secondline",
					"thirdline",
					"forthline",
				},
			},
			want: &[]model.CodeLine{
				{
					Position: 1,
					Line:     "firstline",
				},
				{
					Position: 2,
					Line:     "secondline",
				},
				{
					Position: 3,
					Line:     "thirdline",
				},
			},
		},
		{
			name: "test_end_of_file",
			args: args{
				idx: 3,
				adj: 3,
				lines: []string{
					"firstline",
					"secondline",
					"thirdline",
					"forthline",
				},
			},
			want: &[]model.CodeLine{
				{
					Position: 2,
					Line:     "secondline",
				},
				{
					Position: 3,
					Line:     "thirdline",
				},
				{
					Position: 4,
					Line:     "forthline",
				},
			},
		},
		{
			name: "test_midle_of_file",
			args: args{
				idx: 1,
				adj: 3,
				lines: []string{
					"firstline",
					"secondline",
					"thirdline",
					"forthline",
				},
			},
			want: &[]model.CodeLine{
				{
					Position: 1,
					Line:     "firstline",
				},
				{
					Position: 2,
					Line:     "secondline",
				},
				{
					Position: 3,
					Line:     "thirdline",
				},
			},
		},
		{
			name: "test_even_adj",
			args: args{
				idx: 1,
				adj: 2,
				lines: []string{
					"firstline",
					"secondline",
					"thirdline",
					"forthline",
				},
			},
			want: &[]model.CodeLine{
				{
					Position: 2,
					Line:     "secondline",
				},
				{
					Position: 3,
					Line:     "thirdline",
				},
			},
		},
		{
			name: "test_even_adj_first_line",
			args: args{
				idx: 0,
				adj: 2,
				lines: []string{
					"firstline",
					"secondline",
					"thirdline",
					"forthline",
				},
			},
			want: &[]model.CodeLine{
				{
					Position: 1,
					Line:     "firstline",
				},
				{
					Position: 2,
					Line:     "secondline",
				},
			},
		},
		{
			name: "test_one_adj",
			args: args{
				idx: 3,
				adj: 1,
				lines: []string{
					"firstline",
					"secondline",
					"thirdline",
					"forthline",
				},
			},
			want: &[]model.CodeLine{
				{
					Position: 4,
					Line:     "forthline",
				},
			},
		},
		{
			name: "test_adj_bigger_than_file",
			args: args{
				idx: 3,
				adj: 5,
				lines: []string{
					"firstline",
					"secondline",
					"thirdline",
					"forthline",
				},
			},
			want: &[]model.CodeLine{
				{
					Position: 1,
					Line:     "firstline",
				},
				{
					Position: 2,
					Line:     "secondline",
				},
				{
					Position: 3,
					Line:     "thirdline",
				},
				{
					Position: 4,
					Line:     "forthline",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetAdjacentVulnLines(tt.args.idx, tt.args.adj, tt.args.lines)
			gotStrVulnerabilities, err := test.StringifyStruct(got)
			require.Nil(t, err)
			wantStrVulnerabilities, err := test.StringifyStruct(tt.want)
			require.Nil(t, err)
			if !reflect.DeepEqual(gotStrVulnerabilities, wantStrVulnerabilities) {
				t.Errorf("getAdjacents() = %v, want = %v", gotStrVulnerabilities, wantStrVulnerabilities)
			}
		})
	}
}

func TestDetectCurrentLine(t *testing.T) {
	type fields struct {
		defaultDetectLineResponse *DefaultDetectLineResponse
	}

	type args struct {
		lines []string
		str1  string
		str2  string
	}

	type want struct {
		defaultDetectLineResponse *DefaultDetectLineResponse
	}

	tests := []struct {
		name   string
		fields fields
		args   args
		want   want
	}{
		{
			name: "test_checkLines",
			args: args{
				lines: []string{
					"		\"type\": \"string\"",
					"	\"type\": \"array\"",
				},
				str1: "\"type\"",
				str2: "",
			},
			fields: fields{
				&DefaultDetectLineResponse{
					CurrentLine:     0,
					IsBreak:         false,
					FoundAtLeastOne: false,
					ResolvedFile:    "",
					ResolvedFiles:   map[string]model.ResolvedFileSplit{},
				},
			},
			want: want{
				&DefaultDetectLineResponse{
					CurrentLine:     0,
					IsBreak:         false,
					FoundAtLeastOne: false,
					ResolvedFile:    "",
					ResolvedFiles:   map[string]model.ResolvedFileSplit{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.fields.defaultDetectLineResponse

			d, _, _, _ = d.DetectCurrentLine(tt.args.str1, tt.args.str2, 0, tt.args.lines, "kind")

			if d.CurrentLine != tt.want.defaultDetectLineResponse.CurrentLine {
				t.Errorf("DetectCurrentLine() = %v, want %v", d.CurrentLine, tt.want.defaultDetectLineResponse.CurrentLine)
			}
		})
	}

}

func TestExtractLineFragmentMissingSubstring(t *testing.T) {
	line := `"http://www.example.com"`

	require.Equal(t, line, ExtractLineFragment(line, "unrelated multiline content", false))
}

func TestExtractLineFragmentEmptyInput(t *testing.T) {
	require.Empty(t, ExtractLineFragment("", "", false))
}

func TestGenerateSubstringsDoesNotTreatTemplateSyntaxAsPlaceholder(t *testing.T) {
	var logs bytes.Buffer
	ctx := zerolog.New(&logs).WithContext(context.Background())

	first, second := GenerateSubstrings(ctx, `${{ github.ref }}`, nil, nil, 0)

	require.Equal(t, `${{ github.ref }}`, first)
	require.Empty(t, second)
	require.Empty(t, logs.String())
}

// referenceDetectCurrentLine is the unoptimized selection: score every line
// from start, then take the minimum distance, the lowest line on ties.
func referenceDetectCurrentLine(str1, str2 string, start int, lines []string, kind model.FileKind) (int, model.ResourceLine, model.ResourceLine, bool) {
	distances := map[int]int{}
	starts, ends := map[int]model.ResourceLine{}, map[int]model.ResourceLine{}
	for i := start; i < len(lines); i++ {
		if distance, s, e, ok := checkLine(str1, str2, lines, i, kind); ok {
			distances[i], starts[i], ends[i] = distance, s, e
		}
	}
	if len(distances) == 0 {
		return -1, model.ResourceLine{}, model.ResourceLine{}, false
	}
	line := SelectLineWithMinimumDistance(distances, start)
	return line, starts[line], ends[line], true
}

func TestDetectCurrentLineMatchesFullScan(t *testing.T) {
	lines := []string{
		"- name: web",
		"  azure_rm_securitygroup:",
		"    name: webgroup",
		"    rules:",
		"      - name: webrule",
		"        destination_port_range: \"22\"",
		"- name: web2",
		"  azure_rm_securitygroup:",
		"    name: web2group",
		"    rules:",
		"      - name: webrule2",
		"        destination_port_range: \"2222\"",
		"        note: |",
		"          port 22 is open",
		"# name: commented",
		"  name:web",
		"name: web",
	}
	keys := []struct{ str1, str2 string }{
		{"name", ""}, {"name: web", ""}, {"web", ""}, {"name", "web2"}, {"destination_port_range", "22"},
		{"note", "port 22"}, {"rules", ""}, {"missing", ""}, {"", ""}, {"name", "zzz"},
	}
	for _, kind := range []model.FileKind{model.KindYAML, model.KindJSON} {
		for _, cached := range []bool{false, true} {
			for _, k := range keys {
				for start := range lines {
					file := &model.FileMetadata{OriginalData: strings.Join(lines, "\n")}
					file.SetLazyLines()
					d := &DefaultDetectLineResponse{CurrentLine: start}
					if cached {
						d.File = file
					}
					got, gotStart, gotEnd, _ := d.DetectCurrentLine(k.str1, k.str2, 0, file.Lines(), kind)

					wantLine, wantStart, wantEnd, found := referenceDetectCurrentLine(k.str1, k.str2, start, file.Lines(), kind)
					name := fmt.Sprintf("kind=%s cached=%v key=%q/%q start=%d", kind, cached, k.str1, k.str2, start)
					require.Equal(t, !found, got.IsBreak, name)
					if !found {
						continue
					}
					require.Equal(t, wantLine, got.CurrentLine, name)
					require.Equal(t, wantStart, gotStart, name)
					require.Equal(t, wantEnd, gotEnd, name)
				}
			}
		}
	}
}

func TestDetectCurrentLineMatchesFullScanRandomized(t *testing.T) {
	vocab := []string{
		"name: web", "name: db", "  name: web1", "    - name: task a", "    - name: task b",
		"state: latest", "  state: present", "port: \"22\"", "  note: |", "    port 22 is open",
		"  note: >-", "    web is here", "# name: web", "// name: db", "  cmd: \\", "    web", "",
		"key: value # web", "  - name: web", "name:web",
	}
	keys := [][2]string{
		{"name", ""}, {"name", "web"}, {"name", "task a"}, {"name", "db"}, {"state", "latest"},
		{"note", "port 22"}, {"note", "web"}, {"cmd", "web"}, {"web", ""}, {"state", ""}, {"port", "22"},
	}
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 150; iter++ {
		lines := make([]string, 5+rng.Intn(40))
		for i := range lines {
			lines[i] = vocab[rng.Intn(len(vocab))]
		}
		file := &model.FileMetadata{OriginalData: strings.Join(lines, "\n")}
		file.SetLazyLines()
		fileLines := file.Lines()
		for _, kind := range []model.FileKind{model.KindYAML, model.KindJSON} {
			for _, k := range keys {
				start := rng.Intn(len(fileLines))
				d := &DefaultDetectLineResponse{CurrentLine: start, File: file}
				got, gotStart, gotEnd, _ := d.DetectCurrentLine(k[0], k[1], 0, fileLines, kind)
				wantLine, wantStart, wantEnd, found := referenceDetectCurrentLine(k[0], k[1], start, fileLines, kind)
				name := fmt.Sprintf("iter=%d kind=%s key=%q start=%d lines=%q", iter, kind, k, start, fileLines)
				require.Equal(t, !found, got.IsBreak, name)
				if found {
					require.Equal(t, wantLine, got.CurrentLine, name)
					require.Equal(t, wantStart, gotStart, name)
					require.Equal(t, wantEnd, gotEnd, name)
				}
			}
		}
	}
}
