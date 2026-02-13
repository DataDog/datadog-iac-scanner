package terraform

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateSubstrings(t *testing.T) {
	lines := []string{
		`description = "hello"`,
		`name = "web"`,
		`labels = { Name = "db" }`,
		`tags = ["a", "b", "c"]`,
	}

	tests := []struct {
		name        string
		key         string
		extracted   [][]string
		currentLine int
		wantSubstr1 string
		wantSubstr2 string
		wantIdx     int
	}{
		{
			name:        "list index resolves to value",
			key:         `tags[1]`,
			currentLine: 0,
			wantSubstr1: "tags",
			wantSubstr2: "",
			wantIdx:     3,
		},
		{
			name:        "numeric bracket but not a list -> block navigation (no value)",
			key:         `ingress[0]`,
			currentLine: 0,
			wantSubstr1: "ingress",
			wantSubstr2: "",
			wantIdx:     0,
		},
		{
			name:        "map-style quoted key",
			key:         `labels["Name"]`,
			currentLine: 0,
			wantSubstr1: "labels",
			wantSubstr2: "Name",
			wantIdx:     0,
		},
		{
			name:        "unquoted label key",
			key:         `resource[web]`,
			currentLine: 0,
			wantSubstr1: "resource",
			wantSubstr2: "web",
			wantIdx:     0,
		},
		{
			name:        "placeholder inside brackets gets restored",
			key:         `labels[{{0}}]`,
			extracted:   [][]string{{"Environment"}},
			currentLine: 0,
			wantSubstr1: "labels",
			wantSubstr2: "Environment",
			wantIdx:     0,
		},
		{
			name:        "plain key=value line",
			key:         `description = "hello"`,
			currentLine: 0,
			wantSubstr1: "description",
			// Note: function preserves quotes from the right-hand side
			wantSubstr2: `"hello"`,
			wantIdx:     0,
		},
		{
			name:        "numeric placeholder but not list -> treated as block navigation (no value)",
			key:         `block[{{0}}]`,
			extracted:   [][]string{{"0"}},
			currentLine: 0,
			wantSubstr1: "block",
			wantSubstr2: "",
			wantIdx:     0,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileData := []byte(strings.Join(lines, "\n"))
			got1, got2, idx := GenerateSubstrings(ctx, tt.key, tt.extracted, lines, tt.currentLine, fileData)
			require.Equal(t, tt.wantSubstr1, got1)
			require.Equal(t, tt.wantSubstr2, got2)
			require.Equal(t, tt.wantIdx, idx)
		})
	}
}

func TestResolveListIndex(t *testing.T) {
	tests := []struct {
		name        string
		attrName    string
		index       int
		currentLine int
		lines       []string
		wantContent string
		wantLine    int
	}{
		{
			name:        "single line array multiple elements",
			attrName:    "tags",
			index:       2,
			currentLine: 0,
			lines: []string{
				`names = ["web"]`,
				`tags = ["a", "b", "c"]`,
			},
			wantContent: "",
			wantLine:    1,
		},
		{
			name:        "single line array element further than length",
			attrName:    "tags",
			index:       5,
			currentLine: 0,
			lines: []string{
				`tags = ["a", "b", "c"]`,
				`names = ["web"]`,
			},
			wantContent: "",
			wantLine:    0,
		},
		{
			name:        "single line array second line",
			attrName:    "names",
			index:       0,
			currentLine: 0,
			lines: []string{
				`tags = ["a", "b", "c"]`,
				`names = ["web"]`,
			},
			wantContent: "",
			wantLine:    1,
		},
		{
			name:        "multiple line array multiple elements",
			attrName:    "user_data",
			index:       1,
			currentLine: 0,
			lines: []string{
				`  user_data = [`,
				`    <<-EOT`,
				`      #!/bin/bash`,
				`      echo "test, with, commas"`,
				`    EOT`,
				`    ,`,
				`    "sg-2"`,
				`  ]`,
			},
			wantContent: "",
			wantLine:    6,
		},
		{
			name:        "multiple line array element further than length",
			attrName:    "user_data",
			index:       2,
			currentLine: 0,
			lines: []string{
				`  user_data = [`,
				`    <<-EOT`,
				`      #!/bin/bash`,
				`      echo "test, with, commas"`,
				`    EOT`,
				`    ,`,
				`    "sg-2"`,
				`  ]`,
			},
			wantContent: "",
			wantLine:    0,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileData := []byte(strings.Join(tt.lines, "\n"))

			content, line := resolveListIndex(ctx, tt.attrName, tt.index, tt.currentLine, tt.lines, fileData)
			require.Equal(t, tt.wantContent, content)
			require.Equal(t, tt.wantLine, line)

		})
	}
}

func TestExtractArrayContent(t *testing.T) {
	tests := []struct {
		name        string
		attrName    string
		lines       []string
		startLine   int
		wantContent string
	}{
		{
			name:        "single line array",
			attrName:    "tags",
			lines:       []string{`  tags = ["a", "b", "c"]`},
			startLine:   0,
			wantContent: `["a", "b", "c"]`,
		},
		{
			name:     "multi-line array",
			attrName: "security_groups",
			lines: []string{
				`  security_groups = [`,
				`    "sg-1",`,
				`    "sg-2"`,
				`  ]`,
			},
			startLine: 0,
			wantContent: `[
    "sg-1",
    "sg-2"
  ]`,
		},
		{
			name:     "array with heredoc",
			attrName: "user_data",
			lines: []string{
				`  user_data = [`,
				`    <<-EOT`,
				`      #!/bin/bash`,
				`      echo "test, with, commas"`,
				`    EOT`,
				`    ,`,
				`    "sg-2"`,
				`  ]`,
			},
			startLine: 0,
			wantContent: `[
    <<-EOT
      #!/bin/bash
      echo "test, with, commas"
    EOT
    ,
    "sg-2"
  ]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractArrayContent(tt.attrName, tt.lines, tt.startLine)
			require.Equal(t, tt.wantContent, got)
		})
	}
}

func TestGetArrayElementLine(t *testing.T) {
	tests := []struct {
		name      string
		attrName  string
		index     int
		lines     []string
		startLine int
		wantLine  int
		wantErr   bool
	}{
		{
			name:      "single line array - first element",
			attrName:  "tags",
			index:     0,
			lines:     []string{`  tags = ["a", "b", "c"]`},
			startLine: 0,
			wantLine:  0, // 0-indexed
			wantErr:   false,
		},
		{
			name:      "single line array - second element",
			attrName:  "tags",
			index:     1,
			lines:     []string{`  tags = ["a", "b", "c"]`},
			startLine: 0,
			wantLine:  0, // 0-indexed, same line
			wantErr:   false,
		},
		{
			name:     "multi-line array - first element",
			attrName: "security_groups",
			index:    0,
			lines: []string{
				`  security_groups = [`,
				`    "sg-1",`,
				`    "sg-2"`,
				`  ]`,
			},
			startLine: 0,
			wantLine:  1, // 0-indexed, line 1 in array (2nd line of file)
			wantErr:   false,
		},
		{
			name:     "multi-line array - second element",
			attrName: "security_groups",
			index:    1,
			lines: []string{
				`  security_groups = [`,
				`    "sg-1",`,
				`    "sg-2"`,
				`  ]`,
			},
			startLine: 0,
			wantLine:  2, // 0-indexed, line 2 in array (3rd line of file)
			wantErr:   false,
		},
		{
			name:     "array with heredoc - second element",
			attrName: "user_data",
			index:    1,
			lines: []string{
				`  user_data = [`,
				`    <<-EOT`,
				`      #!/bin/bash`,
				`      echo "test, with, commas"`,
				`    EOT`,
				`    ,`,
				`    "sg-2"`,
				`  ]`,
			},
			startLine: 0,
			wantLine:  6, // 0-indexed, line 6 in array (7th line of file)
			wantErr:   false,
		},
		{
			name:      "index out of bounds",
			attrName:  "tags",
			index:     10,
			lines:     []string{`  tags = ["a", "b"]`},
			startLine: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLine, err := getArrayElementLine(tt.attrName, tt.index, tt.lines, tt.startLine)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantLine, gotLine)
			}
		})
	}
}
