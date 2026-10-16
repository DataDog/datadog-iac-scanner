package terraform

import (
	"context"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
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
			fileData := strings.Join(lines, "\n")
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

			content, line := resolveListIndex(ctx, tt.attrName, tt.index, tt.currentLine, tt.lines, func() (*hclsyntax.Body, error) { return parseBody(fileData) }, unknownBlocks)
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
		{
			name:     "JSON Statement array inside heredoc body",
			attrName: "Statement",
			lines: []string{
				`  policy = <<EOF`,
				`{`,
				`  "Statement": [`,
				`    {`,
				`      "Effect": "Allow"`,
				`    }`,
				`  ]`,
				`}`,
				`EOF`,
			},
			startLine: 1,
			wantContent: `[
    {
      "Effect": "Allow"
    }
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

func TestResolveListIndexStatementInJsonencodeThirdElement(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("test", "jsonencode_third_element.tf"))
	require.NoError(t, err)
	linesPtr := utils.SplitLines(string(data))
	lines := *linesPtr
	ctx := context.Background()
	// currentLine 9 = line after `policy =` (0-indexed), same as DetectLine when resolving Statement[2]
	sub, lineNum := resolveListIndex(ctx, "Statement", 2, 9, lines, func() (*hclsyntax.Body, error) { return parseBody(data) }, unknownBlocks)
	require.Empty(t, sub)
	// Third tuple element starts at `{` on file line 41 (1-based) -> index 40
	require.Equal(t, 40, lineNum)
}

func TestRepeatedBlockSlots(t *testing.T) {
	src := `resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = var.first
    content {}
  }
  ingress {}
  dynamic "ingress" {
    for_each = ["x", "y"]
    content {}
  }
  dynamic "ingress" {
    for_each = var.second
    content {}
  }
}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	body := file.Body.(*hclsyntax.Body).Blocks[0].Body

	tests := []struct {
		name     string
		repeated repeatedBlocks
		want     blockSlots
	}{
		{"document lines are used as recorded", repeatedBlocks{total: 4, lines: []int{1, 1, 5, 10}}, blockSlots{1, 1, 5, 10}},
		{"document lines naming no source block are ignored", repeatedBlocks{total: 2, lines: []int{1, 3}}, blockSlots{5, 6, 6}},
		{"document lines not matching its total are ignored", repeatedBlocks{total: 3, lines: []int{1, 5}}, blockSlots{5, 6, 6}},
		{"no document: unresolved blocks stand for none", unknownBlocks, blockSlots{5, 6, 6}},
		{"total without lines: several unresolved blocks stand for none", repeatedBlocks{total: 7}, blockSlots{5, 6, 6}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, repeatedBlockSlots(body, "ingress", tt.repeated))
		})
	}

	single := `resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = var.rules
    content {}
  }
  ingress {}
}
`
	file, diags = hclsyntax.ParseConfig([]byte(single), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	body = file.Body.(*hclsyntax.Body).Blocks[0].Body
	require.Equal(t, blockSlots{1, 1, 5}, repeatedBlockSlots(body, "ingress", repeatedBlocks{total: 3}),
		"a single unresolved block stands for what the document's total leaves")
}

func TestEnclosingFirst(t *testing.T) {
	src := `resource "r" "x" {
  a {
  }
  b {
    inner {
    }
  }
  c {
  }
}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	blocks := file.Body.(*hclsyntax.Body).Blocks[0].Body.Blocks
	names := func(bs hclsyntax.Blocks) []string {
		out := make([]string, 0, len(bs))
		for _, b := range bs {
			out = append(out, b.Type)
		}
		return out
	}
	require.Equal(t, []string{"a", "b", "c"}, names(enclosingFirst(blocks, -1)), "no context keeps source order")
	require.Equal(t, []string{"b", "a", "c"}, names(enclosingFirst(blocks, 4)), "the block around the line comes first")
	require.Equal(t, []string{"a", "b", "c"}, names(enclosingFirst(blocks, 1)))
	require.Equal(t, []string{"a", "b", "c"}, names(enclosingFirst(blocks, 99)), "a line outside every block keeps source order")
}

// Below the body the blocks were counted for, the document's lines still pick the
// blocks, but its total is not shared out between unresolved dynamic blocks.
func TestRepeatedBlockSlotsInNestedBody(t *testing.T) {
	src := `resource "r" "x" {
  dynamic "flag" {
    for_each = var.flags
    content {}
  }
  flag {}
}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	body := file.Body.(*hclsyntax.Body).Blocks[0].Body

	require.Equal(t, blockSlots{1, 1, 5}, repeatedBlockSlots(body, "flag", repeatedBlocks{total: 3}),
		"in the body it was counted for, the total sizes the one unresolved block")
	require.Equal(t, blockSlots{5}, repeatedBlockSlots(body, "flag", repeatedBlocks{total: 3}.inNestedBody()),
		"in a nested body it is not")
	require.Equal(t, blockSlots{1, 1, 5}, repeatedBlockSlots(body, "flag", repeatedBlocks{total: 3, lines: []int{1, 1, 5}}.inNestedBody()),
		"the document's lines still apply")
}
