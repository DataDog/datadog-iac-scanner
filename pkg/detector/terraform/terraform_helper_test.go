package terraform

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

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

			content, line := resolveListIndex(ctx, tt.attrName, tt.index, tt.currentLine, tt.lines, func() (*hclsyntax.Body, error) { return parseBody(fileData) }, unknownBlocks, nil)
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
	sub, lineNum := resolveListIndex(ctx, "Statement", 2, 9, lines, func() (*hclsyntax.Body, error) { return parseBody(data) }, unknownBlocks, nil)
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
			require.Equal(t, tt.want, repeatedBlockSlots(context.Background(), body, "ingress", tt.repeated, nil))
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
	require.Equal(t, blockSlots{1, 1, 5}, repeatedBlockSlots(context.Background(), body, "ingress", repeatedBlocks{total: 3}, nil),
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

	require.Equal(t, blockSlots{1, 1, 5}, repeatedBlockSlots(context.Background(), body, "flag", repeatedBlocks{total: 3}, nil),
		"in the body it was counted for, the total sizes the one unresolved block")
	require.Equal(t, blockSlots{5}, repeatedBlockSlots(context.Background(), body, "flag", repeatedBlocks{total: 3}.inNestedBody(), nil),
		"in a nested body it is not")
	require.Equal(t, blockSlots{1, 1, 5}, repeatedBlockSlots(context.Background(), body, "flag", repeatedBlocks{total: 3, lines: []int{1, 1, 5}}.inNestedBody(), nil),
		"the document's lines still apply")
}

// A dynamic block whose for_each asks for more blocks than any scan enumerates
// stops expanding at the context: the walk ends promptly and materializes
// nothing, instead of building the full slot list.
func TestRepeatedBlockSlots_StopsWhenTheContextIsDone(t *testing.T) {
	var rules []string
	for i := 0; i < 300000; i++ {
		rules = append(rules, "0")
	}
	src := `resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = ["` + strings.Join(rules, `", "`) + `"]
    content {}
  }
}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	body := file.Body.(*hclsyntax.Body).Blocks[0].Body

	start := time.Now()
	slots := repeatedBlockSlots(canceledContext(), body, "ingress", unknownBlocks, nil)
	require.Less(t, time.Since(start), 10*time.Second, "the expansion must stop promptly at the context")
	require.Empty(t, slots, "a canceled expansion stands for no slots")
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// A cold expansion interrupted mid-walk must not be misread as an unresolved
// for_each: the document's total is not filled and the slots do not grow,
// nothing partial is memoized, and a later lookup on a healthy context still
// produces the complete result.
func TestRepeatedBlockSlots_InterruptedColdExpansionIsNotMisread(t *testing.T) {
	var parts []string
	for i := 0; i < 100000; i++ {
		parts = append(parts, strconv.Itoa(i))
	}
	src := `resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = [` + strings.Join(parts, ", ") + `]
    content {
      from_port = ingress.value
    }
  }
}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	body := file.Body.(*hclsyntax.Body).Blocks[0].Body

	// Cancel while the first, cold expansion is still walking the collection.
	expansions := &sync.Map{}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(time.Millisecond)
		cancel()
	}()
	slots := repeatedBlockSlots(ctx, body, "ingress", repeatedBlocks{total: 90000}, expansions)
	cancel()
	require.Empty(t, slots, "an interrupted expansion must not fill the total or grow the slots")

	after := repeatedBlockSlots(context.Background(), body, "ingress", repeatedBlocks{total: 90000}, expansions)
	require.Len(t, after, 100000, "the healthy lookup must produce the complete result")
}

// Slot materialization itself honors the context: with the memo warm, a
// lookup whose context is canceled while the slots are being appended returns
// nothing, and a healthy re-lookup still materializes the complete result.
func TestRepeatedBlockSlots_CanceledMaterializationReturnsNoPartialSlots(t *testing.T) {
	var parts []string
	for i := 0; i < 1000000; i++ {
		parts = append(parts, strconv.Itoa(i))
	}
	src := `resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = [` + strings.Join(parts, ", ") + `]
    content {
      from_port = ingress.value
    }
  }
}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	body := file.Body.(*hclsyntax.Body).Blocks[0].Body

	// A healthy lookup populates the memo with the complete count.
	warm := &sync.Map{}
	complete := repeatedBlockSlots(context.Background(), body, "ingress", unknownBlocks, warm)
	require.Len(t, complete, 1000000)

	// cancelAfterQueries cancels itself after a fixed number of Err queries:
	// the lookup calls Err once at entry and once per slot appended, so
	// cancellation after 1,000 queries provably lands inside the append loop,
	// well past the entry guard, whatever the goroutine scheduling.
	ctx := &cancelAfterQueries{Context: context.Background(), remaining: 1000}
	slots := repeatedBlockSlots(ctx, body, "ingress", unknownBlocks, warm)
	require.Empty(t, slots, "a canceled materialization must not return partial slots")
	require.ErrorIs(t, ctx.Err(), context.Canceled,
		"the cancellation must have fired inside the append loop, past the entry guard")

	after := repeatedBlockSlots(context.Background(), body, "ingress", unknownBlocks, warm)
	require.Equal(t, complete, after, "the healthy re-lookup must materialize the complete result")
}

// cancelAfterQueries is a context that cancels itself once Err has been
// queried a fixed number of times, so a test can land cancellation at a
// chosen call site deterministically instead of racing a timer.
type cancelAfterQueries struct {
	context.Context
	remaining int
	mu        sync.Mutex
	canceled  bool
}

func (c *cancelAfterQueries) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remaining == 0 {
		c.canceled = true
		return context.Canceled
	}
	c.remaining--
	return nil
}

// A canceled lookup stops before any slot work even when the memo is warm,
// leaves the memo untouched, and a later lookup on a healthy context still
// produces the complete result.
func TestRepeatedBlockSlots_CanceledLookupsDoNotPoisonTheMemo(t *testing.T) {
	var parts []string
	for i := 0; i < 2000; i++ {
		parts = append(parts, strconv.Itoa(i))
	}
	src := `resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = [` + strings.Join(parts, ", ") + `]
    content {
      from_port = ingress.value
    }
  }
}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	body := file.Body.(*hclsyntax.Body).Blocks[0].Body

	expansions := &sync.Map{}
	first := repeatedBlockSlots(context.Background(), body, "ingress", unknownBlocks, expansions)
	require.Len(t, first, 2000, "the healthy lookup expands the block completely and populates the memo")

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 100; i++ {
		require.Empty(t, repeatedBlockSlots(canceled, body, "ingress", unknownBlocks, expansions),
			"a canceled lookup stops before any slot work, memo hits included")
	}

	after := repeatedBlockSlots(context.Background(), body, "ingress", unknownBlocks, expansions)
	require.Equal(t, first, after, "the canceled lookups must not corrupt or extend the memo")
}

// Line detection revisits the same body once per finding, so the expansion of
// one dynamic block is memoized across lookups: the allocations of many
// lookups stay close to those of a single lookup instead of scaling with the
// lookup count (a 100-lookup scan of a 10,000-element block would otherwise
// re-expand the block a hundred times).
func TestRepeatedBlockSlotsExpansionMemoizedAcrossLookups(t *testing.T) {
	var parts []string
	for i := 0; i < 10000; i++ {
		parts = append(parts, strconv.Itoa(i))
	}
	src := `resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = [` + strings.Join(parts, ", ") + `]
    content {
      from_port = ingress.value
    }
  }
}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	body := file.Body.(*hclsyntax.Body).Blocks[0].Body

	lookups := func(r int) func() {
		return func() {
			expansions := &sync.Map{}
			for i := 0; i < r; i++ {
				slots := repeatedBlockSlots(context.Background(), body, "ingress", unknownBlocks, expansions)
				runtime.KeepAlive(slots)
			}
		}
	}

	once := testing.AllocsPerRun(1, lookups(1))
	twenty := testing.AllocsPerRun(1, lookups(20))
	require.Less(t, twenty, 2*once,
		"twenty lookups must reuse the first expansion instead of re-expanding per lookup")
}
