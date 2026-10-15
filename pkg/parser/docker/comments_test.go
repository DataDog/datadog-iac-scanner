package docker

import (
	"reflect"
	"testing"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/stretchr/testify/require"
)

// Test_newIgnore tests the newIgnore function to ensure it returns a new ignore struct with the correct values set.
func Test_newIgnore(t *testing.T) {
	tests := []struct {
		name string
		want *ignore
	}{
		{
			name: "new ignore",
			want: &ignore{
				stages: make(map[int]bool),
				lines:  make([]int, 0),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newIgnore(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newIgnore() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_ignore_setIgnore tests the setIgnore function to ensure it sets the correct values.
func Test_ignore_setIgnore(t *testing.T) {
	type fields struct {
		stages map[int]bool
		lines  []int
	}
	type args struct {
		stage int
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "set ignore",
			fields: fields{
				stages: make(map[int]bool),
				lines:  make([]int, 0),
			},
			args: args{
				stage: 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &ignore{
				stages: tt.fields.stages,
				lines:  tt.fields.lines,
			}
			i.setIgnore(tt.args.stage)
			require.True(t, i.stages[tt.args.stage])
		})
	}
}

// Test_ignore_ignoreBlock tests the ignoreBlock function to ensure it sets the correct values.
func Test_ignore_ignoreBlock(t *testing.T) {
	type fields struct {
		stages map[int]bool
		lines  []int
	}
	type args struct {
		node  *parser.Node
		stage int
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []int
	}{
		{
			name: "ignore block: should add",
			fields: fields{
				stages: map[int]bool{
					0: true,
				},
				lines: []int{1, 2, 3},
			},
			args: args{
				node: &parser.Node{
					StartLine: 5,
					EndLine:   5,
				},
				stage: 0,
			},
			want: []int{1, 2, 3, 5},
		},
		{
			name: "ignore block: should not add",
			fields: fields{
				stages: map[int]bool{
					0: true,
				},
				lines: []int{1, 2, 3},
			},
			args: args{
				node: &parser.Node{
					StartLine: 5,
					EndLine:   5,
				},
				stage: 1,
			},
			want: []int{1, 2, 3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &ignore{
				stages: tt.fields.stages,
				lines:  tt.fields.lines,
			}
			i.ignoreBlock(tt.args.node, tt.args.stage)
			got := i.getIgnoreLines()
			require.Equal(t, tt.want, got)
		})
	}
}

// Test_ignore_getIgnoreLines tests the getIgnoreLines function to ensure it returns the correct values.
func Test_ignore_getIgnoreLines(t *testing.T) {
	type fields struct {
		stages map[int]bool
		lines  []int
	}
	tests := []struct {
		name   string
		fields fields
		want   []int
	}{
		{
			name: "get ignore lines: with dups",
			fields: fields{
				stages: make(map[int]bool),
				lines:  []int{1, 1, 2, 3, 4},
			},
			want: []int{1, 2, 3, 4},
		},
		{
			name: "get ignore lines: without dups",
			fields: fields{
				stages: make(map[int]bool),
				lines:  []int{1, 2, 3, 4},
			},
			want: []int{1, 2, 3, 4},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &ignore{
				stages: tt.fields.stages,
				lines:  tt.fields.lines,
			}
			if got := i.getIgnoreLines(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ignore.getIgnoreLines() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_ignore_getIgnoreComments tests the getIgnoreComments function to ensure it returns the correct values.
func Test_ignore_getIgnoreComments(t *testing.T) {
	type fields struct {
		stages map[int]bool
		lines  []int
	}
	type args struct {
		node *parser.Node
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantIgnore bool
		wantLines  []int
	}{
		{
			name: "get ignore comments: should ignore single line",
			fields: fields{
				stages: make(map[int]bool),
				lines:  make([]int, 0),
			},
			args: args{
				node: &parser.Node{
					PrevComment: []string{"ignore-line"},
					StartLine:   3,
					EndLine:     3,
				},
			},
			wantIgnore: false,
			wantLines:  []int{2, 3},
		},
		{
			name: "get ignore comments: should ignore multi-line",
			fields: fields{
				stages: make(map[int]bool),
				lines:  make([]int, 0),
			},
			args: args{
				node: &parser.Node{
					PrevComment: []string{"ignore-line"},
					StartLine:   3,
					EndLine:     6,
				},
			},
			wantIgnore: false,
			wantLines:  []int{2, 3, 4, 5, 6},
		},
		{
			name: "get ignore comments: should ignore comment multi-line",
			fields: fields{
				stages: make(map[int]bool),
				lines:  make([]int, 0),
			},
			args: args{
				node: &parser.Node{
					PrevComment: []string{"ignore-line", "regular command"},
					StartLine:   3,
					EndLine:     6,
				},
			},
			wantIgnore: false,
			wantLines:  []int{2, 3, 4, 5, 6, 1},
		},
		{
			name: "get ignore comments: should ignore regular comment",
			fields: fields{
				stages: make(map[int]bool),
				lines:  make([]int, 0),
			},
			args: args{
				node: &parser.Node{
					PrevComment: []string{"this is a regular comment"},
					StartLine:   3,
					EndLine:     6,
				},
			},
			wantIgnore: false,
			wantLines:  []int{2},
		},
		{
			name: "get ignore comments: should return true for ignore block",
			fields: fields{
				stages: make(map[int]bool),
				lines:  make([]int, 0),
			},
			args: args{
				node: &parser.Node{
					PrevComment: []string{"ignore-block"},
					StartLine:   3,
					EndLine:     6,
				},
			},
			wantIgnore: true,
			wantLines:  []int{2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &ignore{
				stages: tt.fields.stages,
				lines:  tt.fields.lines,
			}
			if gotIgnore := i.getIgnoreComments(tt.args.node); gotIgnore != tt.wantIgnore {
				t.Errorf("ignore.getIgnoreComments() = %v, want %v", gotIgnore, tt.wantIgnore)
			}
			require.Equal(t, tt.wantLines, i.getIgnoreLines())
		})
	}
}
