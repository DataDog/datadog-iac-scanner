package docker

import (
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// ignore is a structure that contains information about the lines that are being ignored.
type ignore struct {
	stages map[int]bool
	lines  []int
}

// newIgnore returns a new ignore struct.
func newIgnore() *ignore {
	return &ignore{
		stages: make(map[int]bool),
		lines:  make([]int, 0),
	}
}

// setIgnore marks the build stage to be ignored. Stages are counted by position
// rather than named by their FROM line, which two stages can share.
func (i *ignore) setIgnore(stage int) {
	i.stages[stage] = true
}

// ignoreBlock adds block lines to be ignored to the ignore struct.
func (i *ignore) ignoreBlock(node *parser.Node, stage int) {
	if i.stages[stage] {
		i.lines = append(i.lines, model.Range(node.StartLine, node.EndLine)...)
	}
}

// getIgnoreLines returns the lines that are being ignored.
func (i *ignore) getIgnoreLines() []int {
	return model.RemoveDuplicates(i.lines)
}

// getIgnoreComments returns lines to be ignored for each node of the dockerfile
func (i *ignore) getIgnoreComments(node *parser.Node) (ignore bool) {
	if len(node.PrevComment) == 0 {
		return false
	}

	for idx, comment := range node.PrevComment {
		switch processComment(comment) {
		case model.IgnoreLine:
			i.lines = append(i.lines, model.Range(node.StartLine-(idx+1), node.EndLine)...)
		case model.IgnoreBlock:
			i.lines = append(i.lines, node.StartLine-(idx+1))
			ignore = true
		default:
			i.lines = append(i.lines, node.StartLine-(idx+1))
		}
	}

	return
}

// processComment returns the type of comment given.
func processComment(comment string) (value model.CommentCommand) {
	commentLower := strings.ToLower(comment)

	if model.DDCommentRgxp.MatchString(commentLower) {
		commentLower = model.DDCommentRgxp.ReplaceAllString(commentLower, "")
		commands := strings.Split(strings.Trim(commentLower, "\n"), " ")
		value = model.ProcessCommands(commands)
		return
	}
	return model.CommentCommand(comment)
}
