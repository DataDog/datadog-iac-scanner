package dockerfile

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The reader makes traversal observable, including BuildKit's buffered reads.
type countedReader struct {
	reader *strings.Reader
	read   int
}

func (r *countedReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	r.read += n
	return n, err
}

func TestHasFromStopsAtHeader(t *testing.T) {
	for _, prefix := range []string{"FROM alpine\n", "ARG X=1\nFROM alpine\n", "package main\n"} {
		source := prefix + strings.Repeat("binary\x00payload\n", 100000)
		reader := &countedReader{reader: strings.NewReader(source)}
		require.Equal(t, strings.Contains(prefix, "FROM"), HasFrom(reader))
		require.Less(t, reader.read, 8192, "the body is not parsed or traversed")
	}
}

func TestHasFromDirectivesAndContinuations(t *testing.T) {
	for _, source := range []string{
		"\ufeff# syntax=docker/dockerfile:1\r\nARG X=1\r\nFROM alpine\r\n",
		"# escape=`\nARG IMAGE=`\n# comment\n alpine\nFROM `\n $IMAGE\n",
		"ARG IMAGE=\\  \n\n# comment\n alpine\nFROM \\\n $IMAGE\n",
		"ARG\tIMAGE=alpine\nFROM\talpine\n",
	} {
		require.True(t, HasFrom(strings.NewReader(source)), source)
	}
	for _, source := range []string{
		"ARG IMAGE=\\\nFROM alpine\n", "ARG X\nRUN echo hi\nFROM alpine\n", "FROM\n",
		"# escape=x\nFROM alpine\n", strings.Repeat("\x00", 100000),
	} {
		require.False(t, HasFrom(strings.NewReader(source)), source[:min(100, len(source))])
	}
}
