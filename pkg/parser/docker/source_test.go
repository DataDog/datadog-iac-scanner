package docker

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/klauspost/compress/s2"
	"github.com/stretchr/testify/require"
)

// Encoded documents must own tight storage even when the scratch buffer was
// sized for a much larger previous document and is reused by later parses.
func TestSourceEncodingOwnership(t *testing.T) {
	for _, size := range []int{32, 4096, 1 << 20} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			original := bytes.Repeat([]byte("{document: source}\n"), size)
			encoded := encodeSourceDocument(original)
			_ = encodeSourceDocument(bytes.Repeat([]byte("other"), size))
			decoded, err := s2.Decode(nil, encoded)
			require.NoError(t, err)
			require.Equal(t, original, decoded)
			require.LessOrEqual(t, cap(encoded), 2*len(encoded), "keep compressed capacity, not worst-case input capacity")
		})
	}
}

func BenchmarkSourceEncoding(b *testing.B) {
	document := bytes.Repeat([]byte(`{"Original":"RUN echo hi","Value":["echo hi"]}`), 2000)
	b.SetBytes(int64(len(document)))
	b.ReportAllocs()
	for b.Loop() {
		_ = encodeSourceDocument(document)
	}
}
