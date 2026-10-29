/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTailBufferKeepsTheEnd(t *testing.T) {
	b := &tailBuffer{limit: 8}
	_, _ = b.Write([]byte("0123"))
	assert.Equal(t, "0123", b.String())
	for i := 0; i < 10; i++ {
		_, _ = b.Write([]byte("abc"))
		assert.LessOrEqual(t, len(b.buf), 2*b.limit, "trimmed once twice the limit")
	}
	_, _ = b.Write([]byte("XYZ"))
	assert.Equal(t, "bcabcXYZ", b.String())
	_, _ = b.Write([]byte(strings.Repeat("z", 30)))
	assert.Equal(t, strings.Repeat("z", 8), b.String())
}
