/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"strings"

	"github.com/zclconf/go-cty/cty"
)

// canonicalInputsKey keys inputs without memoizing collection digests.
func canonicalInputsKey(inputs map[string]cty.Value) inputsDigest {
	return (*keyMemo)(nil).inputsKey(inputs)
}

type builderSink struct{ b *strings.Builder }

func (s builderSink) WriteString(str string) { s.b.WriteString(str) }

// encodeCtyForKey encodes a cty.Value to the string a cache key digests.
func encodeCtyForKey(v cty.Value) string {
	var b strings.Builder
	(*keyMemo)(nil).writeValue(builderSink{&b}, v)
	return b.String()
}
