/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestToSlug(t *testing.T) {
	tests := []struct {
		have string
		want string
	}{
		{
			have: "my rule",
			want: "my-rule",
		},
		{
			have: "MyRule",
			want: "myrule",
		},
		{
			have: "My Rule",
			want: "my-rule",
		},
	}
	for _, test := range tests {
		require.Equal(t, test.want, toSlug(test.have))
	}
}
