package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMap_MergeMaps(t *testing.T) {
	tests := []struct {
		name string
		map1 map[string]interface{}
		map2 map[string]interface{}
		want map[string]interface{}
	}{
		{
			name: "should merge second map on the first",
			map1: map[string]interface{}{
				"test": true,
			},
			map2: map[string]interface{}{
				"kics": true,
			},
			want: map[string]interface{}{
				"test": true,
				"kics": true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			MergeMaps(test.map1, test.map2)
			require.Equal(t, test.want, test.map1)
		})
	}
}
