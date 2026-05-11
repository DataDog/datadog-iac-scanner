package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetQueryID(t *testing.T) {
	type QueryIDs struct {
		queryID       string
		legacyQueryID string
	}
	tests := []struct {
		have QueryIDs
		want string
	}{
		{
			have: QueryIDs{
				queryID:       "platform-cloudProvider-rule",
				legacyQueryID: "b2c3d4e5-f6a7-48b9-c0d1-e2f3a4b5c6d7",
			},
			want: "b2c3d4e5-f6a7-48b9-c0d1-e2f3a4b5c6d7",
		},
		{
			have: QueryIDs{
				queryID:       "platform-cloudProvider-rule",
				legacyQueryID: "Undefined",
			},
			want: "platform-cloudProvider-rule",
		},
		{
			have: QueryIDs{
				queryID:       "platform-cloudProvider-rule",
				legacyQueryID: "",
			},
			want: "",
		},
		{
			have: QueryIDs{
				queryID:       "",
				legacyQueryID: "",
			},
			want: "",
		},
		{
			have: QueryIDs{
				queryID:       "platform-cloudProvider-rule",
				legacyQueryID: "undefined",
			},
			want: "undefined",
		},
	}

	for _, test := range tests {
		require.Equal(t, test.want, ChooseQueryID(test.have.queryID, test.have.legacyQueryID))
	}
}
