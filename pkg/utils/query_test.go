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

func TestToSlug(t *testing.T) {
	tests := []struct {
		name string
		have string
		want string
	}{
		{
			name: "Regular folder name",
			have: "test_query",
			want: "test-query",
		},
		{
			name: "Idempotency",
			have: "test-query",
			want: "test-query",
		},
		{
			name: "Realistic typo in the middle of a folder name",
			have: "test__query",
			want: "test-query",
		},
		{
			name: "Realistic trailing typo of a folder name",
			have: "test_query_",
			want: "test-query",
		},
		{
			have: "",
			want: "",
		},
	}

	for _, test := range tests {
		require.Equal(t, test.want, ToSlug(test.have))
	}
}

func TestToID(t *testing.T) {
	type QueryInfos struct {
		platform string
		provider string
		slug     string
	}
	tests := []struct {
		have QueryInfos
		want string
	}{
		{
			have: QueryInfos{
				platform: "cicd",
				provider: "github",
				slug:     "anonymous-definition",
			},
			want: "cicd-github-anonymous-definition",
		},
	}

	for _, test := range tests {
		require.Equal(t, test.want, ToID(test.have.platform, test.have.provider, test.have.slug))
	}
}
