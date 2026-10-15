package engine

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const profileTestLibrary = `package generic.common

import rego.v1

all_pairs := {t | some doc in input.document; some t in doc.resource.aws_iam_user}

uses_pairs(x) if x in all_pairs
`

func TestQueryLayerProfile(t *testing.T) {
	libs := librarySummaries(profileTestLibrary)
	tests := []struct {
		name  string
		query string
		all   bool
		types []string
	}{
		{
			name: "literal types",
			query: `package datadog
import rego.v1
DatadogPolicy contains r if {
	b := input.document[i].resource.aws_s3_bucket[n]
	r := {"documentId": input.document[i].id, "n": n, "b": b}
}`,
			types: []string{"aws_s3_bucket"},
		},
		{
			name: "type held in a variable that nothing constrains",
			query: `package datadog
import rego.v1
skip := {"a"}
DatadogPolicy contains r if {
	some i, n, rt
	b := input.document[i].resource[rt][n]
	not rt in skip
	r := {"documentId": input.document[i].id, "n": n, "b": b}
}`,
			all: true,
		},
		{
			name: "library rule used by its bare name",
			query: `package datadog
import data.generic.common as common_lib
import rego.v1
DatadogPolicy contains r if {
	u := input.document[i].resource.aws_iam_user[n]
	common_lib.uses_pairs(n)
	r := {"documentId": input.document[i].id, "n": n, "u": u}
}`,
			types: []string{"aws_iam_user"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := queryLayerProfile(tt.query, libs)
			require.Equal(t, tt.all, p.all)
			if !tt.all {
				got := []string{}
				for k := range p.types {
					got = append(got, k)
				}
				require.ElementsMatch(t, tt.types, got)
			}
		})
	}
}
