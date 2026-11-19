package docker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFinalizeCopyStageRelations(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantSources []int
	}{
		{
			name: "forward named stage is resolved case insensitively",
			content: `FROM alpine AS build
COPY --from=BUILDER /artifact /artifact
FROM alpine AS builder
RUN true
`,
			wantSources: []int{1},
		},
		{
			name: "forward and current numeric stage indices resolve",
			content: `FROM alpine
COPY --from=1 /forward /forward
COPY --from=0 /current /current
FROM alpine
RUN true
`,
			wantSources: []int{1, 0},
		},
		{
			name: "past numeric and named stage resolve",
			content: `FROM alpine AS base
FROM alpine
COPY --from=0 /past-index /past-index
COPY --from=base /past-name /past-name
`,
			wantSources: []int{0, 0},
		},
		{
			name: "external and invalid numeric sources remain non-stage",
			content: `FROM alpine
COPY --from=registry.example/image:tag /external /external
COPY --from=9 /invalid /invalid
`,
			wantSources: []int{-1, -1},
		},
		{
			name: "unknown dynamic source remains unresolved",
			content: `FROM alpine
ARG BUILD_STAGE
COPY --from=$BUILD_STAGE /dynamic /dynamic
`,
			wantSources: []int{-1},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			analysis := parseAnalysis(t, test.content)
			finalizeCopyStageRelations(analysis)

			var got []int
			for _, instruction := range analysis.Instructions {
				if instruction.Copy != nil && instruction.Kind == "copy" {
					got = append(got, instruction.Copy.SourceStage)
				}
			}
			require.Equal(t, test.wantSources, got)
		})
	}
}

func TestFinalizeCopyStageRelationsLeavesUnknownFromUnchanged(t *testing.T) {
	analysis := parseAnalysis(t, `FROM alpine AS base
ARG BUILD_STAGE
COPY --from=$BUILD_STAGE /dynamic /dynamic
`)
	copyFact := analysis.Instructions[2].Copy
	require.NotNil(t, copyFact)
	require.NotNil(t, copyFact.From)
	require.False(t, copyFact.From.Known)
	require.Equal(t, -1, copyFact.SourceStage)

	finalizeCopyStageRelations(analysis)

	require.Equal(t, -1, copyFact.SourceStage)
	require.False(t, copyFact.From.Known)
}

func TestFinalizeCopyStageRelationsUsesLastDuplicateAlias(t *testing.T) {
	analysis := parseAnalysis(t, `FROM alpine AS build
FROM alpine AS builder
FROM alpine AS BUILD
COPY --from=build /source /destination
`)
	finalizeCopyStageRelations(analysis)
	require.Equal(t, 2, analysis.Instructions[3].Copy.SourceStage)
}
