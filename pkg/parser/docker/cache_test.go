package docker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPackageCacheMountFacts(t *testing.T) {
	tests := []struct {
		name       string
		dockerfile string
		call       int
		known      bool
		value      bool
	}{
		{
			name:       "no cache mount is known false without HOME",
			dockerfile: "FROM alpine\nRUN pip install example\n",
			call:       0, known: true, value: false,
		},
		{
			name:       "apt lists without cache mounts are not covered",
			dockerfile: "FROM debian\nRUN apt-get install curl\n",
			call:       0, known: true, value: false,
		},
		{
			name:       "apt lists path can be configured by the base image",
			dockerfile: "FROM debian\nRUN --mount=type=cache,target=/var/lib/apt/lists apt-get install curl\n",
			call:       0, known: false, value: false,
		},
		{
			name:       "USER root does not establish base image cache settings",
			dockerfile: "FROM alpine\nUSER root\nRUN --mount=type=cache,target=/root/.cache/pip pip install example\n",
			call:       0, known: false, value: false,
		},
		{
			name:       "dynamic setup may change cache environment",
			dockerfile: "FROM alpine\nUSER root\nRUN --mount=type=cache,target=/root/.cache/pip $SETUP; pip install example\n",
			call:       1, known: false, value: false,
		},
		{
			name:       "unknown user leaves pip path unknown",
			dockerfile: "FROM alpine\nRUN --mount=type=cache,target=/root/.cache/pip pip install example\n",
			call:       0, known: false, value: false,
		},
		{
			name:       "unknown target leaves coverage unknown",
			dockerfile: "FROM alpine\nUSER root\nRUN --mount=type=cache,target=$CACHE pip install example\n",
			call:       0, known: false, value: false,
		},
		{
			name:       "explicit pip cache directory",
			dockerfile: "FROM alpine\nRUN --mount=type=cache,target=/opt/pip-cache pip install --cache-dir=/opt/pip-cache example\n",
			call:       0, known: true, value: true,
		},
		{
			name:       "unknown options can replace the default cache path",
			dockerfile: "FROM alpine\nRUN --mount=type=cache,target=/var/cache/apk apk add $FLAGS example\n",
			call:       0, known: false, value: false,
		},
		{
			name:       "unresolved configured cache path",
			dockerfile: "FROM alpine\nRUN --mount=type=cache,target=/opt/pip-cache pip install --cache-dir=$CACHE_DIR example\n",
			call:       0, known: false, value: false,
		},
		{
			name:       "later ENV shadows earlier cache path",
			dockerfile: "FROM alpine\nENV PIP_CACHE_DIR=/old-cache\nENV PIP_CACHE_DIR=/new-cache\nRUN --mount=type=cache,target=/new-cache pip install example\n",
			call:       0, known: true, value: true,
		},
		{
			name:       "explicit yarn cache environment",
			dockerfile: "FROM alpine\nENV YARN_CACHE_FOLDER=/work/yarn-cache\nRUN --mount=type=cache,target=/work/yarn-cache yarn add example\n",
			call:       0, known: true, value: true,
		},
		{
			name:       "relative explicit yarn path with cwd override is uncertain",
			dockerfile: "FROM alpine\nWORKDIR /work\nRUN --mount=type=cache,target=/work/cache yarn --cache-folder=cache --cwd=/other add example\n",
			call:       0, known: false, value: false,
		},
		{
			name:       "one of multiple possible yarn caches is insufficient",
			dockerfile: "FROM alpine\nRUN --mount=type=cache,target=/root/.cache/yarn yarn add example\n",
			call:       0, known: false, value: false,
		},
		{
			name:       "environment cache path with inherited stage context",
			dockerfile: "FROM alpine AS base\nENV PIP_CACHE_DIR=/work/cache\nWORKDIR /work\nUSER app\nFROM base\nRUN --mount=type=cache,target=/work/cache pip install example\n",
			call:       0, known: true, value: true,
		},
		{
			name:       "shell environment mutation makes path uncertain",
			dockerfile: "FROM alpine\nUSER root\nRUN --mount=type=cache,target=/root/.cache/pip HOME=/tmp pip install example\n",
			call:       0, known: false, value: false,
		},
		{
			name:       "rpm setopt cache directory is unmodeled",
			dockerfile: "FROM alpine\nRUN --mount=type=cache,target=/var/cache/dnf dnf --setopt=cachedir=/tmp/cache install example\n",
			call:       0, known: false, value: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			analysis := parseAnalysis(t, test.dockerfile)
			var run *Execution
			for i := range analysis.Instructions {
				if analysis.Instructions[i].Execution != nil {
					run = analysis.Instructions[i].Execution
				}
			}
			require.NotNil(t, run)
			require.Len(t, run.PackageCacheMounts, len(run.Calls))
			fact := run.PackageCacheMounts[test.call]
			require.NotNil(t, fact)
			require.Equal(t, test.known, fact.Known)
			require.Equal(t, test.value, fact.Value)
		})
	}
}

func TestPackageCacheMountFactsAlignWithCalls(t *testing.T) {
	analysis := parseAnalysis(t, `FROM alpine
USER root
RUN --mount=type=cache,target=/root/.cache/pip echo before && pip install example --cache-dir=/root/.cache/pip && apk --cache-dir=/var/cache/apk add curl
`)
	var run *Execution
	for i := range analysis.Instructions {
		if analysis.Instructions[i].Execution != nil {
			run = analysis.Instructions[i].Execution
		}
	}
	require.NotNil(t, run)
	require.Len(t, run.PackageCacheMounts, len(run.Calls))
	require.Nil(t, run.PackageCacheMounts[0])
	require.Equal(t, &BoolValue{Known: true, Value: true}, run.PackageCacheMounts[1])
	require.Equal(t, &BoolValue{Known: true, Value: false}, run.PackageCacheMounts[2])
}

func TestPackageCacheMountExpansionFailureStaysUnknown(t *testing.T) {
	analysis := parseAnalysis(t, `FROM alpine
SHELL ["/bin/sh", "-c"]
ARG CACHE_UID=1000
RUN --mount=type=cache,target=/cache/pip,uid=$CACHE_UID pip install --cache-dir=/cache/pip flask
`)
	run := analysis.Instructions[3]
	require.False(t, run.ParseOK)
	require.Contains(t, run.Error, "invalid value $CACHE_UID for uid")
	require.Empty(t, run.Mounts)
	require.NotNil(t, run.Execution)
	require.Len(t, run.Execution.PackageCacheMounts, len(run.Execution.Calls))
	require.Len(t, run.Execution.PackageCacheMounts, 1)
	require.Equal(t, &BoolValue{}, run.Execution.PackageCacheMounts[0])
}
