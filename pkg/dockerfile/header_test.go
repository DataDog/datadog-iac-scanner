/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package dockerfile

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHasFrom(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "simple FROM without RUN",
			content: "FROM scratch\nCOPY app /app\nENTRYPOINT [\"/app\"]\n",
			want:    true,
		},
		{
			name:    "lowercase from",
			content: "from alpine:3.20\n",
			want:    true,
		},
		{
			name:    "leading comments and syntax directive",
			content: "# syntax=docker/dockerfile:1\n# build image\n\nFROM ubuntu:24.04\n",
			want:    true,
		},
		{
			name:    "leading ARGs before FROM",
			content: "ARG BASE=alpine:3.20\nARG TAG=latest\nFROM ${BASE}\n",
			want:    true,
		},
		{
			name:    "UTF-8 BOM and CRLF",
			content: "\ufeff# comment\r\nARG IMG=alpine\r\nFROM $IMG\r\n",
			want:    true,
		},
		{
			name:    "FROM with platform flag",
			content: "FROM --platform=$BUILDPLATFORM golang:1.22 AS build\n",
			want:    true,
		},
		{
			name:    "backslash line-continued keyword",
			content: "F\\\nROM alpine\n",
			want:    true,
		},
		{
			name:    "backtick escape directive and multiline ARG",
			content: "# escape=`\nARG BASE=`\nalpine:3.20\nFROM ${BASE}\n",
			want:    true,
		},
		{
			name:    "valid heredoc body",
			content: "FROM alpine\nRUN <<EOF\necho hello\nEOF\n",
			want:    true,
		},
		{
			name:    "empty content",
			content: "",
			want:    false,
		},
		{
			name:    "comments and whitespace only",
			content: "# just a comment\n   \n# another\n",
			want:    false,
		},
		{
			name:    "ARG only without FROM",
			content: "ARG FOO=bar\nARG BAZ=qux\n",
			want:    false,
		},
		{
			name:    "bare FROM without image",
			content: "FROM\n",
			want:    false,
		},
		{
			name:    "FROM with flag only and no image",
			content: "FROM --platform=linux/amd64\n",
			want:    false,
		},
		{
			name:    "prose containing FROM and RUN",
			content: "Release notes:\nPull FROM the registry and RUN tests.\n",
			want:    false,
		},
		{
			name:    "shell script",
			content: "#!/bin/sh\necho FROM alpine\n",
			want:    false,
		},
		{
			name:    "JSON document",
			content: "{\"from\": \"alpine\", \"run\": \"echo hi\"}\n",
			want:    false,
		},
		{
			name:    "binary bytes with NUL",
			content: "\x1f\x8b\x08\x00\x00\x00\x00\x00FROM alpine\n",
			want:    false,
		},
		{
			name:    "non-ARG instruction before FROM",
			content: "RUN echo nope\nFROM alpine\n",
			want:    false,
		},
		{
			name:    "malformed body after valid FROM",
			content: "FROM alpine\nRUN <<EOF\nunterminated heredoc\n",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, HasFrom([]byte(tt.content)))
		})
	}
}
