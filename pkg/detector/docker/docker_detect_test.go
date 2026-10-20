package docker

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/stretchr/testify/require"
)

var OriginalData1 = `FROM alpine:3.7
RUN apk update \
	&& apk upgrade \
	&& apk add kubectl=1.20.0-r0 \
	&& rm -rf /var/cache/apk/*
ENTRYPOINT ["kubectl"]

FROM alpine:3.9
RUN apk update
RUN apk update && apk upgrade && apk add kubectl=1.20.0-r0 \
	&& rm -rf /var/cache/apk/*
ENTRYPOINT ["kubectl"]
`
var OriginalData2 = `FROM openjdk:10-jdk
VOLUME /tmp
ADD http://source.file/package.file.tar.gz /temp
RUN tar -xjf /temp/package.file.tar.gz \
	&& make -C /tmp/package.file \
	&& rm /tmp/ package.file.tar.gz
ARG JAR_FILE
ADD ${JAR_FILE} app.jar

FROM openjdk:11-jdk
VOLUME /tmp
ADD http://source.file/package.file.tar.gz /temp
RUN tar -xjf /temp/package.file.tar.gz \
	&& make -C /tmp/package.file \
	&& rm /tmp/ package.file.tar.gz
ARG JAR_FILE
ADD ${JAR_FILE} apps.jar
`

var OriginalData3 = `FROM alpine:3.7
RUN apk update \
	&& apk upgrade \
	&& apk add kubectl=1.20.0-r0 \
	&& rm -rf /var/cache/apk/*
ENTRYPOINT ["kubectl"]`

func TestPrepareDockerFileLinesLongMultiLineRun(t *testing.T) {
	t.Parallel()

	// Each continuation must end with `\` so merged segments contain embedded
	// whitespace-backslash sequences; the old regex replaced every match, not
	// just the terminal continuation marker, causing exponential growth.
	const continuationLines = 25
	var dockerfile strings.Builder
	dockerfile.WriteString("FROM alpine:3.7\nRUN true")
	for range continuationLines {
		dockerfile.WriteString(" \\\n\t&& echo step \\")
	}
	dockerfile.WriteString("\n")

	linesPtr := utils.SplitLines(dockerfile.String())
	lines := make([]string, len(*linesPtr))
	copy(lines, *linesPtr)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result := prepareDockerFileLines(lines)
		var runLine string
		for _, line := range result {
			if strings.Contains(line, "RUN true") {
				runLine = line
				break
			}
		}
		require.NotEmpty(t, runLine)
		require.Contains(t, runLine, "echo step")
		require.Less(t, len(runLine), continuationLines*20)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("prepareDockerFileLines did not finish within 2s; likely exponential string growth")
	}
}

// TestDetectDockerLine tests the functions [DetectDockerLine()] and all the methods called by them
func TestDetectDockerLine(t *testing.T) { //nolint
	testCases := []struct {
		expected  model.VulnerabilityLines
		searchKey string
		file      *model.FileMetadata
	}{
		{
			expected: model.VulnerabilityLines{
				Line:                  10,
				LineWithVulnerability: "RUN apk update && apk upgrade && apk add kubectl=1.20.0-r0 \t&& rm -rf /var/cache/apk/*",
				VulnLines: &[]model.CodeLine{
					{
						Position: 9,
						Line:     "RUN apk update",
					},
					{
						Position: 10,
						Line:     "RUN apk update && apk upgrade && apk add kubectl=1.20.0-r0 \\",
					},
					{
						Position: 11,
						Line:     "\t&& rm -rf /var/cache/apk/*",
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Col:  0,
						Line: 10,
					},
					End: model.ResourceLine{
						Col:  86,
						Line: 10,
					},
				},
			},
			searchKey: "FROM={{alpine:3.9}}.RUN={{apk update && apk upgrade && apk add kubectl=1.20.0-r0 	\u0026\u0026 rm -rf /var/cache/apk/*}}",
			file: &model.FileMetadata{
				ScanID:            "Test2",
				ID:                "Test2",
				Kind:              model.KindDOCKER,
				OriginalData:      OriginalData1,
				LinesOriginalData: utils.SplitLines(OriginalData1),
			},
		},
		{
			expected: model.VulnerabilityLines{
				Line:                  17,
				LineWithVulnerability: "ADD ${JAR_FILE} apps.jar",
				VulnLines: &[]model.CodeLine{
					{
						Position: 16,
						Line:     "ARG JAR_FILE",
					},
					{
						Position: 17,
						Line:     "ADD ${JAR_FILE} apps.jar",
					},
					{
						Position: 18,
						Line:     "",
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Col:  0,
						Line: 17,
					},
					End: model.ResourceLine{
						Col:  24,
						Line: 17,
					},
				},
			},
			searchKey: "FROM=openjdk:11-jdk.{{ADD ${JAR_FILE} apps.jar}}",
			file: &model.FileMetadata{
				ScanID:            "Test3",
				ID:                "Test3",
				Kind:              model.KindDOCKER,
				OriginalData:      OriginalData2,
				LinesOriginalData: utils.SplitLines(OriginalData2),
			},
		},
		{
			expected: model.VulnerabilityLines{
				Line:                  6,
				LineWithVulnerability: "ENTRYPOINT [\"kubectl\"]",
				VulnLines: &[]model.CodeLine{
					{
						Position: 4,
						Line:     `	&& apk add kubectl=1.20.0-r0 \`,
					},
					{
						Position: 5,
						Line:     "	&& rm -rf /var/cache/apk/*",
					},
					{
						Position: 6,
						Line:     `ENTRYPOINT ["kubectl"]`,
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Col:  0,
						Line: 6,
					},
					End: model.ResourceLine{
						Col:  22,
						Line: 6,
					},
				},
			},
			searchKey: "FROM={{alpine:3.7}}.ENTRYPOINT[kubectl]",
			file: &model.FileMetadata{
				ScanID:            "Test",
				ID:                "Test",
				Kind:              model.KindDOCKER,
				OriginalData:      OriginalData3,
				LinesOriginalData: utils.SplitLines(OriginalData3),
			},
		},
	}
	ctx := context.Background()
	for i, testCase := range testCases {
		detector := DetectKindLine{}
		t.Run(fmt.Sprintf("detectDockerLine-%d", i), func(t *testing.T) {
			v := detector.DetectLine(ctx, testCase.file, testCase.searchKey, 3)
			require.Equal(t, testCase.expected, v)
		})
	}
}

// Dockerfile instructions are case-insensitive, and search keys spell them in
// uppercase whatever the file uses.
func TestDetectDockerLine_LowercaseInstructions(t *testing.T) {
	data := "from alpine:3.19\nrun apk add curl\nexpose 22\n"
	file := &model.FileMetadata{
		ID:                "lowercase",
		Kind:              model.KindDOCKER,
		OriginalData:      data,
		LinesOriginalData: utils.SplitLines(data),
	}
	for searchKey, line := range map[string]int{
		"FROM={{alpine:3.19}}":                      1,
		"FROM={{alpine:3.19}}.RUN={{apk add curl}}": 2,
		"FROM={{alpine:3.19}}.{{expose 22}}":        3,
		"FROM={{alpine:3.19}}.{{EXPOSE 22}}":        3,
	} {
		got := DetectKindLine{}.DetectLine(context.Background(), file, searchKey, 3)
		require.Equal(t, line, got.Line, searchKey)
	}
	got := DetectKindLine{}.DetectLine(context.Background(), file, "FROM={{alpine:3.19}}.{{expose 22}}", 3)
	require.Equal(t, "expose 22", got.LineWithVulnerability, "the reported line keeps the file's spelling")

	for _, tt := range []struct {
		name, data, key, text string
		line                  int
	}{
		{"copy heredoc", "FROM alpine\nCOPY <<EOF /tmp/config\nexpose 22\nEOF\nEXPOSE 22\n", "FROM={{alpine}}.{{EXPOSE 22}}", "EXPOSE 22", 5},
		{"run heredoc", "FROM alpine\nRUN cat <<EOF > /x\nfrom busybox\nEOF\nFROM busybox\n", "FROM={{busybox}}", "FROM busybox", 5},
		{"bracket value", "FROM alpine\nRUN add user --disabled-password app\n", "FROM={{alpine}}.{{add user}}", "RUN add user --disabled-password app", 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file := &model.FileMetadata{Kind: model.KindDOCKER, OriginalData: tt.data, LinesOriginalData: utils.SplitLines(tt.data)}
			got := DetectKindLine{}.DetectLine(t.Context(), file, tt.key, 3)
			require.Equal(t, tt.line, got.Line)
			require.Equal(t, tt.text, got.LineWithVulnerability)
		})
	}
}
