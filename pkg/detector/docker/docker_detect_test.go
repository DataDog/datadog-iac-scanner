package docker

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	dockersource "github.com/DataDog/datadog-iac-scanner/pkg/dockerfile"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	dockerparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/docker"
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
		result := dockersource.InstructionLines(lines)
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
		{"quoted instruction before real instruction", "FROM alpine\nRUN echo \"RUN apt-get update\"\nrun apt-get update\n", "{{run apt-get update}}", "run apt-get update", 3},
		{"instruction before quoted argument", "FROM alpine\nrun apt-get update\nRUN echo \"run apt-get update\"\n", "{{run apt-get update}}", "run apt-get update", 2},
		{"uncached uppercase with lowercase key", "FROM alpine\nRUN echo hi\n", "FROM={{alpine}}.{{run echo hi}}", "RUN echo hi", 2},
		{"keyword inside COPY argument", "FROM alpine\ncopy ./COPYING /app\n", "FROM={{alpine}}.COPY={{./COPYING}}", "copy ./COPYING /app", 2},
		{"keyword inside RUN argument", "FROM alpine\nrun echo RUNNING\n", "FROM={{alpine}}.RUN={{echo RUNNING}}", "run echo RUNNING", 2},
		{"adjacent continuation", "FROM alpine\nRUN echo ok &&\\\n echo hidden\n", "FROM={{alpine}}.RUN={{echo hidden}}", "RUN echo ok && echo hidden", 2},
		{"trailing continuation whitespace", "FROM alpine\nrun echo ok \\  \n echo hidden\n", "FROM={{alpine}}.RUN={{echo hidden}}", "run echo ok  echo hidden", 2},
		{"backtick continuation", "# escape=`\nFROM alpine\nrun echo ok `\n echo hidden\n", "FROM={{alpine}}.RUN={{echo hidden}}", "run echo ok  echo hidden", 3},
		{"uppercase FROM and lowercase RUN", "FROM alpine:3.19\nrun apk add curl\n", "FROM={{alpine:3.19}}.RUN={{apk add curl}}", "run apk add curl", 2},
		{"uppercase FROM and mixed-case RUN", "FROM alpine:3.19\nRuN apk add curl\n", "FROM={{alpine:3.19}}.RUN={{apk add curl}}", "RuN apk add curl", 2},
		{"later lowercase instruction", "FROM alpine:3.19\nRUN apk add curl\nexpose 22\n", "FROM={{alpine:3.19}}.RUN={{apk add curl}}.{{EXPOSE 22}}", "expose 22", 3},
		{"lowercase FROM and uppercase RUN", "from alpine:3.19\nRUN apk add curl\n", "FROM={{alpine:3.19}}.RUN={{apk add curl}}", "RUN apk add curl", 2},
		{"bracket value before lowercase instruction", "FROM alpine\nRUN add user --disabled-password app\nexpose 22\n", "FROM={{alpine}}.{{add user}}.{{EXPOSE 22}}", "expose 22", 3},
		{"lowercase instructions with bracket value", "from alpine\nrun add user --disabled-password app\n", "FROM={{alpine}}.{{add user}}", "run add user --disabled-password app", 2},
		{"healthcheck none", "FROM alpine\nhealthcheck none\n", "FROM={{alpine}}.{{HEALTHCHECK NONE}}", "healthcheck none", 2},
		{"lowercase healthcheck", "FROM alpine\nhealthcheck cmd curl localhost\n", "FROM={{alpine}}.{{HEALTHCHECK CMD curl localhost}}", "healthcheck cmd curl localhost", 2},
		{"quoted nested instruction before real instruction", "FROM alpine\nHEALTHCHECK CMD echo \"CMD curl localhost\"\nhealthcheck cmd curl localhost\n", "FROM={{alpine}}.HEALTHCHECK={{cmd curl localhost}}", "healthcheck cmd curl localhost", 3},
		{"healthcheck flags", "FROM alpine\nhealthcheck --interval=5s cmd curl localhost\n", "FROM={{alpine}}.HEALTHCHECK={{CMD curl localhost}}", "healthcheck --interval=5s cmd curl localhost", 2},
		{"lowercase onbuild", "FROM alpine\nonbuild run echo hello\n", "FROM={{alpine}}.{{ONBUILD RUN echo hello}}", "onbuild run echo hello", 2},
		{"mixed nested instruction", "FROM alpine\nOnBuIlD rUn echo hello\n", "FROM={{alpine}}.ONBUILD={{RUN echo hello}}", "OnBuIlD rUn echo hello", 2},
		{"keyword-looking value is case sensitive", "FROM alpine\nrun echo RUN\n", "FROM={{alpine}}.RUN={{run}}", "FROM alpine", 1},
		{"literal value case is significant", "FROM alpine\nrun echo CMD\nrun echo cmd\n", "FROM={{alpine}}.RUN={{echo cmd}}", "run echo cmd", 3},
		{"lowercase heredoc", "from alpine\ncopy <<EOF /tmp/config\nEXPOSE 22\nEOF\nexpose 22\n", "FROM={{alpine}}.{{EXPOSE 22}}", "expose 22", 5},
		{"lowercase FROM heredoc", "from alpine\nrun cat <<EOF > /x\nFROM busybox\nEOF\nfrom busybox\n", "FROM={{busybox}}", "from busybox", 5},
		{"quoted multiple heredocs", "FROM alpine\nCOPY <<'FIRST' <<SECOND /tmp/\nEXPOSE 22\nFIRST\nEXPOSE 22\nSECOND\nexpose 22\n", "FROM={{alpine}}.{{EXPOSE 22}}", "expose 22", 7},
		{"indented heredoc", "FROM alpine\nRUN cat <<-EOF > /x\n\tFROM busybox\n\tEOF\nfrom busybox\n", "FROM={{busybox}}", "from busybox", 5},
		{"copy heredoc", "FROM alpine\nCOPY <<EOF /tmp/config\nexpose 22\nEOF\nEXPOSE 22\n", "FROM={{alpine}}.{{EXPOSE 22}}", "EXPOSE 22", 5},
		{"run heredoc", "FROM alpine\nRUN cat <<EOF > /x\nfrom busybox\nEOF\nFROM busybox\n", "FROM={{busybox}}", "FROM busybox", 5},
		{"literal keyword value is case sensitive", "FROM alpine\nRUN ADD user\n", "FROM={{alpine}}.{{add user}}", "FROM alpine", 1},
		{"bracket value", "FROM alpine\nRUN add user --disabled-password app\n", "FROM={{alpine}}.{{add user}}", "RUN add user --disabled-password app", 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, docs, _, _, err := (&dockerparser.Parser{}).Parse(t.Context(), []byte(tt.data), "Dockerfile", false, 0)
			require.NoError(t, err)
			for mode, document := range map[string]model.Document{"parsed": docs[0], "line info": docs[0], "raw": nil, "raw uncached": nil} {
				t.Run(mode, func(t *testing.T) {
					file := &model.FileMetadata{Kind: model.KindDOCKER, OriginalData: tt.data, Document: document}
					if mode == "line info" {
						file.Document = nil
						file.LineInfoDocument = document
					}
					if mode == "raw uncached" {
						file.LinesOriginalData = utils.SplitLines(tt.data)
					} else {
						file.SetLazyLines()
					}
					got := DetectKindLine{}.DetectLine(t.Context(), file, tt.key, 3)
					require.Equal(t, tt.line, got.Line)
					require.Equal(t, tt.text, got.LineWithVulnerability)
					require.Equal(t, tt.line, got.VulnerablilityLocation.Start.Line)
					require.Equal(t, tt.line, got.VulnerablilityLocation.End.Line)
				})
			}
		})
	}
}

func TestDetectDockerLine_DocumentSchemaDoesNotControlSource(t *testing.T) {
	data := "from alpine\nCOPY <<EOF /tmp/config\nEXPOSE 22\nEOF\nexpose 22\n"
	file := &model.FileMetadata{
		Kind:         model.KindDOCKER,
		OriginalData: data,
		Document: model.Document{"command": map[string]interface{}{
			"alpine": []interface{}{
				map[string]interface{}{"_dd_line": float64(3)},
				map[string]interface{}{},
			},
		}},
	}
	file.SetLazyLines()
	got := DetectKindLine{}.DetectLine(t.Context(), file, "FROM={{alpine}}.{{EXPOSE 22}}", 3)
	require.Equal(t, 5, got.Line, "document field names and incomplete metadata do not control source locations")
	require.Equal(t, "expose 22", got.LineWithVulnerability)
}
