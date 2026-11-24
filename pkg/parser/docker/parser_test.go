package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	iacparser "github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/stretchr/testify/require"
)

// TestParser_GetKind tests the functions [GetKind()] and all the methods called by them
func TestParser_GetKind(t *testing.T) {
	p := &Parser{}
	require.Equal(t, model.KindDOCKER, p.GetKind())
}

// TestParser_SupportedExtensions tests the functions [SupportedExtensions()] and all the methods called by them
func TestParser_SupportedExtensions(t *testing.T) {
	p := &Parser{}
	require.Equal(t, []string{"Dockerfile", ".dockerfile", ".ubi8", ".debian", "possibleDockerfile"}, p.SupportedExtensions())
}

// TestParser_SupportedExtensions tests the functions [SupportedTypes()] and all the methods called by them
func TestParser_SupportedTypes(t *testing.T) {
	p := &Parser{}
	require.Equal(t, map[string]bool{"dockerfile": true}, p.SupportedTypes())
}

func TestIsDockerfile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"simple FROM without RUN", "FROM scratch\nCOPY app /app\n", true},
		{"lowercase from", "from alpine:3.20\n", true},
		{"leading comments and directives", "# syntax=docker/dockerfile:1\n# comment\n\nFROM ubuntu:24.04\n", true},
		{"leading ARGs before FROM", "ARG BASE=alpine:3.20\nARG TAG=latest\nFROM ${BASE}\n", true},
		{"UTF-8 BOM and CRLF", "\ufeff# comment\r\nARG IMG=alpine\r\nFROM $IMG\r\n", true},
		{"FROM with platform flag", "FROM --platform=$BUILDPLATFORM golang:1.22 AS build\n", true},
		{"backslash line-continued keyword", "F\\\nROM alpine\n", true},
		{"backtick escape directive and multiline ARG", "# escape=`\nARG BASE=`\nalpine:3.20\nFROM ${BASE}\n", true},
		{"valid heredoc body", "FROM alpine\nRUN <<EOF\necho hello\nEOF\n", true},
		{"empty content", "", false},
		{"comments only", "# just a comment\n   \n", false},
		{"ARG only without FROM", "ARG FOO=bar\n", false},
		{"bare FROM without image", "FROM\n", false},
		{"FROM with flag only", "FROM --platform=linux/amd64\n", false},
		{"prose containing FROM and RUN", "Release notes:\nPull FROM the registry and RUN tests.\n", false},
		{"shell script", "#!/bin/sh\necho FROM alpine\n", false},
		{"JSON document", "{\"from\": \"alpine\", \"run\": \"echo hi\"}\n", false},
		{"non-ARG instruction before FROM", "RUN echo nope\nFROM alpine\n", false},
		{"unterminated heredoc", "FROM alpine\nRUN <<EOF\nunterminated\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, IsDockerfile([]byte(tt.content)))
		})
	}
}

// TestParser_Parse tests the functions [Parse()] and all the methods called by them
func TestParser_Parse(t *testing.T) {
	ctx := context.Background()
	p := &Parser{}
	sample := []string{
		`
		FROM openjdk:11-jdk
		VOLUME /tmp
		ADD http://source.file/package.file.tar.gz /temp
		RUN tar --xjf /temp/package.file.tar.gz \
  			&& make -C /tmp/package.file \
  			&& rm /tmp/ package.file.tar.gz
		ARG JAR_FILE
		ADD ${JAR_FILE} app.jar
		ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]
		`,
		`
		FROM ubuntu:xenial
		RUN echo hi > /etc/hi.conf
		# dd-iac-scan ignore-line
		CMD ["echo"]
		HEALTHCHECK --retries=5 CMD echo hi
		ONBUILD ADD foo bar
		ONBUILD RUN ["cat", "bar"]

		FROM ubuntu:xenial2
		RUN echo hi > /etc/hi.conf
		CMD ["echo"]
		`,
		`
		# dd-iac-scan ignore-block
		FROM golang:alpine
		ENV CGO_ENABLED=0
		WORKDIR /app
		COPY . .
		RUN apk add --no-cache git \
     		&& git config \
      		--global \
      		url."https://${GIT_USER}:${GIT_TOKEN}@github.com".insteadOf \
      		"https://github.com"
		`,
		`
		ARG BASE_IMAGE=alpine
        ARG BASE_IMAGE_TAG=latest

        FROM ${BASE_IMAGE}:${BASE_IMAGE_TAG} as main
		`,
		`
		ARG BASE_IMAGE=alpine
        ARG BASE_IMAGE_TAG=latest=

        FROM ${BASE_IMAGE}:${BASE_IMAGE_TAG} as main
		`,
	}

	for idx, sampleFile := range sample {
		_, doc, igLines, _, err := p.Parse(ctx, []byte(sampleFile), "Dockerfile", true, 15)
		switch idx {
		case 0:
			require.NoError(t, err)
			require.Len(t, doc, 1)
			require.Len(t, doc[0]["command"], 1)
			require.Contains(t, doc[0]["command"], "openjdk:11-jdk")
			docJDk := doc[0]["command"].(map[string]interface{})["openjdk:11-jdk"]
			require.Len(t, docJDk, 7)
			require.Contains(t, docJDk.([]interface{})[5].(map[string]interface{})["Value"].([]interface{})[0], "${JAR_FILE}")
			// require.Equal(t, nil, igLines)
		case 1:
			require.NoError(t, err)
			require.Len(t, doc, 1)
			require.Len(t, doc[0]["command"], 2)
			require.Contains(t, doc[0]["command"], "ubuntu:xenial")
			require.Contains(t, doc[0]["command"], "ubuntu:xenial2")
			docXec := doc[0]["command"].(map[string]interface{})["ubuntu:xenial"]
			docXec2 := doc[0]["command"].(map[string]interface{})["ubuntu:xenial2"]
			require.Len(t, docXec, 6)
			require.Len(t, docXec2, 3)
			require.Contains(t, docXec.([]interface{})[3].(map[string]interface{})["Flags"].([]interface{})[0], "--retries=5")
			require.Contains(t, docXec.([]interface{})[4].(map[string]interface{})["SubCmd"], "add")
			require.Equal(t, []int{4, 5}, igLines)
		case 2:
			require.NoError(t, err)
			require.Len(t, doc, 1)
			require.Len(t, doc[0]["command"], 1)
			require.Contains(t, doc[0]["command"], "golang:alpine")
			docGoALP := doc[0]["command"].(map[string]interface{})["golang:alpine"]
			require.Len(t, docGoALP, 5)
			require.Contains(t, docGoALP.([]interface{})[4].(map[string]interface{})["Value"].([]interface{})[0], "${GIT_USER}")
			require.Equal(t, []int{2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, igLines)
		case 3:
			require.NoError(t, err)
			require.Len(t, doc, 1)
			require.Len(t, doc[0]["command"], 1)
			require.Contains(t, doc[0]["command"], "${BASE_IMAGE}:${BASE_IMAGE_TAG} as main")
			c := doc[0]["command"].(map[string]interface{})["${BASE_IMAGE}:${BASE_IMAGE_TAG} as main"]
			require.Len(t, c, 1)
			require.Contains(t, c.([]interface{})[0].(map[string]interface{})["Value"].([]interface{})[0], "alpine:latest")
		case 4:
			require.NoError(t, err)
			require.Len(t, doc, 1)
			require.Len(t, doc[0]["command"], 1)
			require.Contains(t, doc[0]["command"], "${BASE_IMAGE}:${BASE_IMAGE_TAG} as main")
			c := doc[0]["command"].(map[string]interface{})["${BASE_IMAGE}:${BASE_IMAGE_TAG} as main"]
			require.Len(t, c, 1)
			require.Contains(t, c.([]interface{})[0].(map[string]interface{})["Value"].([]interface{})[0], "alpine:latest=")
		}
	}
}

// Test_GetCommentToken must get the token that represents a comment
func Test_GetCommentToken(t *testing.T) {
	parser := &Parser{}
	require.Equal(t, "#", parser.GetCommentToken())
}

func TestDocker_StringifyContent(t *testing.T) {
	type fields struct {
		parser Parser
	}
	type args struct {
		content []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "test stringify content",
			fields: fields{
				parser: Parser{},
			},
			args: args{
				content: []byte(`
FROM openjdk:11-jdk
VOLUME /tmp
ADD http://source.file/package.file.tar.gz /temp
RUN tar --xjf /temp/package.file.tar.gz \
	&& make -C /tmp/package.file \
	&& rm /tmp/ package.file.tar.gz
ARG JAR_FILE
ADD ${JAR_FILE} app.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]
`),
			},
			want: `
FROM openjdk:11-jdk
VOLUME /tmp
ADD http://source.file/package.file.tar.gz /temp
RUN tar --xjf /temp/package.file.tar.gz \
	&& make -C /tmp/package.file \
	&& rm /tmp/ package.file.tar.gz
ARG JAR_FILE
ADD ${JAR_FILE} app.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fields.parser.StringifyContent(tt.args.content)
			require.Equal(t, tt.wantErr, (err != nil))
			require.Equal(t, tt.want, got)
		})
	}
}

func TestVariableScope_DeclareArgs(t *testing.T) {
	stages := newStageScopes()
	stages.globals = newTestScope(map[string]string{"BARE": "global"})
	stages.inStage = true
	lex := newWordExpander('\\', false)
	values := []string{"ARG=2", "NEXT=${ARG}x", "BARE"}
	stages.declareArgs(lex, values)
	require.Equal(t, []string{"ARG=2", "NEXT=${ARG}x", "BARE"}, values)
	require.Equal(t, map[string]string{"ARG": "2", "NEXT": "2x", "BARE": "global"}, snapshotEnv(stages.current()))
}

func TestVariableScope_DeclareEnvs(t *testing.T) {
	stages := newStageScopes()
	stages.inStage = true
	stages.stage = newTestScope(map[string]string{"K": "KEY", "V": "value"})
	values := []string{"ARG", "2", "=", "$K", "$V", "=", "K", "new", "="}
	stages.declareEnvs(newWordExpander('\\', false), values)
	require.Equal(t, []string{"ARG", "2", "=", "$K", "$V", "=", "K", "new", "="}, values)
	require.Equal(t, map[string]string{"ARG": "2", "KEY": "value", "K": "new", "V": "value"}, snapshotEnv(stages.current()))
}

// Dockerfile instructions are case-insensitive: a lowercase FROM names its
// stage after the image just like an uppercase one.
func TestParser_Parse_LowercaseFrom(t *testing.T) {
	p := &Parser{}
	for _, sample := range []string{
		"from alpine:3.19\nexpose 22\n",
		"From  alpine:3.19\nEXPOSE 22\n",
		"FROM\talpine:3.19\nEXPOSE 22\n",
	} {
		_, doc, _, _, err := p.Parse(context.Background(), []byte(sample), "Dockerfile", true, 15)
		require.NoError(t, err)
		require.Len(t, doc, 1)
		require.Contains(t, doc[0]["command"], "alpine:3.19", "sample %q", sample)
		require.Len(t, doc[0]["command"], 1, "sample %q", sample)
	}
}

// A bare ARG has no value; parsing it must not panic, since a panic in a parser
// worker ends the whole scan.
func TestParser_Parse_BareArg(t *testing.T) {
	p := &Parser{}
	require.NotPanics(t, func() {
		_, doc, _, _, err := p.Parse(context.Background(), []byte("FROM ubuntu:22.04\nARG\nRUN echo hi\n"), "Dockerfile", true, 15)
		require.NoError(t, err)
		require.Len(t, doc, 1)
	})
}

// One ARG instruction may declare several names.
func TestParser_Parse_ArgDeclaresSeveralNames(t *testing.T) {
	p := &Parser{}
	_, doc, _, _, err := p.Parse(context.Background(), []byte("ARG IMAGE=alpine TAG=3.19\nFROM ${IMAGE}:${TAG}\n"), "Dockerfile", true, 15)
	require.NoError(t, err)
	stage := doc[0]["command"].(map[string]interface{})["${IMAGE}:${TAG}"]
	require.Equal(t, "alpine:3.19", stage.([]interface{})[0].(map[string]interface{})["Value"].([]interface{})[0])
}

// A variable is substituted by its whole name: with V and VERSION both
// declared, $VERSION must not become the value of V followed by "ERSION",
// whichever order the variables are visited in.
func TestParser_Parse_ArgSubstitutionMatchesWholeNames(t *testing.T) {
	src := []byte("ARG V=1\nARG VERSION=latest\nFROM ubuntu:$VERSION\nENV HOME_DIR=/home\nRUN echo ${HOME_DIR} $HOME_DIRX $UNSET\n")
	for range 50 {
		p := &Parser{}
		_, doc, _, _, err := p.Parse(context.Background(), src, "Dockerfile", true, 15)
		require.NoError(t, err)
		stage := doc[0]["command"].(map[string]interface{})["ubuntu:$VERSION"].([]interface{})
		require.Equal(t, "ubuntu:latest", stage[0].(map[string]interface{})["Value"].([]interface{})[0])
		require.Equal(t, "echo /home $HOME_DIRX $UNSET", stage[2].(map[string]interface{})["Value"].([]interface{})[0])
	}
}

func TestResolveArgsAndEnvs_WholeReferences(t *testing.T) {
	args := map[string]string{"V": "1", "VERSION": "latest", "NESTED": "$VERSION", "EMPTY": ""}
	values := []string{"$V $VERSION ${VERSION} $VERSION_SUFFIX ${UNKNOWN} $UNKNOWN ${EMPTY} $NESTED"}
	require.Equal(t, []string{"1 latest latest $VERSION_SUFFIX ${UNKNOWN} $UNKNOWN  $VERSION"},
		resolveArgsAndEnvs(values, newTestScope(args)))
}

func TestParser_Parse_ChainedDeclarations(t *testing.T) {
	for _, tt := range []struct {
		name, source, stage string
		command             int
		want                []interface{}
	}{
		{"ARG", "ARG BASE=alpine:latest\nARG IMAGE=$BASE\nFROM $IMAGE\n", "$IMAGE", 0, []interface{}{"alpine:latest"}},
		{"multiple ARG names", "ARG BASE=alpine:latest IMAGE=$BASE\nFROM $IMAGE\n", "$IMAGE", 0, []interface{}{"alpine:latest"}},
		{"ENV", "FROM alpine\nENV A=1\nENV B=$A\nRUN echo $B\n", "alpine", 3, []interface{}{"echo 1"}},
		{"ENV uses prior scope", "FROM alpine\nENV A=1\nENV A=2 B=$A\nRUN echo $A $B\n", "alpine", 3, []interface{}{"echo 2 1"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resolved, docs, _, _, err := (&Parser{}).Parse(t.Context(), []byte(tt.source), "Dockerfile", true, 15)
			require.NoError(t, err)
			require.Equal(t, tt.source, string(resolved))
			commands := docs[0]["command"].(map[string]interface{})[tt.stage].([]interface{})
			require.Equal(t, tt.want, commands[tt.command].(map[string]interface{})["Value"])
			if tt.name == "ARG" {
				args := docs[0]["args"].([]interface{})
				arg := args[1].(map[string]interface{})
				require.Equal(t, []interface{}{"IMAGE=$BASE"}, arg["Value"])
				require.Equal(t, "ARG IMAGE=$BASE", arg["Original"], "source text remains available to line detection")
			}
		})
	}
}

// The scope rows follow BuildKit's converter (dockerfile2llb), which keeps ARG and
// ENV in one environment where the last write wins, copies the whole parent
// environment into a derived stage, and lets a bare ARG take the global value.
// They were checked against the converter's resulting environment, not assumed.
func TestParser_Parse_VariableScopes(t *testing.T) {
	for _, tt := range []struct {
		name, source string
		want         map[int][]string
	}{
		{"bare ARG preserves unset expressions", "FROM alpine\nARG VERSION\nARG INSECURE\nRUN ${VERSION:?need} ${INSECURE:+--insecure}\n", map[int][]string{4: {"${VERSION:?need} ${INSECURE:+--insecure}"}}},
		{"empty declared ARG triggers colon default and alternate", "FROM alpine\nARG X=\nRUN ${X:-fallback} ${X:+alternate} ${X+present}\n", map[int][]string{3: {"fallback  present"}}},
		{"known ARG required and alternate", "FROM alpine\nARG X=known\nRUN ${X:?need} ${X:+alternate}\n", map[int][]string{3: {"known alternate"}}},
		{"unset runtime shell default stays intact", "FROM alpine\nRUN A=2; echo ${A:-1} $?\n", map[int][]string{2: {"A=2; echo ${A:-1} $?"}}},
		{"shell quoting and defaults", "FROM alpine\nARG V=1\nRUN echo \\$V '$V' \"$V\" ${V:-d}\n", map[int][]string{3: {`echo \$V '$V' "1" 1`}}},
		{"quoted declaration values", "FROM alpine\nARG V=1\nENV A=\"$V words\" LITERAL='$V' ESCAPED=\\$V\nRUN echo $A $LITERAL $ESCAPED\n", map[int][]string{3: {"A", "\"$V words\"", "=", "LITERAL", "'$V'", "=", "ESCAPED", "\\$V", "="}, 4: {"echo 1 words $V $V"}}},
		{"escape directive in expansion", "# escape=`\nFROM alpine\nARG V=1\nRUN echo `$V $V\n", map[int][]string{4: {"echo `$V 1"}}},
		{"unsupported bash expansion falls back locally", "FROM alpine\nARG H=hello\nRUN echo ${#H} $H\n", map[int][]string{3: {"echo ${#H} hello"}}},
		{"unmatched apostrophe starts literal context", "FROM alpine\nARG H=hello\nRUN echo $H it's $H\n", map[int][]string{3: {"echo hello it's $H"}}},
		{"resolved declarations", "ARG V=1\nFROM alpine\nARG V\nENV A=$V\nARG B=$A\nRUN echo $B\n", map[int][]string{4: {"A", "$V", "="}, 5: {"B=$A"}, 6: {"echo 1"}}},
		{"ENV overrides ARG", "FROM alpine\nARG V=1\nENV V=2\nRUN echo $V ${V}\n", map[int][]string{4: {"echo 2 2"}}},
		{"later ARG overrides ENV, last write wins", "FROM alpine\nENV V=2\nARG V=1\nRUN echo $V\n", map[int][]string{4: {"echo 1"}}},
		{"ENV default uses effective scope", "FROM alpine\nARG V=1\nENV V=2\nENV NEXT=$V\nRUN echo $NEXT\n", map[int][]string{4: {"NEXT", "$V", "="}, 5: {"echo 2"}}},
		{"ENV expands keys before saving", "FROM alpine\nARG NAME=PORT\nENV ${NAME}=22\nEXPOSE $PORT\n", map[int][]string{3: {"${NAME}", "22", "="}, 4: {"22"}}},
		{"ARG default uses effective scope", "FROM alpine\nARG V=1\nENV V=2\nARG NEXT=$V\nRUN echo $NEXT\n", map[int][]string{5: {"echo 2"}}},
		{"global ARG only in FROM", "ARG V=alpine\nFROM $V\nRUN echo $V\n", map[int][]string{2: {"alpine"}, 3: {"echo $V"}}},
		{"global ARG redeclared", "ARG V=alpine\nFROM $V\nARG V\nRUN echo $V\n", map[int][]string{4: {"echo alpine"}}},
		{"global ARG overridden locally", "ARG V=alpine\nFROM $V\nARG V=local\nRUN echo $V\n", map[int][]string{4: {"echo local"}}},
		{"bare ARG takes the global value", "ARG V=global\nFROM alpine\nARG V=local\nARG V\nRUN echo $V\n", map[int][]string{5: {"echo global"}}},
		{"bare ARG without a global keeps the stage value", "FROM alpine\nARG V=local\nARG V\nRUN echo $V\n", map[int][]string{4: {"echo local"}}},
		{"unrelated stage resets variables", "FROM alpine AS build\nARG A=one\nENV E=two\nFROM busybox\nRUN echo $A $E\n", map[int][]string{5: {"echo $A $E"}}},
		{"FROM only sees global ARG", "ARG IMAGE=alpine\nFROM $IMAGE AS build\nARG IMAGE=busybox\nENV IMAGE=scratch\nFROM $IMAGE\n", map[int][]string{5: {"alpine"}}},
		{"derived stage inherits ARG and ENV", "FROM alpine AS build\nARG A=one\nENV E=two\nFROM build\nRUN echo $A $E\n", map[int][]string{5: {"echo one two"}}},
		{"derived stage matches names case-insensitively", "FROM alpine AS Build\nENV E=two\nFROM build\nRUN echo $E\n", map[int][]string{4: {"echo two"}}},
		{"quoted base name still finds its stage", "FROM alpine AS base\nENV PORT=22\nFROM \"base\"\nEXPOSE $PORT\n", map[int][]string{4: {"22"}}},
		{"derived stage does not leak into its parent", "FROM alpine AS base\nENV V=base\nFROM base AS child\nENV V=child\nFROM alpine AS other\nRUN echo $V\n", map[int][]string{6: {"echo $V"}}},
		{"unset default stays visible", "FROM alpine:${TAG:-latest}\nRUN echo ${TAG:-latest}\n", map[int][]string{1: {"alpine:${TAG:-latest}"}, 2: {"echo ${TAG:-latest}"}}},
		{"unset global replacement keeps both slashes", "FROM alpine\nARG H=hello\nRUN echo ${UNKNOWN//a/b} $H\n", map[int][]string{3: {"echo ${UNKNOWN//a/b} hello"}}},
		{"single-quoted unset operator strips quotes in declaration", "FROM alpine\nENV A='${UNKNOWN:-x}'\nRUN echo $A\n", map[int][]string{3: {"echo ${UNKNOWN:-x}"}}},
		{"single-quoted unset operator does not block known modifier", "FROM alpine\nARG H=hello\nRUN echo '${UNKNOWN:-x}' ${H:-fallback}\n", map[int][]string{3: {"echo '${UNKNOWN:-x}' hello"}}},
		{"ENV keeps a reference to a variable set by the same instruction", "FROM alpine\nENV A=1\nENV A=2 B=$A\nRUN echo $A $B\n", map[int][]string{3: {"A", "2", "=", "B", "$A", "="}, 4: {"echo 2 1"}}},
		{"legacy ENV form", "FROM alpine\nENV PORT 22\nEXPOSE $PORT\n", map[int][]string{3: {"22"}}},
		{"sibling stages are isolated", "FROM alpine AS base\nENV V=base\nFROM base AS left\nENV V=left\nFROM base AS right\nRUN echo $V\n", map[int][]string{6: {"echo base"}}},
		{"ONBUILD declaration is deferred", "FROM alpine\nENV V=local\nONBUILD ENV V=child\nRUN echo $V\n", map[int][]string{4: {"echo local"}}},
		{"substitution stays single-pass", "FROM alpine\nARG A=$B\nENV B=expanded\nRUN echo $A\n", map[int][]string{4: {"echo $B"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, docs, _, _, err := (&Parser{}).Parse(t.Context(), []byte(tt.source), "Dockerfile", false, 0)
			require.NoError(t, err)
			data, err := json.Marshal(docs[0])
			require.NoError(t, err)
			var resource Resource
			require.NoError(t, json.Unmarshal(data, &resource))
			commands := map[int]Command{}
			for _, stage := range resource.CommandList {
				for _, cmd := range stage {
					commands[cmd.StartLine] = cmd
				}
			}
			for line, want := range tt.want {
				require.Contains(t, commands, line)
				require.Equal(t, want, commands[line].Value, "line %d", line)
			}
		})
	}
}

func resolveArgsAndEnvs(values []string, scope *envNode) []string {
	return expandValues(newWordExpander('\\', true), values, scope)
}

func TestParserVerticalTabStage(t *testing.T) {
	source := []byte("FROM\valpine AS b\nENV H=hello\nRUN echo $H\n")
	_, docs, _, _, err := (&Parser{}).Parse(t.Context(), source, "Dockerfile", false, 0)
	require.NoError(t, err)
	commands := docs[0]["command"].(map[string]interface{})
	require.Contains(t, commands, "alpine AS b")
	require.NotContains(t, commands, "")
	stage := commands["alpine AS b"].([]interface{})
	require.Equal(t, []interface{}{"echo hello"}, stage[2].(map[string]interface{})["Value"])
}

func TestParser_Parse_LineInfoOnlySkipsExpansion(t *testing.T) {
	source := []byte("ARG BASE=alpine:3.19\nFROM $BASE\nENV V=hello\nRUN echo $V\n")
	_, docs, _, _, err := (&Parser{}).Parse(iacparser.WithLineInfoOnly(t.Context()), source, "Dockerfile", false, 0)
	require.NoError(t, err)
	commands := docs[0]["command"].(map[string]interface{})["$BASE"].([]interface{})
	require.Equal(t, []interface{}{"$BASE"}, commands[0].(map[string]interface{})["Value"])
	require.Equal(t, []interface{}{"echo $V"}, commands[2].(map[string]interface{})["Value"])
}

// A chain of stages shares its parents' bindings via a persistent balanced tree,
// so both memory and unknown-variable lookups across all stages stay O(N log N).
func TestParser_Parse_StageChainSharesParentScope(t *testing.T) {
	parse := func(stages int) uint64 {
		var source strings.Builder
		source.WriteString("FROM alpine AS s0\nENV V0=0\n")
		for i := 1; i <= stages; i++ {
			fmt.Fprintf(&source, "FROM s%d AS s%d\nENV V%d=%d\nRUN echo $UNKNOWN\n", i-1, i, i, i)
		}
		fmt.Fprintf(&source, "RUN echo $V0 $V%d\n", stages)

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, docs, _, _, err := (&Parser{}).Parse(t.Context(), []byte(source.String()), "Dockerfile", false, 0)
		runtime.ReadMemStats(&after)
		require.NoError(t, err)
		lastStage := docs[0]["command"].(map[string]interface{})[fmt.Sprintf("s%d AS s%d", stages-1, stages)].([]interface{})
		lastCmd := lastStage[len(lastStage)-1].(map[string]interface{})
		require.Equal(t, []interface{}{fmt.Sprintf("echo 0 %d", stages)}, lastCmd["Value"])
		return after.TotalAlloc - before.TotalAlloc
	}
	small, large := parse(1000), parse(4000)
	require.Less(t, large, small*6, "4x the stages must not cost much more than 4x the memory")
}

// Declarations are expanded only when actually read. Neither an in-stage chain,
// a bare ARG redeclaring a global chain, nor a single-quoted reference to it
// should force resolution.
func TestParser_Parse_UnreadDoublingChainIsFree(t *testing.T) {
	var inStage, globalRedecl, singleQuoted, unsupportedOp strings.Builder
	inStage.WriteString("FROM scratch\nARG A=x\n")
	globalRedecl.WriteString("ARG A=x\n")
	singleQuoted.WriteString("FROM scratch\nARG A=x\n")
	unsupportedOp.WriteString("FROM scratch\nARG A=x\n")
	for i := 0; i < 60; i++ {
		inStage.WriteString("ARG A=$A$A\n")
		globalRedecl.WriteString("ARG A=$A$A\n")
		singleQuoted.WriteString("ARG A=$A$A\n")
		unsupportedOp.WriteString("ARG A=$A$A\n")
	}
	globalRedecl.WriteString("FROM scratch\nARG A\n")
	singleQuoted.WriteString("ARG S='$A'\nRUN echo $S\n")
	unsupportedOp.WriteString("ARG OFF=2\nRUN echo ${A:$OFF}\n")

	for name, source := range map[string]string{
		"in-stage":          inStage.String(),
		"global bare ARG":   globalRedecl.String(),
		"single-quoted ref": singleQuoted.String(),
		"unsupported op":    unsupportedOp.String(),
	} {
		t.Run(name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			_, docs, _, _, err := (&Parser{}).Parse(t.Context(), []byte(source), "Dockerfile", false, 0)
			runtime.ReadMemStats(&after)
			require.NoError(t, err)
			require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(16<<20))
			if name == "single-quoted ref" {
				stage := docs[0]["command"].(map[string]interface{})["scratch"].([]interface{})
				require.Equal(t, []interface{}{"echo $A"}, stage[len(stage)-1].(map[string]interface{})["Value"])
			}
			if name == "unsupported op" {
				stage := docs[0]["command"].(map[string]interface{})["scratch"].([]interface{})
				require.Equal(t, []interface{}{"echo ${A:2}"}, stage[len(stage)-1].(map[string]interface{})["Value"])
			}
		})
	}
}

// Dependency discovery is purely lexical and never feeds synthetic empty values
// into BuildKit's lexer. With large cached H and R and a still-lazy P=z,
// evaluating ${H//$P/$R} must resolve P first instead of running a replacement
// with an empty pattern.
func TestParser_Parse_LazyPatternDoesNotAllocatePlaceholderReplacement(t *testing.T) {
	bigH := strings.Repeat("a", 32<<10)
	bigR := strings.Repeat("b", 32<<10)
	source := fmt.Sprintf(
		"FROM scratch\nARG H=%s\nARG R=%s\nRUN echo $H $R\nARG P=z\nARG OUT=${H//$P/$R}\nRUN echo $OUT\n",
		bigH, bigR,
	)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, docs, _, _, err := (&Parser{}).Parse(t.Context(), []byte(source), "Dockerfile", false, 0)
	runtime.ReadMemStats(&after)
	require.NoError(t, err)
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(8<<20),
		"resolving P statically must not run a speculative empty-pattern replacement")

	stage := docs[0]["command"].(map[string]interface{})["scratch"].([]interface{})
	require.Equal(t, []interface{}{"echo " + bigH}, stage[len(stage)-1].(map[string]interface{})["Value"])
}

// A long chain of declarations that each refer to the previous one resolves
// without recursing per link in the document, and every link resolves once.
func TestParser_Parse_LongDeclarationChain(t *testing.T) {
	const links = 20000
	var source strings.Builder
	source.WriteString("FROM scratch\nARG A=x\n")
	for i := 0; i < links; i++ {
		source.WriteString("ARG A=$A\n")
	}
	source.WriteString("RUN echo $A\n")
	_, docs, _, _, err := (&Parser{}).Parse(t.Context(), []byte(source.String()), "Dockerfile", false, 0)
	require.NoError(t, err)
	stage := docs[0]["command"].(map[string]interface{})["scratch"].([]interface{})
	last := stage[len(stage)-1].(map[string]interface{})
	require.Equal(t, []interface{}{"echo x"}, last["Value"])
}

// Reading a variable expands its declaration in the middle of expanding the
// word that read it, so the two expansions must not share lexer state.
func TestParser_Parse_NestedDeclarationsExpandIndependently(t *testing.T) {
	source := "FROM scratch\nARG A=x\nARG A=$A$A\nARG A=$A$A\nARG A=$A$A\nRUN echo $A\n"
	_, docs, _, _, err := (&Parser{}).Parse(t.Context(), []byte(source), "Dockerfile", false, 0)
	require.NoError(t, err)
	stage := docs[0]["command"].(map[string]interface{})["scratch"].([]interface{})
	require.Equal(t, []interface{}{"echo xxxxxxxx"}, stage[len(stage)-1].(map[string]interface{})["Value"])
}

// Resolving a long chain must not use goroutine stack per link. The chain is
// resolved under a stack cap well below what recursive resolution needs.
func TestParser_Parse_LongDeclarationChainUsesBoundedStack(t *testing.T) {
	var source strings.Builder
	source.WriteString("FROM scratch\nARG A=x\nENV B=$A\n")
	for i := 0; i < 40000; i++ {
		source.WriteString("ARG A=$A\n")
	}
	source.WriteString("RUN echo $A $B\n")
	old := debug.SetMaxStack(8 << 20)
	defer debug.SetMaxStack(old)
	_, docs, _, _, err := (&Parser{}).Parse(t.Context(), []byte(source.String()), "Dockerfile", false, 0)
	require.NoError(t, err)
	stage := docs[0]["command"].(map[string]interface{})["scratch"].([]interface{})
	require.Equal(t, []interface{}{"echo x x"}, stage[len(stage)-1].(map[string]interface{})["Value"])
}

// Every dependency of a word is discovered statically in one pass, so a
// declaration reading N others scales linearly instead of rescanning N times.
func TestParser_Parse_ManyDependenciesResolveInOnePass(t *testing.T) {
	measure := func(inputs int) uint64 {
		var source, ref strings.Builder
		source.WriteString("FROM scratch\n")
		for i := 0; i < inputs; i++ {
			fmt.Fprintf(&source, "ARG V%d=x\n", i)
			fmt.Fprintf(&ref, "${V%d:+y}", i)
		}
		fmt.Fprintf(&source, "ARG OUT=%s\nRUN echo $OUT\n", ref.String())
		// Lines are limited to 64 KiB by the Dockerfile parser.
		require.Less(t, ref.Len(), 60000)

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, docs, _, _, err := (&Parser{}).Parse(t.Context(), []byte(source.String()), "Dockerfile", false, 0)
		runtime.ReadMemStats(&after)
		require.NoError(t, err)
		stage := docs[0]["command"].(map[string]interface{})["scratch"].([]interface{})
		require.Equal(t, []interface{}{"echo " + strings.Repeat("y", inputs)}, stage[len(stage)-1].(map[string]interface{})["Value"])
		return after.TotalAlloc - before.TotalAlloc
	}

	small, large := measure(500), measure(2000)
	require.Less(t, large, small*6, "4x dependencies must not allocate quadratically")
}

// Popped stack frames in resolveBindings must be zeroed so intermediate values
// in a growing chain (ARG A=$A...) become collectable during resolveBindings
// rather than retaining O(N^2) bytes until the function returns.
func TestParser_Parse_GrowingChainReleasesIntermediateValues(t *testing.T) {
	const links = 2000
	step := strings.Repeat(".", 64)
	var source strings.Builder
	source.WriteString("FROM scratch\nARG A=x\n")
	for i := 0; i < links; i++ {
		source.WriteString("ARG A=$A")
		source.WriteString(step)
		source.WriteByte('\n')
	}
	source.WriteString("RUN echo $A\n")

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, docs, _, _, err := (&Parser{}).Parse(t.Context(), []byte(source.String()), "Dockerfile", false, 0)
	require.NoError(t, err)
	runtime.ReadMemStats(&after)

	stage := docs[0]["command"].(map[string]interface{})["scratch"].([]interface{})
	want := "echo x" + strings.Repeat(step, links)
	require.Equal(t, []interface{}{want}, stage[len(stage)-1].(map[string]interface{})["Value"])
	// Without zeroing popped frames, 2k x 64B links retain ~128+ MiB during
	// resolveBindings; with zeroing, intermediate bindings are collected early.
	require.Less(t, after.HeapInuse, before.HeapInuse+(80<<20))
}

// Deeply nested ${A-...} across continuation lines must not crash the process
// with a stack overflow inside BuildKit's recursive shell.Lex.
func TestParser_Parse_DeepNestingDoesNotOverflowStack(t *testing.T) {
	const levels = 15000
	const chunk = 500
	var source strings.Builder
	source.WriteString("FROM alpine\nARG A=x\nRUN echo ")
	for i := 0; i < levels; i += chunk {
		source.WriteString(strings.Repeat("${A-", chunk))
		source.WriteString("\\\n")
	}
	source.WriteString("$A")
	for i := 0; i < levels; i += chunk {
		source.WriteString(strings.Repeat("}", chunk))
		source.WriteString("\\\n")
	}
	source.WriteByte('\n')

	old := debug.SetMaxStack(8 << 20)
	defer debug.SetMaxStack(old)

	_, docs, _, _, err := (&Parser{}).Parse(t.Context(), []byte(source.String()), "Dockerfile", false, 0)
	require.NoError(t, err)
	stage := docs[0]["command"].(map[string]interface{})["alpine"].([]interface{})
	val := stage[len(stage)-1].(map[string]interface{})["Value"].([]interface{})[0].(string)
	require.Contains(t, val, "${A-x}")
}
