package docker

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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

func TestParser_ExpandsVariablesDeterministically(t *testing.T) {
	tests := []struct {
		name       string
		dockerfile string
		want       []interface{}
	}{
		{
			name: "chained ARG defaults",
			dockerfile: `FROM alpine
ARG A=1000
ARG B=$A
ARG C=${B}
RUN groupadd --gid $C`,
			want: []interface{}{"groupadd --gid 1000"},
		},
		{
			name: "whole names",
			dockerfile: `FROM alpine
ARG A=one
ARG AB=two
RUN echo $A $AB ${AB} $ABC`,
			want: []interface{}{"echo one two two $ABC"},
		},
		{
			name: "default for empty or unset",
			dockerfile: `FROM alpine
ARG A=
ARG B=${A:-x}
ENV C=${MISSING:-y}
RUN echo $B $C ${A:-z}`,
			want: []interface{}{"echo x y z"},
		},
		{
			name: "default does not override a non-empty value",
			dockerfile: `FROM alpine
ARG A=one
RUN echo ${A:-x}`,
			want: []interface{}{"echo one"},
		},
		{
			name: "escaped references and quotes",
			dockerfile: `FROM alpine
ARG A=one
RUN echo \$A '$A' "$A" $A`,
			want: []interface{}{`echo \$A '$A' "one" one`},
		},
		{
			name:       "file escape directive",
			dockerfile: "# escape=\x60\nFROM alpine\nARG A=one\nARG B=\x60$A\nRUN echo \x60$A $B $A",
			want:       []interface{}{"echo \x60$A $A one"},
		},
		{
			name: "mixed declarations and no forward references",
			dockerfile: `FROM alpine
ARG A=${B:-before}
ENV B=after
ARG C=$B
ENV D=$C
RUN echo $A $B $C $D`,
			want: []interface{}{"echo before after after after"},
		},
		{
			name: "ENV assignments see previous values",
			dockerfile: `FROM alpine
ENV A=before
ENV A=after B=$A
RUN echo $A $B`,
			want: []interface{}{"echo after before"},
		},
		{
			name: "ENV legacy form and quoted value",
			dockerfile: `FROM alpine
ARG A="two words"
ENV B "$A more"
RUN echo "$B"`,
			want: []interface{}{`echo "two words more"`},
		},
		{
			name: "cross-stage visibility and default-less redeclaration",
			dockerfile: `ARG A=before
FROM alpine AS first
ENV B=$A
FROM alpine
ARG A
RUN echo $A $B`,
			want: []interface{}{"echo before before"},
		},
		{
			name: "ARG assignments on one line",
			dockerfile: `FROM alpine
ARG A=one B=$A
RUN echo $B`,
			want: []interface{}{"echo one"},
		},
		{
			name: "ARG or ENV shadows the previous declaration",
			dockerfile: `FROM alpine
ARG A=arg
ENV A=env
ARG B=$A
ARG A=again
RUN echo $A $B`,
			want: []interface{}{"echo again env"},
		},
		{
			name: "literal value is not expanded again",
			dockerfile: `FROM alpine
ARG A=one
ARG B=\$A
ENV C=$B
RUN echo $C`,
			want: []interface{}{"echo $A"},
		},
		{
			name: "references around unsupported shell syntax",
			dockerfile: `FROM alpine
ARG A=one
RUN echo $A ${A:0:1} ${#A} ${A^^} ${!A} $${{A}} ${A:=fallback} ${A}`,
			want: []interface{}{"echo one ${A:0:1} ${#A} ${A^^} ${!A} $${{A}} ${A:=fallback} one"},
		},
		{
			name: "apostrophe in trailing shell comment",
			dockerfile: `FROM alpine
ARG A=one
RUN echo $A # don't`,
			want: []interface{}{"echo one # don't"},
		},
		{
			name: "reference after unmatched apostrophe",
			dockerfile: `FROM alpine
ARG A=one
RUN echo don't $A`,
			want: []interface{}{"echo don't one"},
		},
		{
			name: "uid before unsupported substring expansion",
			dockerfile: `FROM alpine
ARG USER_UID=1000
ENV HOME=/root
RUN useradd -u $USER_UID && echo ${HOME:0:3}`,
			want: []interface{}{"useradd -u 1000 && echo ${HOME:0:3}"},
		},
		{
			name: "fallback respects quotes escapes whole names and defaults",
			dockerfile: `FROM alpine
ARG A=one
ARG AB=two
ARG EMPTY=
RUN echo ${A^^} '$A' \$A "$A '$AB'" $AB $ABC ${EMPTY:-${A}} ${EMPTY:-'}'}`,
			want: []interface{}{`echo ${A^^} '$A' \$A "one 'two'" two $ABC one '}'`},
		},
		{
			name:       "fallback uses file escape directive",
			dockerfile: "# escape=\x60\nFROM alpine\nARG A=one\nRUN echo ${A^^} \x60$A $A",
			want:       []interface{}{"echo ${A^^} \x60$A one"},
		},
	}

	parser := &Parser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for range 100 {
				_, docs, _, _, err := parser.Parse(context.Background(), []byte(tt.dockerfile), "Dockerfile", true, 15)
				require.NoError(t, err)
				require.Len(t, docs, 1)
				stages := docs[0]["command"].(map[string]interface{})
				commands := stages["alpine"].([]interface{})
				last := commands[len(commands)-1].(map[string]interface{})
				require.Equal(t, "run", last["Cmd"])
				require.Equal(t, tt.want, last["Value"])
			}
		})
	}
}

func TestParser_PreservesEnvReferencesForRules(t *testing.T) {
	const dockerfile = `FROM alpine
ENV A=before
ENV A=after B=$A
RUN echo $B`
	parser := &Parser{}
	_, docs, _, _, err := parser.Parse(context.Background(), []byte(dockerfile), "Dockerfile", true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	stages := docs[0]["command"].(map[string]interface{})
	commands := stages["alpine"].([]interface{})
	require.Len(t, commands, 4)
	require.Equal(t, []interface{}{"A", "after", "=", "B", "$A", "="}, commands[2].(map[string]interface{})["Value"])
	require.Equal(t, []interface{}{"echo before"}, commands[3].(map[string]interface{})["Value"])
}
