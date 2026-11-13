package docker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	scannerparser "github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/open-policy-agent/opa/v1/rego"
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

func TestSaveAndResolveArgs(t *testing.T) {
	tests := []struct {
		name   string
		fun    string
		value  string
		values []string
		want   struct {
			args   map[string]string
			values []string
		}
	}{
		{
			name:   "Args saving and resolving",
			value:  "ARG=2",
			values: []string{"ARG=${ARG}"},
			want: struct {
				args   map[string]string
				values []string
			}{
				args: map[string]string{
					"ARG": "2",
				},
				values: []string{"ARG=2"},
			},
		},
	}
	for _, tt := range tests {
		args := make(map[string]string)
		values := make([]string, 1)
		t.Run(tt.name, func(t *testing.T) {
			args = saveArgs(args, tt.value)
			values = resolveArgsAndEnvs(tt.values, args)
			require.Equal(t, tt.want.args, args)
			require.Equal(t, tt.want.values, values)
		})
	}
}

func TestSaveAndResolveEnvs(t *testing.T) {
	tests := []struct {
		name     string
		fun      string
		envValue []string
		values   []string
		want     struct {
			args   map[string]string
			values []string
		}
	}{
		{
			name:     "Env saving and resolving",
			envValue: []string{"ARG", "2", "=", "ENV", "env", "="},
			values:   []string{"ARG=${ARG}"},
			want: struct {
				args   map[string]string
				values []string
			}{
				args: map[string]string{
					"ARG": "2",
					"ENV": "env",
				},
				values: []string{"ARG=2"},
			},
		},
	}
	for _, tt := range tests {
		args := make(map[string]string)
		values := make([]string, 1)
		t.Run(tt.name, func(t *testing.T) {
			args = saveEnvs(args, tt.envValue)
			values = resolveArgsAndEnvs(tt.values, args)
			require.Equal(t, tt.want.args, args)
			require.Equal(t, tt.want.values, values)
		})
	}
}

func parseAnalysis(t *testing.T, content string) *Analysis {
	t.Helper()
	ast, err := parser.Parse(strings.NewReader(content))
	require.NoError(t, err)
	return analyze(ast.AST, newSource([]byte(content), ast.EscapeToken))
}

func TestParser_ParseModel(t *testing.T) {
	result := parseAnalysis(t, `ARG BASE=alpine
FROM --platform=$BUILDPLATFORM ${BASE} AS build
ENV FOO=bar
USER 1000:1000
WORKDIR /src
COPY --from=other --chown=1000:1000 a b /src/
ADD --checksum=sha256:abc https://example.com/a /a
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN --mount=type=cache,target=/root/.cache/pip sudo pip install 'example==1.2' | cat
CMD ["echo", "a | b"]
HEALTHCHECK --interval=10s CMD curl https://example.com || exit 1
ONBUILD RUN echo deferred
FROM build AS final
WORKDIR sub
RUN echo inherited
COPY one
FROM registry.example.com:5000/team/image:tag
SHELL ["powershell", "-Command"]
RUN Write-Output hi
`)
	instructions := result.Instructions
	require.Len(t, instructions, 19)
	require.Len(t, result.Stages, 3)
	require.Equal(t, -1, instructions[0].Stage)
	require.Equal(t, "BASE", result.Bindings[result.GlobalArguments].Bindings[0].Name)
	require.Equal(t, "unknown", instructions[1].Image.Kind)
	require.False(t, instructions[1].Platform.Known)
	require.Equal(t, 0, result.Stages[1].BaseStage)
	require.Equal(t, "registry.example.com:5000", instructions[16].Image.Registry)
	require.Equal(t, "team/image", instructions[16].Image.Repository)

	require.Equal(t, "other", instructions[5].Copy.From.Text)
	require.Len(t, instructions[5].Copy.Sources, 2)
	require.Equal(t, "remote", instructions[6].Copy.Sources[0].Kind)
	require.Equal(t, "sha256:abc", instructions[6].Copy.Checksum.Text)
	require.False(t, instructions[15].ParseOK)

	run := instructions[8]
	require.Equal(t, "cache", run.Mounts[0].Kind)
	require.Equal(t, "/root/.cache/pip", run.Mounts[0].Target.Text)
	require.Equal(t, []string{"/bin/bash", "-o", "pipefail", "-c"}, run.Execution.Shell)
	require.Equal(t, []string{"sudo"}, run.Execution.Calls[0].Wrappers)
	require.True(t, run.Execution.Pipelines[0].Pipefail)
	require.Equal(t, "pip", run.Execution.PackageCommands[0].Manager)
	require.True(t, run.Execution.PackageCommands[0].Packages[0].Pinned)
	require.Equal(t, []string{"echo", "a | b"}, instructions[9].Execution.Argv)
	require.Equal(t, "10s", instructions[10].Healthcheck.Interval)
	require.False(t, instructions[18].Execution.Complete)

	context := func(index int) Context { return result.Contexts[instructions[index].Context] }
	require.Equal(t, "1000:1000", context(8).User.Text)
	require.Equal(t, context(8).Environment, context(14).Environment, "a stage inherits its base stage's environment")
	require.Equal(t, "/src/sub", context(14).Workdir.Text)
	require.Equal(t, -1, context(17).Environment)

	trigger := instructions[11].Trigger
	require.Equal(t, "run", trigger.Kind)
	require.True(t, result.Contexts[trigger.Context].Deferred)
	require.Equal(t, "1000:1000", result.Contexts[trigger.Context].User.Text)
}

func TestParser_ParseSources(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine AS build
  RUN apt-get update \
    # comment
    && apt-get install -y \
       curl=7.0 git
RUN <<-EOF
	pip install flask
	EOF
ONBUILD RUN echo deferred
`)
	require.Equal(t, model.Source{Line: 1, Column: 0, EndLine: 1, EndColumn: 20}, result.Stages[0].Source)
	run := result.Instructions[1]
	require.Equal(t, model.Source{Line: 2, Column: 2, EndLine: 5, EndColumn: 19}, run.Source)
	calls := run.Execution.Calls
	require.Equal(t, &model.Source{Line: 2, Column: 6, EndLine: 2, EndColumn: 20}, calls[0].Source)
	require.Equal(t, &model.Source{Line: 4, Column: 7, EndLine: 5, EndColumn: 19}, calls[1].Source)
	install := run.Execution.PackageCommands[1]
	require.Equal(t, calls[1].Source, install.Source)
	require.Equal(t, &model.Source{Line: 5, Column: 7, EndLine: 5, EndColumn: 15}, install.Packages[0].Source)
	require.Equal(t, &model.Source{Line: 5, Column: 16, EndLine: 5, EndColumn: 19}, install.Packages[1].Source)

	heredoc := result.Instructions[2].Execution.PackageCommands[0]
	require.Equal(t, &model.Source{Line: 7, Column: 1, EndLine: 7, EndColumn: 18}, heredoc.Source)
	require.Equal(t, &model.Source{Line: 7, Column: 13, EndLine: 7, EndColumn: 18}, heredoc.Packages[0].Source)

	trigger := result.Instructions[3]
	require.Equal(t, trigger.Source, trigger.Trigger.Source)
	require.Nil(t, trigger.Trigger.Execution.Calls[0].Source, "a trigger runs in another build, not at its own text")
}

func TestParser_ParseLineInfoOnly(t *testing.T) {
	content := []byte("FROM alpine\nENV TEXT=hello\nRUN echo '$TEXT'; sudo apt-get install example\n")
	p := &Parser{}
	ctx := context.Background()
	_, enriched, _, _, err := p.Parse(ctx, content, "Dockerfile", false, 0)
	require.NoError(t, err)
	_, legacy, _, _, err := p.Parse(scannerparser.WithLineInfoOnly(ctx), content, "Dockerfile", false, 0)
	require.NoError(t, err)
	results, err := rego.New(rego.Query(`some instruction in input._dockerfile.instructions
some command in instruction.execution.package_commands
command.manager == "apt-get"
command.packages[0].source.line == 3`), rego.Input(enriched[0])).Eval(ctx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	encoded, err := json.Marshal(enriched[0])
	require.NoError(t, err)
	require.Contains(t, string(encoded), "$TEXT")
	require.NotContains(t, string(encoded), "span")
	delete(enriched[0], "_dockerfile")
	require.Equal(t, legacy, enriched)
}
