package docker

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
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
	require.Equal(t, []string{"Dockerfile", ".dockerfile", ".ubi8", ".debian", utils.PossibleDockerfile}, p.SupportedExtensions())
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
			scope := variableScope{args: args}
			scope.declareArgs(newWordExpander('\\', false), []string{tt.value}, nil)
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
		resolveArgsAndEnvs(values, args))
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
				require.Equal(t, []interface{}{"IMAGE=alpine:latest"}, arg["Value"])
				require.Equal(t, "ARG IMAGE=$BASE", arg["Original"], "source text remains available to line detection")
			}
		})
	}
}

func TestParser_Parse_VariableScopes(t *testing.T) {
	for _, tt := range []struct {
		name, source string
		want         map[int][]string
	}{
		{"runtime parameters with defaults", "FROM alpine\nRUN test ${A:-1} -eq 1 || exit $?\n", map[int][]string{2: {"test 1 -eq 1 || exit $?"}}},
		{"recovery with nested unknown default", "FROM alpine\nARG H=hello\nRUN echo it's ${A:-${B:-$C}} $? $H\n", map[int][]string{3: {"echo it's $C $? hello"}}},
		{"declaration default preserves unknown references", "FROM alpine\nENV A=${MISSING:-$UNKNOWN}\nRUN echo $A\n", map[int][]string{2: {"A", "$UNKNOWN", "="}, 3: {"echo $UNKNOWN"}}},
		{"shell quoting and defaults", "FROM alpine\nARG V=1\nRUN echo \\$V '$V' \"$V\" ${V:-d}\n", map[int][]string{3: {`echo \$V '$V' "1" 1`}}},
		{"quoted declaration values", "FROM alpine\nARG V=1\nENV A=\"$V words\" LITERAL='$V' ESCAPED=\\$V\nRUN echo $A $LITERAL $ESCAPED\n", map[int][]string{3: {"A", "1 words", "=", "LITERAL", "$V", "=", "ESCAPED", "$V", "="}, 4: {"echo 1 words $V $V"}}},
		{"escape directive in expansion", "# escape=`\nFROM alpine\nARG V=1\nRUN echo `$V $V\n", map[int][]string{4: {"echo `$V 1"}}},
		{"unset FROM default", "FROM alpine:${TAG:-latest}\n", map[int][]string{1: {"alpine:latest"}}},
		{"unset command default", "FROM alpine\nRUN echo ${TAG:-latest} $UNKNOWN\n", map[int][]string{2: {"echo latest $UNKNOWN"}}},
		{"unsupported expansion is local", "FROM alpine\nARG H=hello\nRUN echo ${#H} $H\n", map[int][]string{3: {"echo ${#H} hello"}}},
		{"unmatched apostrophe is literal", "FROM alpine\nARG H=hello\nRUN echo it's $H\n", map[int][]string{3: {"echo it's hello"}}},
		{"unset declaration default", "ARG IMAGE=alpine:${TAG:-latest}\nFROM $IMAGE\n", map[int][]string{2: {"alpine:latest"}}},
		{"nested default", "FROM alpine\nARG H=hello\nRUN echo ${MISSING:-${H}}\n", map[int][]string{3: {"echo hello"}}},
		{"recovery preserves quoting", "FROM alpine\nARG H=hello\nRUN echo ${#H} \\$H '$H' \"$H\" ${MISSING:-d}\n", map[int][]string{3: {`echo ${#H} \$H '$H' "hello" d`}}},
		{"unsupported reference after known reference", "FROM alpine\nARG H=hello\nRUN echo $H ${H@Q} $H\n", map[int][]string{3: {"echo hello ${H@Q} hello"}}},
		{"empty default", "FROM alpine\nARG V=\nRUN echo ${V:-d}\n", map[int][]string{3: {"echo d"}}},
		{"resolved declarations", "ARG V=1\nFROM alpine\nARG V\nENV A=$V\nARG B=$A\nRUN echo $B\n", map[int][]string{4: {"A", "1", "="}, 5: {"B=1"}, 6: {"echo 1"}}},
		{"ENV overrides ARG", "FROM alpine\nARG V=1\nENV V=2\nRUN echo $V ${V}\n", map[int][]string{4: {"echo 2 2"}}},
		{"later ARG does not override ENV", "FROM alpine\nENV V=2\nARG V=1\nRUN echo $V\n", map[int][]string{4: {"echo 2"}}},
		{"ENV default uses effective scope", "FROM alpine\nARG V=1\nENV V=2\nENV NEXT=$V\nRUN echo $NEXT\n", map[int][]string{4: {"NEXT", "2", "="}, 5: {"echo 2"}}},
		{"ARG default uses effective scope", "FROM alpine\nARG V=1\nENV V=2\nARG NEXT=$V\nRUN echo $NEXT\n", map[int][]string{5: {"echo 2"}}},
		{"global ARG only in FROM", "ARG V=alpine\nFROM $V\nRUN echo $V\n", map[int][]string{2: {"alpine"}, 3: {"echo $V"}}},
		{"global ARG redeclared", "ARG V=alpine\nFROM $V\nARG V\nRUN echo $V\n", map[int][]string{4: {"echo alpine"}}},
		{"global ARG overridden locally", "ARG V=alpine\nFROM $V\nARG V=local\nRUN echo $V\n", map[int][]string{4: {"echo local"}}},
		{"unrelated stage resets variables", "FROM alpine AS build\nARG A=one\nENV E=two\nFROM busybox\nRUN echo $A $E\n", map[int][]string{5: {"echo $A $E"}}},
		{"FROM only sees global ARG", "ARG IMAGE=alpine\nFROM $IMAGE AS build\nARG IMAGE=busybox\nENV IMAGE=scratch\nFROM $IMAGE\n", map[int][]string{5: {"alpine"}}},
		{"base stage inheritance", "FROM alpine AS build\nARG A=one\nENV E=two\nFROM build\nRUN echo $A $E\n", map[int][]string{5: {"echo one two"}}},
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

func resolveArgsAndEnvs(values []string, scopes ...map[string]string) []string {
	lex := newWordExpander('\\', true)
	return expandValues(lex, values, scopes...)
}
