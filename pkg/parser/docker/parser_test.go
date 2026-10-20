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
				require.Equal(t, []interface{}{"IMAGE=$BASE"}, args[1].(map[string]interface{})["Value"], "declarations retain raw source values")
			}
		})
	}
}

func TestFromArguments(t *testing.T) {
	for _, tt := range []struct{ source, want string }{
		{"", ""}, {"F", ""}, {"fro", ""}, {"FROM", ""}, {"RUN echo hi", ""},
		{"FROM alpine", "alpine"}, {"  fRoM\talpine AS build  ", "alpine AS build"},
	} {
		t.Run(tt.source, func(t *testing.T) {
			require.Equal(t, tt.want, fromArguments(tt.source))
		})
	}
}
