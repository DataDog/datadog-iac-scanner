package docker

import (
	"context"
	"encoding/json"
	"math"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// parseResource parses a Dockerfile and decodes the document back into a Resource.
func parseResource(t *testing.T, content string) Resource {
	t.Helper()
	_, documents, _, _, err := (&Parser{}).Parse(context.Background(), []byte(content), "Dockerfile", true, 15)
	require.NoError(t, err)
	require.Len(t, documents, 1)
	raw, err := json.Marshal(documents[0])
	require.NoError(t, err)
	var resource Resource
	require.NoError(t, json.Unmarshal(raw, &resource))
	return resource
}

// findCommand returns the command of a stage (keyed by the raw FROM text, "" for the instructions before the first
// FROM) whose Original is original.
func findCommand(t *testing.T, resource Resource, stage, original string) Command {
	t.Helper()
	commands := resource.Arguments
	if stage != "" {
		var ok bool
		commands, ok = resource.CommandList[stage]
		require.True(t, ok, "stage %q not found in %v", stage, resource.CommandList)
	}
	for _, command := range commands {
		if command.Original == original {
			return command
		}
	}
	require.Failf(t, "command not found", "%q in stage %q", original, stage)
	return Command{}
}

type expectedCommand struct {
	stage    string
	original string
	value    []string
	flags    []string
}

func TestVariableResolver_Substitution(t *testing.T) {
	tests := []struct {
		name       string
		dockerfile string
		want       []expectedCommand
	}{
		{
			name:       "a name only matches a whole identifier",
			dockerfile: "FROM alpine\nARG P=x\nARG V=9\nENV PATH=/a:$PATH\nRUN echo $PATH $PNPM $P $VERSION_ID $V ${V}x\n",
			want: []expectedCommand{
				{"alpine", "ENV PATH=/a:$PATH", []string{"PATH", "/a:$PATH", "="}, nil},
				{"alpine", "RUN echo $PATH $PNPM $P $VERSION_ID $V ${V}x", []string{"echo /a:$PATH $PNPM x $VERSION_ID 9 9x"}, nil},
			},
		},
		{
			name:       "overlapping global ARG names in FROM",
			dockerfile: "ARG T=x\nARG TAG=nonroot\nFROM img:$TAG\nCOPY a /a\n",
			want: []expectedCommand{
				{"img:$TAG", "FROM img:$TAG", []string{"img:nonroot"}, nil},
				{"", "ARG TAG=nonroot", []string{"TAG=nonroot"}, nil},
			},
		},
		{
			name:       "a global ARG is not visible in a stage that does not redeclare it",
			dockerfile: "ARG M=http://mirror.example.com\nFROM alpine:3.20\nRUN curl -fsSL $M/a.sh\nUSER $M\n",
			want: []expectedCommand{
				{"alpine:3.20", "RUN curl -fsSL $M/a.sh", []string{"curl -fsSL $M/a.sh"}, nil},
				{"alpine:3.20", "USER $M", []string{"$M"}, nil},
			},
		},
		{
			name: "a redeclared global ARG takes the global value, or its own default",
			dockerfile: "ARG M=http://global.example.com\nARG N=http://n.example.com\nFROM alpine AS one\nARG M\n" +
				"RUN curl $M\nFROM alpine AS two\nARG M=http://own.example.com\nARG N\nRUN curl $M $N\n",
			want: []expectedCommand{
				{"alpine AS one", "ARG M", []string{"M"}, nil},
				{"alpine AS one", "RUN curl $M", []string{"curl http://global.example.com"}, nil},
				{"alpine AS two", "RUN curl $M $N", []string{"curl http://own.example.com http://n.example.com"}, nil},
			},
		},
		{
			name:       "global ARGs see the global ARGs declared before them",
			dockerfile: "ARG a2=box\nARG a3=\"$a2-foo\"\nFROM busy$a2 AS build\nARG a3\nRUN echo $a3\n",
			want: []expectedCommand{
				{"busy$a2 AS build", "FROM busy$a2 AS build", []string{"busybox", "AS", "build"}, nil},
				{"busy$a2 AS build", "RUN echo $a3", []string{"echo box-foo"}, nil},
			},
		},
		{
			name:       "ARG and ENV of a stage do not leak into an unrelated stage",
			dockerfile: "FROM alpine AS one\nARG V=1\nENV E=e1\nFROM alpine\nENV V=$V W=$E\nRUN echo $E $V $W\n",
			want: []expectedCommand{
				{"alpine", "ENV V=$V W=$E", []string{"V", "$V", "=", "W", "$E", "="}, nil},
				{"alpine", "RUN echo $E $V $W", []string{"echo $E $V $E"}, nil},
			},
		},
		{
			name:       "a stage ARG is not visible to a later FROM",
			dockerfile: "FROM alpine:3 AS b\nARG TAG=nonroot\nRUN true\nFROM img:${TAG}\nCOPY a /a\n",
			want: []expectedCommand{
				{"img:${TAG}", "FROM img:${TAG}", []string{"img:${TAG}"}, nil},
			},
		},
		{
			name: "a stage built on an earlier stage inherits its ARG and ENV values",
			dockerfile: "ARG BASE=base\nFROM alpine AS base\nARG A=1\nENV E=e\nFROM ${BASE} AS child\nRUN echo $A $E\n" +
				"FROM child\nENV F=$E-f\nRUN echo $A $E $F\nFROM alpine\nRUN echo $A $E\n",
			want: []expectedCommand{
				{"${BASE} AS child", "RUN echo $A $E", []string{"echo 1 e"}, nil},
				{"child", "RUN echo $A $E $F", []string{"echo 1 e e-f"}, nil},
				{"alpine", "RUN echo $A $E", []string{"echo $A $E"}, nil},
			},
		},
		{
			name:       "shell-form CMD, ENTRYPOINT and HEALTHCHECK only see ENV values",
			dockerfile: "FROM alpine\nARG A=1\nENV E=e\nRUN echo $A $E\nCMD echo $A $E\nENTRYPOINT echo $A $E\nHEALTHCHECK CMD curl $A $E\n",
			want: []expectedCommand{
				{"alpine", "RUN echo $A $E", []string{"echo 1 e"}, nil},
				{"alpine", "CMD echo $A $E", []string{"echo $A e"}, nil},
				{"alpine", "ENTRYPOINT echo $A $E", []string{"echo $A e"}, nil},
				{"alpine", "HEALTHCHECK CMD curl $A $E", []string{"CMD", "curl $A e"}, nil},
			},
		},
		{
			name: "exec form is substituted like shell text, JSON-form COPY like the instructions Docker expands",
			dockerfile: `FROM alpine
ARG M=http://mirror.example.com
ENV E=http://env.example.com
RUN ["/bin/sh", "-c", "curl -fsSL $M/a.sh | sh"]
RUN ["env", "sh", "-c", "wget \"$M/b\""]
RUN ["/usr/bin/env", "bash", "-c", "wget \"${M}/c\""]
RUN ["bash", "--rcfile", "/dev/null", "-c", "wget $M/d"]
RUN ["bash", "-O", "extglob", "-c", "wget $M/e"]
RUN ["sh", "-c", "sh -c \"$1\"", "arg0", "wget $M/f"]
RUN ["curl", "-o", "/x", "$M/g.tgz", "$1", "$$M"]
CMD ["/bin/sh", "-c", "curl $M/h $E/h"]
ENTRYPOINT ["echo", "${E}"]
HEALTHCHECK CMD ["sh", "-c", "curl -f $E/health || exit 1"]
COPY ["$E", "/d"]
`,
			want: []expectedCommand{
				{"alpine", `RUN ["/bin/sh", "-c", "curl -fsSL $M/a.sh | sh"]`, []string{"/bin/sh", "-c", "curl -fsSL http://mirror.example.com/a.sh | sh"}, nil},
				{"alpine", `RUN ["env", "sh", "-c", "wget \"$M/b\""]`, []string{"env", "sh", "-c", `wget "http://mirror.example.com/b"`}, nil},
				{"alpine", `RUN ["/usr/bin/env", "bash", "-c", "wget \"${M}/c\""]`, []string{
					"/usr/bin/env", "bash", "-c", `wget "http://mirror.example.com/c"`,
				}, nil},
				{"alpine", `RUN ["bash", "--rcfile", "/dev/null", "-c", "wget $M/d"]`, []string{
					"bash", "--rcfile", "/dev/null", "-c", "wget http://mirror.example.com/d",
				}, nil},
				{"alpine", `RUN ["bash", "-O", "extglob", "-c", "wget $M/e"]`, []string{"bash", "-O", "extglob", "-c", "wget http://mirror.example.com/e"}, nil},
				{"alpine", `RUN ["sh", "-c", "sh -c \"$1\"", "arg0", "wget $M/f"]`, []string{
					"sh", "-c", `sh -c "$1"`, "arg0", "wget http://mirror.example.com/f",
				}, nil},
				// Known limitation: curl receives the literal $M/g.tgz.
				{"alpine", `RUN ["curl", "-o", "/x", "$M/g.tgz", "$1", "$$M"]`, []string{
					"curl", "-o", "/x", "http://mirror.example.com/g.tgz", "$1", "$http://mirror.example.com",
				}, nil},
				{"alpine", `CMD ["/bin/sh", "-c", "curl $M/h $E/h"]`, []string{"/bin/sh", "-c", "curl $M/h http://env.example.com/h"}, nil},
				{"alpine", `ENTRYPOINT ["echo", "${E}"]`, []string{"echo", "http://env.example.com"}, nil},
				{"alpine", `HEALTHCHECK CMD ["sh", "-c", "curl -f $E/health || exit 1"]`, []string{
					"CMD", "sh", "-c", "curl -f http://env.example.com/health || exit 1",
				}, nil},
				{"alpine", `COPY ["$E", "/d"]`, []string{"http://env.example.com", "/d"}, nil},
			},
		},
		{
			name: "references inside a modifier that cannot be computed are substituted in shell text",
			dockerfile: `FROM alpine
ARG URL=http://example.invalid/data
ARG EMPTY=
RUN wget "${MIRROR:-$URL}" "${EMPTY:=$URL}" ${URL:0:4} ${UNKNOWN:+${URL}x} ${URL=$URL} ${UNKNOWN:-'}
LABEL a=${MIRROR:-$URL} b=${EMPTY:=$URL}
`,
			want: []expectedCommand{
				{"alpine", `RUN wget "${MIRROR:-$URL}" "${EMPTY:=$URL}" ${URL:0:4} ${UNKNOWN:+${URL}x} ${URL=$URL} ${UNKNOWN:-'}`, []string{
					`wget "${MIRROR:-http://example.invalid/data}" "${EMPTY:=http://example.invalid/data}" ${URL:0:4} ` +
						`${UNKNOWN:+http://example.invalid/datax} ${URL=http://example.invalid/data} ${UNKNOWN:-'}`,
				}, nil},
				{"alpine", `LABEL a=${MIRROR:-$URL} b=${EMPTY:=$URL}`, []string{"a", "${MIRROR:-$URL}", "=", "b", "${EMPTY:=$URL}", "="}, nil},
			},
		},
		{
			name: "the instructions Docker expands read numeric names, shell text keeps positional parameters",
			dockerfile: `FROM scratch
ARG 1=root
ARG 2x=y
USER ${1}
LABEL a=$1 b=${1:-x} c=$12 d=$1x
RUN echo $1 ${1} "$1"
`,
			want: []expectedCommand{
				{"scratch", "USER ${1}", []string{"root"}, nil},
				{"scratch", "LABEL a=$1 b=${1:-x} c=$12 d=$1x", []string{"a", "root", "=", "b", "root", "=", "c", "$12", "=", "d", "rootx", "="}, nil},
				{"scratch", `RUN echo $1 ${1} "$1"`, []string{`echo $1 ${1} "$1"`}, nil},
			},
		},
		{
			name: "nested references, mixed-case aliases and values the lexer rejects",
			dockerfile: `FROM alpine AS Base
ARG V=1
ARG W=2
ARG Z="unterminated
LABEL a=${V:-${W}} b=${V:+${W}x} c=${NONE:-${W}}
RUN echo ${V:+${W}${V}} $Z
FROM base
RUN echo $V $W
`,
			want: []expectedCommand{
				{"alpine AS Base", "LABEL a=${V:-${W}} b=${V:+${W}x} c=${NONE:-${W}}", []string{"a", "1", "=", "b", "2x", "=", "c", "${NONE:-${W}}", "="}, nil},
				{"alpine AS Base", "RUN echo ${V:+${W}${V}} $Z", []string{"echo 21 $Z"}, nil},
				{"base", "RUN echo $V $W", []string{"echo 1 2"}, nil},
			},
		},
		{
			name:       "single-quoted spans are kept as written in the instructions Docker expands",
			dockerfile: "FROM alpine\nARG M=http://mirror.example.com\nLABEL a='$M' b=\"$M\" c=\"it's $M\"\nWORKDIR '$M'/$M\n",
			want: []expectedCommand{
				{"alpine", "LABEL a='$M' b=\"$M\" c=\"it's $M\"", []string{
					"a", "'$M'", "=", "b", "\"http://mirror.example.com\"", "=", "c", "\"it's http://mirror.example.com\"", "=",
				}, nil},
				{"alpine", "WORKDIR '$M'/$M", []string{"'$M'/http://mirror.example.com"}, nil},
			},
		},
		{
			name: "shell text is substituted inside quotes, command substitutions and nested shells",
			dockerfile: "FROM alpine\nARG URL=http://example.invalid/data\n" +
				"RUN echo \"$(printf '\"')\" && wget -O /out \"$URL\"\n" +
				"RUN echo \"`printf '\"'`\" && wget -O /out \"$URL\"\n" +
				"RUN sh -c 'wget -O /out \"$URL\"' && sh -c \"wget \\$URL\"\n" +
				"RUN curl '$URL/b' \"${URL}/c\"\n",
			want: []expectedCommand{
				{"alpine", "RUN echo \"$(printf '\"')\" && wget -O /out \"$URL\"", []string{
					"echo \"$(printf '\"')\" && wget -O /out \"http://example.invalid/data\"",
				}, nil},
				{"alpine", "RUN echo \"`printf '\"'`\" && wget -O /out \"$URL\"", []string{
					"echo \"`printf '\"'`\" && wget -O /out \"http://example.invalid/data\"",
				}, nil},
				{"alpine", "RUN sh -c 'wget -O /out \"$URL\"' && sh -c \"wget \\$URL\"", []string{
					"sh -c 'wget -O /out \"http://example.invalid/data\"' && sh -c \"wget \\http://example.invalid/data\"",
				}, nil},
				// Known limitation: the outer shell would keep '$URL/b' literal.
				{"alpine", "RUN curl '$URL/b' \"${URL}/c\"", []string{
					"curl 'http://example.invalid/data/b' \"http://example.invalid/data/c\"",
				}, nil},
			},
		},
		{
			name: "quoted values are stored without quotes, documents keep their quotes",
			dockerfile: "FROM alpine\nARG Q=\"http://quoted.example.com\"\nENV A=\"x y\" B='$Q'\n" +
				"RUN curl $Q/x && echo \"$A\" $B\nUSER \"$A\"\n",
			want: []expectedCommand{
				{"alpine", "ARG Q=\"http://quoted.example.com\"", []string{"Q=\"http://quoted.example.com\""}, nil},
				{"alpine", "ENV A=\"x y\" B='$Q'", []string{"A", "\"x y\"", "=", "B", "'$Q'", "="}, nil},
				{"alpine", "RUN curl $Q/x && echo \"$A\" $B", []string{"curl http://quoted.example.com/x && echo \"x y\" $Q"}, nil},
				{"alpine", "USER \"$A\"", []string{"\"x y\""}, nil},
			},
		},
		{
			name: "values are expanded when they are declared",
			dockerfile: "FROM alpine\nENV FOO=a\nARG X=$FOO\nENV FOO=b\nARG a=1 b=$a\nENV abc=hello\nENV abc=bye def=$abc\n" +
				"RUN echo $X $FOO $b $abc $def\n",
			want: []expectedCommand{
				{"alpine", "ARG X=$FOO", []string{"X=a"}, nil},
				{"alpine", "ARG a=1 b=$a", []string{"a=1", "b=1"}, nil},
				{"alpine", "ENV abc=bye def=$abc", []string{"abc", "bye", "=", "def", "$abc", "="}, nil},
				{"alpine", "RUN echo $X $FOO $b $abc $def", []string{"echo a b 1 bye hello"}, nil},
			},
		},
		{
			name: "ENV instructions only substitute ARG values",
			dockerfile: "FROM alpine\nARG APP_VERSION=1.0\nENV APP_VERSION=${APP_VERSION}\nENV FOO=bar\n" +
				"ENV FOO=bar BAZ=${FOO}/baz\nARG X=1\nENV X=2\nENV Y=$X\nARG X=3\nENV Z=$X\n" +
				"ONBUILD ENV W=$FOO\nRUN echo $APP_VERSION $BAZ $Y $Z\n",
			want: []expectedCommand{
				{"alpine", "ENV APP_VERSION=${APP_VERSION}", []string{"APP_VERSION", "1.0", "="}, nil},
				{"alpine", "ENV FOO=bar BAZ=${FOO}/baz", []string{"FOO", "bar", "=", "BAZ", "${FOO}/baz", "="}, nil},
				{"alpine", "ENV Y=$X", []string{"Y", "$X", "="}, nil},
				{"alpine", "ENV Z=$X", []string{"Z", "3", "="}, nil},
				{"alpine", "ONBUILD ENV W=$FOO", []string{"W", "$FOO", "="}, nil},
				{"alpine", "RUN echo $APP_VERSION $BAZ $Y $Z", []string{"echo 1.0 bar/baz 2 3"}, nil},
			},
		},
		{
			name:       "ENV names are expanded before they are declared",
			dockerfile: "FROM scratch\nARG KEY=OWNER\nENV $KEY=root ${KEY}_HOME=/home/$KEY\nUSER $OWNER\nRUN echo $OWNER_HOME $KEY\n",
			want: []expectedCommand{
				{"scratch", "ENV $KEY=root ${KEY}_HOME=/home/$KEY", []string{"OWNER", "root", "=", "OWNER_HOME", "/home/OWNER", "="}, nil},
				{"scratch", "USER $OWNER", []string{"root"}, nil},
				{"scratch", "RUN echo $OWNER_HOME $KEY", []string{"echo /home/OWNER OWNER"}, nil},
			},
		},
		{
			name: "the instructions Docker expands read Unicode names, shell text reads ASCII names",
			dockerfile: "FROM scratch\nARG USUÁRIO=root\nARG USU=x\nUSER ${USUÁRIO}\nLABEL a=$USUÁRIO b=$USU\n" +
				"RUN echo $USUÁRIO ${USUÁRIO}\n",
			want: []expectedCommand{
				{"scratch", "USER ${USUÁRIO}", []string{"root"}, nil},
				{"scratch", "LABEL a=$USUÁRIO b=$USU", []string{"a", "root", "=", "b", "x", "="}, nil},
				{"scratch", "RUN echo $USUÁRIO ${USUÁRIO}", []string{"echo xÁRIO ${USUÁRIO}"}, nil},
			},
		},
		{
			name: "a quoted brace does not close a modifier",
			dockerfile: "FROM scratch\nARG OWNER=app\nUSER ${OWNER:+\"r}oot\"}\nLABEL a=${OWNER:+'}'} b=${OWNER:-${NONE:-\"}\"}}x\n" +
				"RUN echo ${OWNER:+\"r}oot\"} ${OWNER:-'}\n",
			want: []expectedCommand{
				{"scratch", "USER ${OWNER:+\"r}oot\"}", []string{"r}oot"}, nil},
				// b depends on the unknown NONE, so it is kept as written.
				{"scratch", "LABEL a=${OWNER:+'}'} b=${OWNER:-${NONE:-\"}\"}}x", []string{"a", "}", "=", "b", "${OWNER:-${NONE:-\"}\"}}x", "="}, nil},
				{"scratch", "RUN echo ${OWNER:+\"r}oot\"} ${OWNER:-'}", []string{"echo r}oot ${OWNER:-'}"}, nil},
			},
		},
		{
			name: "modifiers are delimited across escapes, nested references in double quotes and unterminated quotes",
			dockerfile: `FROM alpine
ARG A=a
LABEL a=${A:+\}} b=${A:+"${B:-"}"}x"} c=${A:+"\"}"}
WORKDIR ${A:+'x}/$A
RUN echo ${A:+\}} ${A:+"\"}"} ${A:+'x} $A
`,
			want: []expectedCommand{
				// b depends on the unknown B, so it is kept as written.
				{"alpine", `LABEL a=${A:+\}} b=${A:+"${B:-"}"}x"} c=${A:+"\"}"}`, []string{
					"a", "}", "=", "b", `${A:+"${B:-"}"}x"}`, "=", "c", `"}`, "=",
				}, nil},
				{"alpine", "WORKDIR ${A:+'x}/$A", []string{"${A:+'x}/$A"}, nil},
				{"alpine", `RUN echo ${A:+\}} ${A:+"\"}"} ${A:+'x} $A`, []string{`echo } "} ${A:+'x} a`}, nil},
			},
		},
		{
			name: "ENV names are expanded with ENV values too, and a name the lexer rejects is not declared",
			dockerfile: `FROM alpine
ARG EMPTY=
ENV KEY=OWNER
ENV $KEY=root
USER $OWNER
ENV ${EMPTY:?}=x C=2
RUN echo $C $OWNER
`,
			want: []expectedCommand{
				{"alpine", "ENV $KEY=root", []string{"$KEY", "root", "="}, nil},
				{"alpine", "USER $OWNER", []string{"root"}, nil},
				{"alpine", "ENV ${EMPTY:?}=x C=2", []string{"${EMPTY:?}", "x", "=", "C", "2", "="}, nil},
				{"alpine", "RUN echo $C $OWNER", []string{"echo 2 root"}, nil},
			},
		},
		{
			name: "modifier values are computed with BuildKit's quote removal",
			dockerfile: `FROM scratch
ARG DEST=stage/app
ARG OWNER=prefix-root
ARG A=a
WORKDIR ${DEST#"stage"}
USER ${OWNER#"prefix-"}
LABEL a=${A:+"\""} b="${OWNER%"-root"}" c=${OWNER#'prefix'}
RUN printf '%s' ${OWNER#"prefix-"} "${DEST%"/app"}" && printf 'fetch:\n\twget $$OWNER $$\n' > Makefile
`,
			want: []expectedCommand{
				{"scratch", `WORKDIR ${DEST#"stage"}`, []string{"/app"}, nil},
				{"scratch", `USER ${OWNER#"prefix-"}`, []string{"root"}, nil},
				{"scratch", `LABEL a=${A:+"\""} b="${OWNER%"-root"}" c=${OWNER#'prefix'}`, []string{"a", `"`, "=", "b", `"prefix"`, "=", "c", "-root", "="}, nil},
				{"scratch", `RUN printf '%s' ${OWNER#"prefix-"} "${DEST%"/app"}" && printf 'fetch:\n\twget $$OWNER $$\n' > Makefile`, []string{
					`printf '%s' root "stage" && printf 'fetch:\n\twget $prefix-root $$\n' > Makefile`,
				}, nil},
			},
		},
		{
			name: "a value derived from an unknown name does not select a modifier branch",
			dockerfile: `FROM alpine AS deferred
ARG UPSTREAM
ARG MIRROR=$UPSTREAM
ENV ENV_MIRROR=$UPSTREAM DERIVED=${MIRROR}x
ARG URL=http://example.invalid/data
RUN wget "${MIRROR:-$URL}" "${ENV_MIRROR:-$URL}" "${DERIVED:+$URL}" ${MIRROR#x} $MIRROR ${ENV_MIRROR}
USER ${MIRROR:-root}
FROM alpine AS known
ARG UPSTREAM=
ARG MIRROR=$UPSTREAM
ENV LITERAL='$UPSTREAM'
ARG URL=http://example.invalid/data
RUN wget "${MIRROR:-$URL}" && printf '%s' "${LITERAL:-$URL}"
USER ${MIRROR:-root}
`,
			want: []expectedCommand{
				{"alpine AS deferred", `RUN wget "${MIRROR:-$URL}" "${ENV_MIRROR:-$URL}" "${DERIVED:+$URL}" ${MIRROR#x} $MIRROR ${ENV_MIRROR}`, []string{
					`wget "${MIRROR:-http://example.invalid/data}" "${ENV_MIRROR:-http://example.invalid/data}" ` +
						`"${DERIVED:+http://example.invalid/data}" ${MIRROR#x} $UPSTREAM $UPSTREAM`,
				}, nil},
				{"alpine AS deferred", "USER ${MIRROR:-root}", []string{"${MIRROR:-root}"}, nil},
				// UPSTREAM is known and empty; LITERAL holds the literal text $UPSTREAM.
				{"alpine AS known", `RUN wget "${MIRROR:-$URL}" && printf '%s' "${LITERAL:-$URL}"`, []string{
					`wget "http://example.invalid/data" && printf '%s' "$UPSTREAM"`,
				}, nil},
				{"alpine AS known", "USER ${MIRROR:-root}", []string{"root"}, nil},
			},
		},
		{
			name:       "an unknown reference in a declared value stays as written",
			dockerfile: "FROM alpine\nARG X=$FOO\nENV FOO=a BAR=$X\nRUN echo $X $BAR\n",
			want: []expectedCommand{
				{"alpine", "ENV FOO=a BAR=$X", []string{"FOO", "a", "=", "BAR", "$FOO", "="}, nil},
				{"alpine", "RUN echo $X $BAR", []string{"echo $FOO $FOO"}, nil},
			},
		},
		{
			name: "BuildKit modifiers",
			dockerfile: "FROM alpine\nARG V=1\nARG EMPTY=\nENV W=${V:-2} Z=${EMPTY:-d} U=${UNSET:-3}\n" +
				"RUN echo ${V:-2} ${V:+set} ${EMPTY:-d} ${UNSET:-3} ${V:+\"$W\"} $Z\n",
			want: []expectedCommand{
				{"alpine", "ENV W=${V:-2} Z=${EMPTY:-d} U=${UNSET:-3}", []string{"W", "1", "=", "Z", "d", "=", "U", "${UNSET:-3}", "="}, nil},
				{"alpine", "RUN echo ${V:-2} ${V:+set} ${EMPTY:-d} ${UNSET:-3} ${V:+\"$W\"} $Z", []string{
					"echo 1 set d ${UNSET:-3} 1 d",
				}, nil},
			},
		},
		{
			name:       "unknown names stay as written",
			dockerfile: "FROM alpine\nARG NODEFAULT\nARG KNOWN=k\nRUN echo $NODEFAULT ${NODEFAULT} $NEVER ${NEVER:-x} $KNOWN\n",
			want: []expectedCommand{
				{"alpine", "ARG NODEFAULT", []string{"NODEFAULT"}, nil},
				{"alpine", "RUN echo $NODEFAULT ${NODEFAULT} $NEVER ${NEVER:-x} $KNOWN", []string{
					"echo $NODEFAULT ${NODEFAULT} $NEVER ${NEVER:-x} k",
				}, nil},
			},
		},
		{
			name:       "shell parameters and bash-only expansions are kept, $$NAME reads as $ and $NAME",
			dockerfile: "FROM alpine\nARG X=1\nRUN echo $$X $1 $@ ${#X} ${X:0:1} \\$X \"\\$X\" $(echo $X) ${X,,} $XY $\n",
			want: []expectedCommand{
				{"alpine", "RUN echo $$X $1 $@ ${#X} ${X:0:1} \\$X \"\\$X\" $(echo $X) ${X,,} $XY $", []string{
					"echo $1 $1 $@ ${#X} ${X:0:1} \\1 \"\\1\" $(echo 1) ${X,,} $XY $",
				}, nil},
			},
		},
		{
			name: "multi-line and heredoc RUN keep their text",
			dockerfile: "# syntax=docker/dockerfile:1\nFROM alpine:3.20\nARG X=1\nRUN <<EOT\ncurl http://example.com/$X.sh | sh\nEOT\n" +
				"RUN echo 'a\\\nb' \"c   d\" \\\n    && echo $X\n",
			want: []expectedCommand{
				{"alpine:3.20", "RUN <<EOT", []string{"<<EOT"}, nil},
				{"alpine:3.20", "RUN echo 'ab' \"c   d\"     && echo $X", []string{"echo 'ab' \"c   d\"     && echo 1"}, nil},
			},
		},
		{
			name: "ADD and COPY flag values are expanded in place",
			dockerfile: "FROM alpine AS s\nARG PERM=777\nARG OWNER=app\nARG SUM=sha256:0\n" +
				"COPY --chmod=$PERM --chown=${OWNER}:$GROUP --from=$S --link a /b\nADD --checksum=$SUM --chmod=$PERM a /b\n" +
				"RUN --mount=type=cache,target=$PERM true\n",
			want: []expectedCommand{
				{"alpine AS s", "COPY --chmod=$PERM --chown=${OWNER}:$GROUP --from=$S --link a /b", []string{"a", "/b"},
					[]string{"--chmod=777", "--chown=app:$GROUP", "--from=$S", "--link"}},
				{"alpine AS s", "ADD --checksum=$SUM --chmod=$PERM a /b", []string{"a", "/b"}, []string{"--checksum=sha256:0", "--chmod=777"}},
				{"alpine AS s", "RUN --mount=type=cache,target=$PERM true", []string{"true"}, []string{"--mount=type=cache,target=$PERM"}},
			},
		},
		{
			name: "instructions Docker expands",
			dockerfile: "FROM alpine\nARG D=/app\nARG P=8080\nWORKDIR $D\nUSER ${P}\nEXPOSE $P ${P}/udp\nVOLUME [\"$D\"]\n" +
				"VOLUME $D/v\nSTOPSIGNAL SIG$P\nLABEL dir=$D\nADD $D /x\nMAINTAINER $D\nSHELL [\"/bin/sh\", \"$D\"]\n",
			want: []expectedCommand{
				{"alpine", "WORKDIR $D", []string{"/app"}, nil},
				{"alpine", "USER ${P}", []string{"8080"}, nil},
				{"alpine", "EXPOSE $P ${P}/udp", []string{"8080", "8080/udp"}, nil},
				{"alpine", "VOLUME [\"$D\"]", []string{"/app"}, nil},
				{"alpine", "VOLUME $D/v", []string{"/app/v"}, nil},
				{"alpine", "STOPSIGNAL SIG$P", []string{"SIG8080"}, nil},
				{"alpine", "LABEL dir=$D", []string{"dir", "/app", "="}, nil},
				{"alpine", "ADD $D /x", []string{"/app", "/x"}, nil},
				{"alpine", "MAINTAINER $D", []string{"$D"}, nil},
				{"alpine", "SHELL [\"/bin/sh\", \"$D\"]", []string{"/bin/sh", "$D"}, nil},
			},
		},
		{
			name: "ONBUILD triggers see ENV values and do not change the scope",
			dockerfile: "FROM alpine\nARG A=1\nENV E=e\nONBUILD RUN echo $A $E\nONBUILD COPY $E /x\nONBUILD ENV Z=1\n" +
				"ONBUILD ARG Y=2\nONBUILD RUN [\"echo\", \"$E\"]\nRUN echo $Z $Y\n",
			want: []expectedCommand{
				{"alpine", "ONBUILD RUN echo $A $E", []string{"echo $A e"}, nil},
				{"alpine", "ONBUILD COPY $E /x", []string{"e", "/x"}, nil},
				{"alpine", "ONBUILD RUN [\"echo\", \"$E\"]", []string{"echo", "e"}, nil},
				{"alpine", "RUN echo $Z $Y", []string{"echo $Z $Y"}, nil},
			},
		},
		{
			name:       "the escape directive applies to the instructions Docker expands, not to shell text",
			dockerfile: "# escape=`\nFROM alpine\nARG X=1\nWORKDIR c:\\$X\\`$X\nRUN echo \\$X `$X\n",
			want: []expectedCommand{
				{"alpine", "WORKDIR c:\\$X\\`$X", []string{"c:\\1\\`$X"}, nil},
				{"alpine", "RUN echo \\$X `$X", []string{"echo \\1 `1"}, nil},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := parseResource(t, tt.dockerfile)
			for _, want := range tt.want {
				got := findCommand(t, resource, want.stage, want.original)
				require.Equal(t, want.value, got.Value, want.original)
				if want.flags != nil {
					require.Equal(t, want.flags, got.Flags, want.original)
				}
			}
		})
	}
}

func TestVariableResolver_Deterministic(t *testing.T) {
	dockerfile := "ARG T=x\nARG TA=y\nARG TAG=nonroot\nFROM img:$TAG AS a\nARG P=1\nARG PA=2\nARG PATH_X=3\n" +
		"ENV E=$P$PA$PATH_X\nRUN echo $P $PA $PATH_X ${PA}${P} $E\nFROM a\nRUN echo $PATH_X $E\n"
	first, err := json.Marshal(parseResource(t, dockerfile))
	require.NoError(t, err)
	for range 50 {
		again, err := json.Marshal(parseResource(t, dockerfile))
		require.NoError(t, err)
		require.Equal(t, string(first), string(again))
	}
	resource := parseResource(t, dockerfile)
	require.Equal(t, []string{"img:nonroot", "AS", "a"}, findCommand(t, resource, "img:$TAG AS a", "FROM img:$TAG AS a").Value)
	require.Equal(t, []string{"echo 1 2 3 21 123"},
		findCommand(t, resource, "img:$TAG AS a", "RUN echo $P $PA $PATH_X ${PA}${P} $E").Value)
	require.Equal(t, []string{"echo 3 123"}, findCommand(t, resource, "a", "RUN echo $PATH_X $E").Value)
}

// TestVariableResolver_LinearOnHostileInput checks that unclosed ${NAME<modifier> references and quotes do not make
// the substitution quadratic: a 200 KB instruction took seconds to minutes before the search was bounded. It compares
// the parse times of 10 KB and 80 KB inputs rather than an absolute time, which depends on the machine and on the race
// detector: 8 times the size takes about 8 times longer when linear, 64 times when quadratic; the bound is 32 times.
func TestVariableResolver_LinearOnHostileInput(t *testing.T) {
	for _, chunk := range []string{"${X:-", "${X:+'", `${X:+"`, "${X:-${X:+$X"} {
		small := minParseDuration(t, hostileDockerfile(chunk, 10_000))
		large := minParseDuration(t, hostileDockerfile(chunk, 80_000))
		t.Logf("%q: 10 KB in %v, 80 KB in %v", chunk, small, large)
		require.Less(t, large, 32*small+20*time.Millisecond, "%q: 10 KB in %v, 80 KB in %v", chunk, small, large)
	}
}

// hostileDockerfile repeats chunk in a RUN and a WORKDIR instruction of about size bytes each, split into continuation
// lines that fit BuildKit's line limit.
func hostileDockerfile(chunk string, size int) string {
	body := strings.Repeat(chunk, size/len(chunk))
	var lines []string
	for len(body) > 0 {
		n := min(len(body), 50_000)
		lines = append(lines, body[:n])
		body = body[n:]
	}
	text := strings.Join(lines, " \\\n")
	return "FROM alpine\nARG X=1\nRUN echo " + text + "\nWORKDIR " + text + "\n"
}

// minParseDuration returns the shortest of three parse times of dockerfile, without garbage collection during the
// parse, to reduce noise.
func minParseDuration(t *testing.T, dockerfile string) time.Duration {
	t.Helper()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	shortest := time.Duration(math.MaxInt64)
	for range 3 {
		runtime.GC()
		start := time.Now()
		resource := parseResource(t, dockerfile)
		shortest = min(shortest, time.Since(start))
		require.Len(t, resource.CommandList["alpine"], 4)
	}
	return shortest
}
