package docker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParser_NormalizesExposePorts(t *testing.T) {
	result := parseAnalysis(t, "FROM alpine\nEXPOSE 80 8000-8002/tcp 65536 $DYNAMIC\n")
	ports := result.Instructions[1].Ports
	require.Len(t, ports, 4)
	knownPorts := map[int64]Port{}
	var unknown int
	for _, port := range ports {
		if port.Start.Known {
			knownPorts[port.Start.Value] = port
		} else {
			unknown++
			require.False(t, port.End.Known)
		}
	}
	require.Equal(t, 1, unknown)
	require.Equal(t, NumberValue{Known: true, Value: 80}, knownPorts[80].End)
	require.Equal(t, NumberValue{Known: true, Value: 8000}, knownPorts[8000].Start)
	require.Equal(t, NumberValue{Known: true, Value: 8002}, knownPorts[8000].End)
	require.Equal(t, NumberValue{Known: true, Value: 65536}, knownPorts[65536].Start,
		"port policy limits are enforced by Rego, while the parser preserves the numeric fact")
}

func TestParser_PreservesNumericExposeEndpoints(t *testing.T) {
	result := parseAnalysis(t, "FROM alpine\nEXPOSE 90000-80 90001-not-a-port\n")
	ports := result.Instructions[1].Ports
	require.Len(t, ports, 2)
	require.Equal(t, NumberValue{Known: true, Value: 90000}, ports[0].Start)
	require.Equal(t, NumberValue{Known: true, Value: 80}, ports[0].End,
		"the parser preserves reversed endpoints for the policy layer")
	require.Equal(t, NumberValue{Known: true, Value: 90001}, ports[1].Start)
	require.False(t, ports[1].End.Known)
}

func TestParser_NormalizesEffectiveUserName(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine AS base
USER app:group
FROM base
USER $BUILD_USER:group
FROM base AS inherited
RUN true
`)
	base := result.Contexts[result.Instructions[1].Context]
	require.Equal(t, "app", base.UserName.Text)
	require.True(t, base.UserName.Known)
	child := result.Contexts[result.Instructions[3].Context]
	require.False(t, child.UserName.Known)
	require.Equal(t, "inherited", result.Stages[2].Name)
	inherited := result.Contexts[result.Instructions[5].Context]
	require.Equal(t, "app", inherited.UserName.Text)
	require.True(t, inherited.UserName.Known)
}

func TestParser_NormalizesUserNameDefault(t *testing.T) {
	result := parseAnalysis(t, "ARG BUILD_USER=app:group\nFROM alpine\nARG BUILD_USER\nUSER $BUILD_USER\n")
	userName := result.Contexts[result.Instructions[3].Context].UserName
	require.False(t, userName.Known)
	require.NotNil(t, userName.Default)
	require.Equal(t, "app", *userName.Default)
}

func TestParser_NormalizesImageNamespaceAndFileScheme(t *testing.T) {
	result := parseAnalysis(t, `FROM registry.example.com/team/service:latest
ADD https://example.com/archive.tar /tmp/archive.tar
ADD HTTP://example.com/archive.tar /tmp/archive-upper.tar
`)
	require.Equal(t, "team", result.Instructions[0].Image.Namespace)
	require.Equal(t, "https", result.Instructions[1].Copy.Sources[0].Scheme)
	require.Equal(t, "http", result.Instructions[2].Copy.Sources[0].Scheme)
	require.Equal(t, "remote", result.Instructions[2].Copy.Sources[0].Kind)
}

func TestParser_NormalizesCopyFromKind(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine AS base
COPY --from=0 /source /destination
COPY --from=base /source /destination
COPY --from=$BUILD_STAGE /source /destination
COPY /source /destination
`)
	require.Equal(t, "index", result.Instructions[1].Copy.FromKind.Text)
	require.True(t, result.Instructions[1].Copy.FromKind.Known)
	require.Equal(t, "name", result.Instructions[2].Copy.FromKind.Text)
	require.True(t, result.Instructions[2].Copy.FromKind.Known)
	require.False(t, result.Instructions[3].Copy.FromKind.Known)
	require.Nil(t, result.Instructions[3].Copy.FromKind.Default)
	require.Nil(t, result.Instructions[4].Copy.FromKind)
}
