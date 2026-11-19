package docker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShellFormRuntimeCommandsKeepSyntaxAndOpenFacts(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine
ENV IMAGE_MODE=production
SHELL ["/bin/bash", "-e", "-c"]
CMD echo "$IMAGE_MODE"
ENTRYPOINT printf '%s' "$IMAGE_MODE"
`)
	cmd := instructionByKind(t, result, "cmd")
	entrypoint := instructionByKind(t, result, "entrypoint")
	for _, instruction := range []*Instruction{cmd, entrypoint} {
		require.NotNil(t, instruction.Execution)
		require.NotNil(t, instruction.Syntax)
		require.Equal(t, "shell", instruction.Execution.Form)
		require.Equal(t, "shell", instruction.Syntax.Form)
		require.Equal(t, []string{"/bin/bash", "-e", "-c"}, instruction.Execution.Shell)
		require.True(t, instruction.Execution.ShellKnown)
		require.Empty(t, instruction.Execution.Calls)
		require.False(t, instruction.Execution.Complete, "shell-form runtime commands have an open semantic inventory")
	}
	require.Equal(t, `echo "$IMAGE_MODE"`, cmd.Execution.Script)
	require.Equal(t, cmd.Execution.Script, cmd.Syntax.Script)
	require.Equal(t, `printf '%s' "$IMAGE_MODE"`, entrypoint.Execution.Script)
	require.Equal(t, entrypoint.Execution.Script, entrypoint.Syntax.Script)
	context := result.Contexts[cmd.Context]
	_, invented := context.EnvironmentValues["IMAGE_MODE"]
	require.True(t, invented, "the scanner still reports explicitly configured image ENV")
	_, runtimeVariable := context.EnvironmentValues["RUNTIME_ONLY"]
	require.False(t, runtimeVariable, "runtime environment is not fabricated into parser facts")
}

func TestExecFormRuntimeCommandsKeepLiteralArgvFacts(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine
CMD ["python", "-c", "print('$RUNTIME_ONLY')"]
ENTRYPOINT ["/usr/bin/python3", "-m", "http.server"]
`)
	cmd := instructionByKind(t, result, "cmd")
	entrypoint := instructionByKind(t, result, "entrypoint")
	require.NotNil(t, cmd.Syntax)
	require.NotNil(t, entrypoint.Syntax)
	require.Equal(t, "exec", cmd.Execution.Form)
	require.Equal(t, "exec", cmd.Syntax.Form)
	require.Equal(t, []string{"python", "-c", "print('$RUNTIME_ONLY')"}, cmd.Execution.Argv)
	require.Equal(t, cmd.Execution.Argv, cmd.Syntax.Argv)
	require.True(t, cmd.Execution.Complete, "literal exec-form argv can be analyzed directly")
	require.Equal(t, "exec", entrypoint.Execution.Form)
	require.Equal(t, []string{"/usr/bin/python3", "-m", "http.server"}, entrypoint.Execution.Argv)
	require.Equal(t, entrypoint.Execution.Argv, entrypoint.Syntax.Argv)
	require.True(t, entrypoint.Execution.Complete)
	_, runtimeVariable := result.Contexts[cmd.Context].EnvironmentValues["RUNTIME_ONLY"]
	require.False(t, runtimeVariable, "exec-form argument text does not create build-time ENV facts")
}

func TestBuildTimeAndHealthcheckShellAnalysisRemainComplete(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine
RUN echo build-time
HEALTHCHECK CMD echo healthy
CMD echo runtime
`)
	run := instructionByKind(t, result, "run")
	healthcheck := instructionByKind(t, result, "healthcheck")
	runtime := instructionByKind(t, result, "cmd")
	require.NotNil(t, run.Execution)
	require.NotNil(t, run.Syntax)
	require.True(t, run.Execution.Complete)
	require.NotEmpty(t, run.Execution.Calls)
	require.NotNil(t, healthcheck.Healthcheck.Execution)
	require.NotNil(t, healthcheck.Healthcheck.Syntax)
	require.Equal(t, "shell", healthcheck.Healthcheck.Syntax.Form)
	require.Equal(t, "echo healthy", healthcheck.Healthcheck.Syntax.Script)
	require.NotNil(t, healthcheck.Syntax)
	require.True(t, healthcheck.Healthcheck.Execution.Complete)
	require.NotEmpty(t, healthcheck.Healthcheck.Execution.Calls)
	require.NotNil(t, runtime.Syntax)
	require.False(t, runtime.Execution.Complete)
	require.Empty(t, runtime.Execution.Calls)
}

func instructionByKind(t *testing.T, analysis *Analysis, kind string) *Instruction {
	t.Helper()
	for i := range analysis.Instructions {
		if analysis.Instructions[i].Kind == kind {
			return &analysis.Instructions[i]
		}
	}
	t.Fatalf("instruction kind %q not found", kind)
	return nil
}
