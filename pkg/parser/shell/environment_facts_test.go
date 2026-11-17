package shell

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnvironmentMayChangeFromShellSyntax(t *testing.T) {
	for _, script := range []string{
		"HOME=/tmp pip install flask",
		"export HOME=/tmp; pip install flask",
		"unset HOME; pip install flask",
		"configure() { HOME=/tmp; }; pip install flask",
		"cd /tmp; pip install --cache-dir cache flask",
		"$SETUP; pip install flask",
		". ./environment; pip install flask",
		"eval \"$SETUP\"; pip install flask",
	} {
		t.Run(script, func(t *testing.T) {
			require.True(t, Analyze(script, "sh").EnvironmentMayChange)
		})
	}
	for _, script := range []string{
		"pip install flask==1.0",
		"curl 'https://example.test/?x=y'",
		"echo 'HOME=/tmp'",
	} {
		t.Run(script, func(t *testing.T) {
			require.False(t, Analyze(script, "sh").EnvironmentMayChange)
		})
	}
}
