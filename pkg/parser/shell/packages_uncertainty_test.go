package shell

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPackageOptionValuesPreserveUncertainty(t *testing.T) {
	for _, script := range []string{
		"gem install rake --version $VERSION",
		"pip install --index-url $INDEX requests",
		"apk add -- $PACKAGES",
	} {
		t.Run(script, func(t *testing.T) {
			facts := Analyze(script, "sh")
			require.True(t, facts.Complete, "valid shell syntax can still have unknown command semantics")
			require.Len(t, facts.PackageCommands, 1)
			require.False(t, facts.PackageCommands[0].Known, "consumed option values and -- operands must retain uncertainty")
		})
	}
}
