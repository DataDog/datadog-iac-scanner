package shell

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCDOperandFacts(t *testing.T) {
	for _, tt := range []struct {
		script string
		value  string
		known  bool
		absent bool
	}{
		{script: "cd -LP /tmp", value: "/tmp", known: true},
		{script: "cd -P -- '/tmp path'", value: "/tmp path", known: true},
		{script: "cd -- -L", value: "-L", known: true},
		{script: "cd relative", value: "relative", known: true},
		{script: "cd $FLAGS /tmp"},
		{script: "cd *"},
		{script: "cd -"},
		{script: "cd -Z /tmp"},
		{script: "cd before after"},
		{script: "cd ''"},
		{script: "cd", absent: true},
		{script: "echo cd", absent: true},
	} {
		t.Run(tt.script, func(t *testing.T) {
			facts := Analyze(tt.script, "sh")
			require.Len(t, facts.Calls, 1)
			operand := facts.Calls[0].CDPath
			if tt.absent {
				require.Nil(t, operand)
				return
			}
			require.NotNil(t, operand)
			require.Equal(t, tt.known, operand.Known)
			if tt.known {
				require.Equal(t, tt.value, operand.Text)
			}
		})
	}
}
