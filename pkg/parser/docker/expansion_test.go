package docker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExpandValuesUnsetDefaultsAndRecovery(t *testing.T) {
	for _, tt := range []struct {
		source, want string
		raw          bool
	}{
		{`${MISSING:-"a}b"}`, `a}b`, false},
		{`"${MISSING:-"word"}" $UNKNOWN`, `""word"" $UNKNOWN`, true},
		{`${MISSING:-d} \$UNKNOWN '${UNKNOWN}' "$UNKNOWN"`, `d \$UNKNOWN '${UNKNOWN}' "$UNKNOWN"`, true},
		{`${MISSING:-d} \$UNKNOWN '${UNKNOWN}' "$UNKNOWN"`, `d $UNKNOWN ${UNKNOWN} $UNKNOWN`, false},
		{`${MISSING:-d} $X $UNKNOWN ${UNKNOWN}`, `d literal $H $UNKNOWN ${UNKNOWN}`, true},
		{`${#H} $H \$H '$H' "$H"`, `${#H} hello \$H '$H' "hello"`, true},
	} {
		t.Run(tt.source, func(t *testing.T) {
			scope := map[string]string{"H": "hello", "X": "literal $H", "MARKER": "\x00"}
			require.Equal(t, []string{tt.want}, expandValues(newWordExpander('\\', tt.raw), []string{tt.source}, scope))
		})
	}
}
