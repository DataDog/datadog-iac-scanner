package ansibleconfig

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParseNonAnsibleConfig(t *testing.T) {
	const tla = "CONSTANTS\n Scopes <- AllScopes\nSPECIFICATION FairSpec\nINVARIANT TypeOK\nCHECK_DEADLOCK FALSE\n"
	for _, tt := range []struct {
		name, path, content string
		skipped, wantErr    bool
	}{
		{"TLA", "specs/Model.cfg", tla, true, false},
		{"ansible provenance", "ansible.cfg", tla, false, false},
		{"unknown headerless", "custom.cfg", "broken config\n", false, false},
		{"malformed ansible", "ansible.cfg", "[defaults\ninventory = hosts\n", false, true},
		{"real config", "ansible.cfg", "[defaults]\ninventory = hosts\n[ssh_connection]\npipelining = true\n", false, false},
		{"custom config path", "elsewhere/custom.conf", "[defaults]\ninventory = hosts\n", false, false},
		{"mixed config", "Model.cfg", tla + "[defaults]\ninventory = hosts\n", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, docs, _, _, err := (&Parser{}).Parse(context.Background(), []byte(tt.content), tt.path, false, 1)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.skipped {
					require.Empty(t, docs)
				} else {
					require.NotEmpty(t, docs)
				}
			}
		})
	}
}
