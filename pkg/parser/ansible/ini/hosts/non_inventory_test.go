package hosts

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestPytestWarningActionsDoNotHideInventoryHosts(t *testing.T) {
	for _, option := range []string{"addopts=-v", "filterwarnings="} {
		for _, declaration := range []struct{ host, role string }{
			{"default:22", ""},
			{"default:22", "web"},
			{"default:22", "web:Warning"},
			{`default:"22"`, "web:Warning"},
			{`default:'22'`, "web:Warning"},
			{`default:\22`, "web:Warning"},
			{`default:2"2"`, "web:Warning"},
		} {
			t.Run(option+"/"+declaration.host+"/"+declaration.role, func(t *testing.T) {
				content := "[pytest]\n" + option + "\n  " + declaration.host
				if declaration.role != "" {
					content += " role=" + declaration.role
				}
				content += "\n"
				_, docs, _, _, err := (&Parser{}).Parse(context.Background(), []byte(content), "tests/pytest.ini", false, 1)
				require.NoError(t, err)
				require.Len(t, docs, 1)
				all := docs[0]["all"].(*model.Document)
				children := (*all)["children"].(*model.Document)
				group := (*children)["pytest"].(*model.Document)
				hosts := (*group)["hosts"].(*model.Document)
				require.Contains(t, *hosts, "default")
				vars := (*hosts)["default"].(*model.Document)
				if declaration.role != "" {
					require.Equal(t, declaration.role, (*vars)["role"])
				}
			})
		}
	}
}

func TestParseNonInventoryAndInventory(t *testing.T) {
	for _, tt := range []struct {
		name, path, content string
		skipped, wantErr    bool
	}{
		{"pytest quotes", "tests/pytest.ini", "[pytest]\nfilterwarnings =\n    ignore:can't open file:Warning\n", true, false},
		{"pytest apostrophe after first token", "tests/pytest.ini", "[pytest]\nfilterwarnings =\n    ignore:cannot open user's file:Warning\n", true, false},
		{"warning after other option", "tests/pytest.ini", "[pytest]\naddopts=-v\n    ignore:can't open file:Warning\n", false, true},
		{"basename alone", "pytest.ini", "[web]\nserver1\n", false, false},
		{"indented host wins", "pytest.ini", "[pytest]\naddopts=-v\n  server1\n", false, false},
		{"indented host variables win", "pytest.ini", "[pytest]\naddopts=-v\n  server1 role=web\n", false, false},
		{"section alone", "custom.ini", "[pytest]\nserver1\n", false, false},
		{"bare hosts", "custom.ini", "localhost\nserver1\n", false, false},
		{"groups CRLF", "custom.ini", "# comment\r\n[web]\r\nserver[01:02]:22 ansible_user='test user'\r\n", false, false},
		{"vars", "custom.ini", "[web:vars]\nfoo = bar\n", false, false},
		{"children", "custom.ini", "[all:children]\nweb\n[web]\nserver1\n", false, false},
		{"malformed assignment", "custom.ini", "[web]\nserver1 = bad\n", false, true},
		{"malformed quote", "custom.ini", "[web]\nserver1 foo='bad\n", false, true},
		{"mixed inventory", "pytest.ini", "[pytest]\nfoo = bar\n[web:hosts]\nserver1\n", false, true},
		{"inventory provenance", "inventory/pytest.ini", "[pytest]\nfoo = bar\n", false, true},
		{"ambiguous app config", "dev.ini", "[app.publisher]\ntopic = \"events\"\n", false, true},
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
