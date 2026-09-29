package runner

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	ansibleconfig "github.com/DataDog/datadog-iac-scanner/pkg/parser/ansible/ini/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/ansible/ini/hosts"
	"github.com/stretchr/testify/require"
)

func TestINIPathDependentSkipsAreNotShared(t *testing.T) {
	for _, tt := range []struct {
		name, content, parsedPath, skippedPath string
		add                                    func(*parser.Builder) *parser.Builder
	}{
		{"pytest", "[pytest]\naddopts=-v\n", "custom.ini", "pytest.ini", func(b *parser.Builder) *parser.Builder { return b.Add(&hosts.Parser{}) }},
		{"TLA", "CONSTANTS\n Scopes <- AllScopes\nSPECIFICATION FairSpec\n", "ansible.cfg", "Model.cfg", func(b *parser.Builder) *parser.Builder { return b.Add(&ansibleconfig.Parser{}) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, reversed := range []bool{false, true} {
				ctx := context.Background()
				p := buildTestParser(t, ctx, tt.add)
				trk := &parseCountingTracker{}
				svc := &Service{Parser: p, Tracker: trk, Storage: nopLineInfoStorage{}, FilePlatform: map[string]string{tt.parsedPath: "ansible", tt.skippedPath: "ansible"}}
				paths := []string{tt.parsedPath, tt.skippedPath}
				if reversed {
					paths[0], paths[1] = paths[1], paths[0]
				}
				for _, path := range paths {
					content := []byte(tt.content)
					require.NoError(t, svc.sinkContent(ctx, path, "scan", &Content{Content: &content}, nil, false, 15))
				}
				require.Len(t, svc.files, 1)
				require.Equal(t, tt.parsedPath, svc.files[0].FilePath)
				require.Len(t, trk.parsed, 2, "benign skips must not count as parse failures")
			}
		})
	}
}
