package runner

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	ansibleconfig "github.com/DataDog/datadog-iac-scanner/pkg/parser/ansible/ini/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/ansible/ini/hosts"
	"github.com/stretchr/testify/require"
)

type countingHostsParser struct {
	hosts.Parser
	calls int
}

func (p *countingHostsParser) Parse(ctx context.Context, content []byte, path string, resolve bool, depth int) ([]byte, []model.Document, []int, map[string]model.ResolvedFile, error) {
	p.calls++
	return p.Parser.Parse(ctx, content, path, resolve, depth)
}

type countingConfigParser struct {
	ansibleconfig.Parser
	calls int
}

func (p *countingConfigParser) Parse(ctx context.Context, content []byte, path string, resolve bool, depth int) ([]byte, []model.Document, []int, map[string]model.ResolvedFile, error) {
	p.calls++
	return p.Parser.Parse(ctx, content, path, resolve, depth)
}

func TestINISuccessfulParsesAreShared(t *testing.T) {
	for _, ext := range []string{".ini", ".cfg", ".conf"} {
		t.Run(ext, func(t *testing.T) {
			ctx := context.Background()
			hostParser := &countingHostsParser{}
			configParser := &countingConfigParser{}
			content := []byte("[web]\nexample.test ansible_port=22\n")
			calls := &hostParser.calls
			p := buildTestParser(t, ctx, func(b *parser.Builder) *parser.Builder {
				if ext == ".ini" {
					return b.Add(hostParser)
				}
				content = []byte("[defaults]\nhost_key_checking=false\n")
				calls = &configParser.calls
				return b.Add(configParser)
			})
			svc := &Service{Parser: p, Tracker: &parseCountingTracker{}, Storage: nopLineInfoStorage{},
				FilePlatform: map[string]string{"a/custom" + ext: "ansible", "b/custom" + ext: "ansible"}}
			for _, dir := range []string{"a", "b"} {
				require.NoError(t, svc.sinkContent(ctx, dir+"/custom"+ext, "scan", &Content{Content: &content}, nil, false, 15))
			}
			require.Len(t, svc.files, 2)
			require.Equal(t, 1, *calls, "identical ordinary files must only parse once")
			_, cached := svc.lookupSharedParse(content)
			require.NotNil(t, cached)
			require.Equal(t, svc.files[0].Document, svc.files[1].Document)
		})
	}
}

func TestINIPathDependentSkipsAreNotShared(t *testing.T) {
	for _, tt := range []struct {
		name, content, parsedPath, skippedPath string
		add                                    func(*parser.Builder) *parser.Builder
	}{
		{"pytest", "[pytest]\naddopts=-v\n", "custom.ini", "pytest.ini", func(b *parser.Builder) *parser.Builder { return b.Add(&hosts.Parser{}) }},
		{"TLA", "CONSTANTS\n Scopes <- AllScopes\nSPECIFICATION FairSpec\n", "ansible.cfg", "Model.cfg", func(b *parser.Builder) *parser.Builder { return b.Add(&ansibleconfig.Parser{}) }},
		{"pytest inventory provenance", "[pytest]\naddopts=-v\n", "inventory/pytest.ini", "pytest.ini", func(b *parser.Builder) *parser.Builder { return b.Add(&hosts.Parser{}) }},
		{"TLA ansible provenance", "CONSTANTS\n Scopes <- AllScopes\nSPECIFICATION FairSpec\n", "ansible/Model.cfg", "Model.cfg", func(b *parser.Builder) *parser.Builder { return b.Add(&ansibleconfig.Parser{}) }},
		{"cfg files artifact", "[defaults]\nhost_key_checking=false\n", "ansible.cfg", "roles/web/files/ansible.cfg", func(b *parser.Builder) *parser.Builder { return b.Add(&ansibleconfig.Parser{}) }},
		{"conf files artifact", "[defaults]\nhost_key_checking=false\n", "inventory/custom.conf", "roles/web/files/custom.conf", func(b *parser.Builder) *parser.Builder { return b.Add(&ansibleconfig.Parser{}) }},
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
				var parsedCache *sharedParse
				for _, path := range paths {
					content := []byte(tt.content)
					require.NoError(t, svc.sinkContent(ctx, path, "scan", &Content{Content: &content}, nil, false, 15))
					_, cached := svc.lookupSharedParse(content)
					if path == tt.parsedPath {
						require.NotNil(t, cached, "successful parses should still populate the cache")
						parsedCache = cached
					} else {
						require.Same(t, parsedCache, cached, "skips must not populate or overwrite cached parses")
					}
				}
				require.Len(t, svc.files, 1)
				require.Equal(t, tt.parsedPath, svc.files[0].FilePath)
				require.Len(t, trk.parsed, 2, "benign skips must not count as parse failures")
			}
		})
	}
}
