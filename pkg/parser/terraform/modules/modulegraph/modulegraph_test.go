package modulegraph

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/stretchr/testify/require"
)

type stubResolver struct {
	resolution resolver.Resolution
}

func (r stubResolver) Resolve(
	_ context.Context, _ *tfmodules.ParsedModule,
) (resolver.Resolution, error) {
	return r.resolution, nil
}

func TestResolveAssemblesModuleMetadataAndPaths(t *testing.T) {
	root, moduleDir := writeModuleGraphFixture(t)

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: stubResolver{resolution: resolver.Resolution{
			LocalPath: moduleDir,
		}},
		MaxDepth: 2,
	})

	require.Equal(t, []string{filepath.Join(moduleDir, "main.tf")}, result.ScanPaths)
	require.Equal(t, map[string]string{
		moduleDir: "git::https://github.com/acme/network//modules/vpc?ref=v1@1.2.3",
	}, result.SourceMappings)
	require.Equal(t, []ResolvedModule{{
		CallerRoot:      root,
		Source:          "git::https://git@github.com/acme/network.git//modules/vpc?ref=v1",
		Version:         "1.2.3",
		Name:            "network",
		LocalPath:       moduleDir,
		CanonicalSource: "git::https://github.com/acme/network//modules/vpc?ref=v1@1.2.3",
	}}, result.Modules)
}

func TestResolveCleanupIsIdempotent(t *testing.T) {
	root, moduleDir := writeModuleGraphFixture(t)
	var cleanupCalls atomic.Int32

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: stubResolver{resolution: resolver.Resolution{
			LocalPath: moduleDir,
			Cleanup: func() {
				cleanupCalls.Add(1)
			},
		}},
		MaxDepth: 2,
	})

	result.Cleanup()
	result.Cleanup()
	require.Equal(t, int32(1), cleanupCalls.Load())
}

func writeModuleGraphFixture(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	moduleDir := filepath.Join(base, "module")
	require.NoError(t, os.MkdirAll(root, 0o755))
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "network" {
  source  = "git::https://git@github.com/acme/network.git//modules/vpc?ref=v1"
  version = "1.2.3"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(moduleDir, "main.tf"), []byte(`
resource "aws_vpc" "this" {}
`), 0o644))
	return root, moduleDir
}
