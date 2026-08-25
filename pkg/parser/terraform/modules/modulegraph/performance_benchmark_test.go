/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package modulegraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
)

type benchmarkResolver struct {
	bySource map[string]resolver.Resolution
}

func (r benchmarkResolver) Resolve(
	_ context.Context, mod *tfmodules.ParsedModule,
) (resolver.Resolution, error) {
	return r.bySource[mod.Source], nil
}

func BenchmarkResolve100RemoteModules(b *testing.B) {
	const count = 100
	root := b.TempDir()
	var config strings.Builder
	resolutions := make(map[string]resolver.Resolution, count)
	for i := 0; i < count; i++ {
		source := fmt.Sprintf("example.com/acme/module-%03d/aws", i)
		fmt.Fprintf(&config, "module \"m%03d\" { source = %q }\n", i, source)
		moduleDir := filepath.Join(root, "modules", fmt.Sprintf("%03d", i))
		if err := os.MkdirAll(moduleDir, 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(moduleDir, "main.tf"),
			[]byte(fmt.Sprintf("resource \"aws_vpc\" \"m%03d\" {}\n", i)),
			0o600,
		); err != nil {
			b.Fatal(err)
		}
		resolutions[source] = resolver.Resolution{LocalPath: moduleDir}
	}
	rootFile := filepath.Join(root, "main.tf")
	if err := os.WriteFile(rootFile, []byte(config.String()), 0o600); err != nil {
		b.Fatal(err)
	}
	request := &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{rootFile},
		Resolver:       benchmarkResolver{bySource: resolutions},
		MaxDepth:       2,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		result := Resolve(b.Context(), request)
		if len(result.Modules) != count {
			b.Fatalf("resolved %d modules", len(result.Modules))
		}
		result.Cleanup()
	}
}
