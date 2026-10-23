/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

// BenchmarkSinkExpandedTerraform includes parsing, normalization and registration,
// with many unchanged blocks beside one expanding block. The single-instance
// case measures overhead on files that do not produce extra layers.
func BenchmarkSinkExpandedTerraform(b *testing.B) {
	for _, count := range []int{1, 40} {
		for _, ext := range []string{"tf", "tf.json"} {
			b.Run(fmt.Sprintf("%s/instances=%d", ext, count), func(b *testing.B) {
				ctx := context.Background()
				path := "main." + ext
				source := expandedBenchmarkConfig(b, ext, count)
				fsys := vfs.NewMemFS(map[string][]byte{path: source})
				parsers, err := parser.NewBuilder(ctx).WithFS(fsys).
					Add(terraformParser.NewDefaultWithParams(fsys, "", model.SCIInfo{})).Build([]string{"terraform"}, []string{""})
				require.NoError(b, err)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					svc := &Service{Parser: parsers[0], Tracker: noopTracker{}, Storage: nopLineInfoStorage{}, Platforms: []string{"terraform"}}
					content := source
					require.NoError(b, svc.sinkContent(ctx, path, "scan", &Content{Content: &content}, nil, false, 15))
					require.Len(b, svc.files, count)
				}
			})
		}
	}
}

func expandedBenchmarkConfig(tb testing.TB, ext string, count int) []byte {
	tb.Helper()
	if ext == "tf.json" {
		blocks := map[string]interface{}{}
		for i := range 150 {
			blocks[fmt.Sprintf("static%d", i)] = map[string]interface{}{
				"bucket": fmt.Sprintf("logs-%d", i), "acl": "public-read",
				"tags":       map[string]interface{}{"owner": "security", "environment": "production"},
				"versioning": map[string]interface{}{"enabled": true},
			}
		}
		blocks["expanded"] = map[string]interface{}{"count": count, "bucket": "logs-${count.index}", "acl": "${count.index == 1 ? \"public-read\" : \"private\"}"}
		source, err := json.Marshal(map[string]interface{}{"resource": map[string]interface{}{"aws_s3_bucket": blocks}})
		require.NoError(tb, err)
		return source
	}
	var source strings.Builder
	for i := range 150 {
		fmt.Fprintf(&source, `resource "aws_s3_bucket" "static%d" {
 bucket = "logs-%d"
 acl = "public-read"
 tags = { owner = "security", environment = "production" }
 versioning { enabled = true }
}
`, i, i)
	}
	fmt.Fprintf(&source, `resource "aws_s3_bucket" "expanded" {
 count = %d
 bucket = "logs-${count.index}"
 acl = count.index == 1 ? "public-read" : "private"
}
`, count)
	return []byte(source.String())
}
