/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"context"
	"reflect"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// fixFinding is what a fix is built from.
type fixFinding struct {
	vuln       model.VulnerableFile
	start, end model.SarifResourceLocation
}

// Whatever field of a finding differs, the cache returns the fix building it
// directly gives, and a finding seen before gets the fix built for it.
func TestFixCache_MatchesTransformToSarifFix(t *testing.T) {
	ctx := context.Background()
	source := []string{
		`resource "aws_s3_bucket" "b" {`,
		`  bucket = "logs"`,
		`    acl  = "public-read"`,
		`}`,
		``,
	}
	otherSource := append([]string(nil), source...)
	otherSource[2] = `  acl = "public-read"`
	block := model.ResourceLocation{Start: model.ResourceLine{Line: 1, Col: 1}, End: model.ResourceLine{Line: 4, Col: 2}}
	bases := map[string]fixFinding{
		"replacement found from the block header": {vuln: model.VulnerableFile{
			FileName: "modules/bucket/main.tf", Line: 1, LineWithVulnerability: source[0],
			Remediation: `{"before":"acl = \"public-read\"","after":"acl = \"private\""}`, RemediationType: "replacement",
			FileSource: source, BlockLocation: block,
			RemediationLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 1, Col: 1}, End: model.ResourceLine{Line: 1, Col: 1}},
		}, start: model.SarifResourceLocation{Line: 1, Col: 1}, end: model.SarifResourceLocation{Line: 1, Col: 1}},
		"replacement on the attribute line": {vuln: model.VulnerableFile{
			FileName: "modules/bucket/main.tf", Line: 3, LineWithVulnerability: source[2],
			Remediation: `{"before":"public-read","after":"private"}`, RemediationType: "replacement",
			FileSource: source, BlockLocation: block,
			RemediationLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 3, Col: 5}, End: model.ResourceLine{Line: 3, Col: 25}},
		}, start: model.SarifResourceLocation{Line: 3, Col: 5}, end: model.SarifResourceLocation{Line: 3, Col: 25}},
		"removal": {vuln: model.VulnerableFile{
			FileName: "modules/bucket/main.tf", Line: 3, LineWithVulnerability: source[2],
			Remediation: "acl", RemediationType: "removal", FileSource: source, BlockLocation: block,
			RemediationLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 3, Col: 1}, End: model.ResourceLine{Line: 3, Col: 23}},
		}, start: model.SarifResourceLocation{Line: 3, Col: 1}, end: model.SarifResourceLocation{Line: 3, Col: 23}},
		"addition": {vuln: model.VulnerableFile{
			FileName: "modules/bucket/main.tf", Line: 1, LineWithVulnerability: source[0],
			Remediation: "force_destroy = true", RemediationType: "addition", FileSource: source, BlockLocation: block,
			RemediationLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 4, Col: 1}, End: model.ResourceLine{Line: 4, Col: 1}},
		}, start: model.SarifResourceLocation{Line: 4, Col: 1}, end: model.SarifResourceLocation{Line: 4, Col: 1}},
	}
	variants := map[string]func(*fixFinding){
		"file name":          func(f *fixFinding) { f.vuln.FileName = "modules/other/main.tf" },
		"remediation":        func(f *fixFinding) { f.vuln.Remediation = `{"before":"public-read","after":"log-delivery-write"}` },
		"remediation type":   func(f *fixFinding) { f.vuln.RemediationType = "removal" },
		"line text":          func(f *fixFinding) { f.vuln.LineWithVulnerability = source[2] },
		"line":               func(f *fixFinding) { f.vuln.Line = 2 },
		"file source":        func(f *fixFinding) { f.vuln.FileSource = otherSource },
		"block start":        func(f *fixFinding) { f.vuln.BlockLocation.Start.Line = 3 },
		"block end":          func(f *fixFinding) { f.vuln.BlockLocation.End.Line = 2 },
		"remediation start":  func(f *fixFinding) { f.vuln.RemediationLocation.Start.Line = 2 },
		"start location":     func(f *fixFinding) { f.start = model.SarifResourceLocation{Line: 2, Col: 3} },
		"end location":       func(f *fixFinding) { f.end = model.SarifResourceLocation{Line: 4, Col: 1} },
		"nothing (same fix)": func(*fixFinding) {},
		// Fields fixes are not built from, the remediation's end line included:
		// it is only ever overwritten.
		"other fields as set": func(f *fixFinding) {
			f.vuln.ResourceName, f.vuln.SearchKey = "other", "x"
			f.vuln.RemediationLocation.End.Line = 2
		},
	}
	cache := NewFixCache()
	changes := map[string]bool{}
	for range 2 {
		for baseName, base := range bases {
			baseFix, baseErr := TransformToSarifFix(ctx, base.vuln, base.start, base.end)
			for name, vary := range variants {
				f := base
				vary(&f)
				wantFix, wantErr := TransformToSarifFix(ctx, f.vuln, f.start, f.end)
				gotFix, gotErr := cache.TransformToSarifFix(ctx, f.vuln, f.start, f.end)
				require.Equal(t, wantErr, gotErr, "%s, %s", baseName, name)
				require.Equal(t, wantFix, gotFix, "%s, %s", baseName, name)
				if !reflect.DeepEqual(wantFix, baseFix) || !reflect.DeepEqual(wantErr, baseErr) {
					changes[name] = true
				}
			}
		}
	}
	// Each keyed field changes the fix of at least one finding above, so a
	// cache ignoring it would have returned a stale fix.
	var unexercised []string
	for name := range variants {
		if name == "nothing (same fix)" || name == "other fields as set" {
			require.False(t, changes[name], name)
		} else if !changes[name] {
			unexercised = append(unexercised, name)
		}
	}
	require.Empty(t, unexercised, "these change no fix here")
}
