/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

const resultsTestPlaceholder = "\u0000dd-unknown-test"

const resultsMain = `resource "aws_security_group" "sg" {
  name = "sg"

  ingress {
    from_port = 22
    to_port   = 22
  }

  ingress {
    from_port = 443
    to_port   = 443
  }
}

module "m" {
  source = "./mod"
  count  = 2
}

variable "name" { default = "root" }
output "name" { value = var.name }
provider "aws" { region = "us-east-1" }
`

const resultsModule = `resource "aws_s3_bucket" "b" {
  count  = 2
  bucket = "b"
  acl    = "public-read"
}
`

// terraformResultsInput models the files in a temporary directory and
// returns the decoding input of its root and the scanned files.
func terraformResultsInput(t *testing.T, files map[string]string) (*terraformInput, map[string]*model.FileMetadata) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	var metas model.FileMetadatas
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		lines := strings.Split(content, "\n")
		metas = append(metas, &model.FileMetadata{
			ID: name, FilePath: path, Kind: model.KindTerraform, OriginalData: content, LinesOriginalData: &lines,
		})
	}
	scan, err := tfmodel.Load(context.Background(), dir, &tfmodel.Options{})
	require.NoError(t, err)
	require.Len(t, scan.Roots, 1)
	proj := project.Project(scan.Roots, project.Options{Placeholder: resultsTestPlaceholder})
	byID := map[string]*model.FileMetadata{}
	for _, f := range metas {
		byID[f.ID] = f
	}
	return &terraformInput{
		projection:  proj,
		base:        dir,
		files:       keyedFiles((&Inspector{fsys: vfs.DiskFS{}}).terraformFiles(metas)),
		repoPath:    dir,
		placeholder: resultsTestPlaceholder,
		outputLines: 3,
		attribution: &terraformAttribution{cache: newModuleAttributionCache()},
		written:     newWrittenFindings(),
	}, byID
}

func decodeBlockResult(t *testing.T, input *terraformInput, files map[string]*model.FileMetadata, result string) (*model.Vulnerability, *QueryContext, error) {
	t.Helper()
	var v any
	dec := json.NewDecoder(strings.NewReader(result))
	dec.UseNumber()
	require.NoError(t, dec.Decode(&v))
	qCtx := &QueryContext{
		Files: files,
		Query: &PreparedQuery{Metadata: model.QueryMetadata{
			Query: "rule",
			Metadata: map[string]interface{}{
				"id": "rule-id", "queryName": "Rule", "severity": "HIGH", "platform": "Terraform",
			},
		}},
		terraform: input,
	}
	vuln, err := DefaultVulnerabilityBuilder(context.Background(), qCtx, &trackerMock{}, v, nil, false, 0)
	return vuln, qCtx, err
}

type trackerMock struct{}

func (*trackerMock) TrackQueryLoad(int)       {}
func (*trackerMock) TrackQueryExecuting(int)  {}
func (*trackerMock) TrackQueryExecution(int)  {}
func (*trackerMock) FailedDetectLine()        {}
func (*trackerMock) FailedLineInfoDocument()  {}
func (*trackerMock) SkippedSupersededResult() {}
func (*trackerMock) GetOutputLines() int      { return 3 }

func TestTerraformBlockResult(t *testing.T) {
	input, files := terraformResultsInput(t, map[string]string{"main.tf": resultsMain, "mod/main.tf": resultsModule})

	tests := []struct {
		name, result      string
		line, remediation int
		searchKey         string
	}{
		{"block header", `{"_dd_id": "./aws_security_group.sg", "path": []}`, 1, 12, "aws_security_group.sg"},
		{"attribute", `{"_dd_id": "./aws_security_group.sg", "path": ["name"]}`, 2, 2, "aws_security_group.sg.name"},
		{"nested block element", `{"_dd_id": "./aws_security_group.sg", "path": ["ingress", 1, "from_port"]}`,
			10, 10, "aws_security_group.sg.ingress[1].from_port"},
		{"missing leaf", `{"_dd_id": "./aws_security_group.sg", "path": ["ingress", 0, "cidr_blocks"]}`,
			4, 5, "aws_security_group.sg.ingress[0].cidr_blocks"},
		{"key on a nested block list", `{"_dd_id": "./aws_security_group.sg", "path": ["ingress"], "key": 22}`,
			4, 5, `aws_security_group.sg.ingress["22"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _, err := decodeBlockResult(t, input, files, tt.result)
			require.NoError(t, err)
			require.Equal(t, tt.line, v.Line)
			require.Equal(t, files["main.tf"].FilePath, v.FileName)
			require.Equal(t, "main.tf", v.FileID)
			require.Equal(t, "aws_security_group", v.ResourceType)
			require.Equal(t, "sg", v.ResourceName)
			require.Equal(t, "aws_security_group.sg", v.ResourceID)
			require.Equal(t, ".", v.RootModule)
			require.Equal(t, tt.searchKey, v.SearchKey)
			require.Equal(t, "rule-id", v.QueryID)
			require.Equal(t, model.SeverityHigh, string(v.Severity))
			require.Equal(t, tt.line, v.VulnerabilityLocation.Start.Line, "the native detection range")
			require.Equal(t, 1, v.BlockLocation.Start.Line)
			require.Equal(t, 13, v.BlockLocation.End.Line)
			require.True(t, v.KeepDetectionLocation)
			require.Equal(t, tt.remediation, v.RemediationLocation.Start.Line, "the fix insertion point")
			summary := model.CreateSummary(context.Background(), model.Counters{}, []model.Vulnerability{*v}, "scan", nil, "/repo", model.SCIInfo{})
			require.True(t, summary.Queries[0].Files[0].KeepDetectionLocation)
			require.Equal(t, files["main.tf"].Lines(), v.FileSource, "fixes are built on the file's lines")
			require.Empty(t, v.ModuleCallChain)
		})
	}
	seenStaticKinds := map[string]bool{}
	for id, loc := range input.projection.Blocks {
		if loc.Block.Module.Address != "" {
			continue
		}
		switch loc.Kind {
		case address.KindVariable, address.KindOutput, address.KindProvider, address.KindModule:
			v, _, err := decodeBlockResult(t, input, files, `{"_dd_id":"`+id+`","path":[]}`)
			require.NoError(t, err)
			require.Equal(t, loc.Address, v.ResourceID, id)
			require.Equal(t, ".", v.RootModule, id)
			seenStaticKinds[loc.Kind] = true
		}
	}
	require.True(t, seenStaticKinds[address.KindVariable])
	require.True(t, seenStaticKinds[address.KindOutput])
	require.True(t, seenStaticKinds[address.KindProvider])
	require.True(t, seenStaticKinds[address.KindModule])
}

func TestTerraformBlockResult_ModuleInstance(t *testing.T) {
	input, files := terraformResultsInput(t, map[string]string{"main.tf": resultsMain, "mod/main.tf": resultsModule})

	v, _, err := decodeBlockResult(t, input, files,
		`{"_dd_id": "./module.m[1].aws_s3_bucket.b[0]", "path": ["acl"], "evidence": [["./aws_security_group.sg", ["name"]]]}`)
	require.NoError(t, err)
	require.Equal(t, files["mod/main.tf"].FilePath, v.FileName)
	require.Equal(t, 4, v.Line)
	require.Equal(t, "aws_s3_bucket", v.ResourceType)
	require.Equal(t, "b", v.ResourceName, "no resource instance key; the module key is in ModuleCallChain")
	require.Equal(t, "main.tf|module.m[1]", v.ModuleCallChain)
	require.Equal(t, "module.m[1].aws_s3_bucket.b[0]", v.ResourceID)
	require.Equal(t, ".", v.RootModule)
	require.NotNil(t, v.ModuleAttribution)
	require.Equal(t, "main.tf", v.ModuleAttribution.CallSite.Filename)
	require.Equal(t, 16, v.ModuleAttribution.CallSite.LineStart, "the root call's source argument")
	require.Equal(t, []model.SourceLocation{{Filename: "main.tf", LineStart: 2, LineEnd: 2, ColumnStart: 3, ColumnEnd: 14}},
		v.RelatedLocations)
}

func TestLegacyModuleAddressSpellingPreservesLegacyIdentity(t *testing.T) {
	keys := []string{
		"plain",
		`quote" and slash\\`,
		`${literal} %{template}`,
		"line\nbreak and \x00 control",
		"snowman ☃",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			canonical := "module.m" + address.InstanceSuffix(cty.StringVal(key)) + ".module.n[2]"
			traversal, diags := hclsyntax.ParseTraversalAbs([]byte(canonical), "address", hcl.InitialPos)
			require.False(t, diags.HasErrors(), "%s", diags.Error())
			var foundKey bool
			for _, step := range traversal {
				if idx, ok := step.(hcl.TraverseIndex); ok && idx.Key.Type() == cty.String {
					require.Equal(t, key, idx.Key.AsString(), "canonical address round-trips its raw key")
					foundKey = true
				}
			}
			require.True(t, foundKey)

			legacyModule := `module.m["` + key + `"].module.n[2]`
			require.Equal(t, legacyModule, legacyModuleAddress(canonical))
			chain := legacyModuleCallChainKey([]tfeval.CallSite{{CalledFrom: "stack/main.tf"}}, canonical, "/repo")
			require.Equal(t, "stack/main.tf|"+legacyModule, chain)

			v := model.Vulnerability{
				FileName: "modules/m/main.tf", Platform: model.TerraformPlatform,
				ResourceType: "aws_s3_bucket", ResourceName: "bucket", QueryID: "legacy-rule",
				ModuleCallChain: chain,
			}
			wantFingerprint := model.GetDatadogFingerprintHash(
				model.SCIInfo{}, filepath.FromSlash(v.FileName), v.Platform, v.ResourceType, v.ResourceName,
				v.QueryID, "", "stack/main.tf|"+legacyModule,
			)
			summary := model.CreateSummary(context.Background(), model.Counters{}, []model.Vulnerability{v}, "scan", nil, "/repo", model.SCIInfo{})
			require.Equal(t, wantFingerprint, summary.Queries[0].Files[0].Fingerprint)
		})
	}
}

func TestTerraformBlockResult_SpecialModuleKeyKeepsCanonicalAddress(t *testing.T) {
	key := `quote" slash\\ ${literal} %{template}`
	literal := string(hclwrite.TokensForValue(cty.StringVal(key)).Bytes())
	input, files := terraformResultsInput(t, map[string]string{
		"main.tf": fmt.Sprintf(`module "m" {
  for_each = toset([%s])
  source   = "./mod"
}
`, literal),
		"mod/main.tf": `resource "aws_s3_bucket" "b" {
  acl = "public-read"
}
`,
	})
	canonicalModule := "module.m" + address.InstanceSuffix(cty.StringVal(key))
	result, err := json.Marshal(map[string]interface{}{
		"_dd_id": "./" + canonicalModule + ".aws_s3_bucket.b",
		"path":   []string{},
	})
	require.NoError(t, err)
	v, _, err := decodeBlockResult(t, input, files, string(result))
	require.NoError(t, err)
	legacyChain := "main.tf|" + legacyModuleAddress(canonicalModule)
	require.Equal(t, legacyChain, v.ModuleCallChain)
	require.Equal(t, "b", v.ResourceName)
	require.Equal(t, canonicalModule+".aws_s3_bucket.b", v.ResourceID)
	require.Equal(t, ".", v.RootModule)
	summary := model.CreateSummary(context.Background(), model.Counters{}, []model.Vulnerability{*v}, "scan", nil, "/repo", model.SCIInfo{})
	wantFingerprint := model.GetDatadogFingerprintHash(
		model.SCIInfo{}, summary.Queries[0].Files[0].FileName, v.Platform, v.ResourceType, v.ResourceName,
		v.QueryID, "", legacyChain,
	)
	require.Equal(t, wantFingerprint, summary.Queries[0].Files[0].Fingerprint)
}

// Native reporting keeps the historical bare ResourceName while ResourceID
// carries the canonical count or for_each address.
func TestTerraformBlockResult_InstanceResourceID(t *testing.T) {
	input, files := terraformResultsInput(t, map[string]string{
		"main.tf": `
resource "aws_db_instance" "db" {
  count               = 2
  identifier          = "db-${count.index}"
  publicly_accessible = true
}

resource "aws_s3_bucket" "b" {
  for_each = toset(["open", "closed"])
  bucket   = each.key
  acl      = "public-read"
}

resource "aws_s3_bucket" "special" {
  for_each = {
    "$${literal}"  = "dollar"
    "%%{template}" = "percent"
  }
  bucket = each.key
  acl    = "public-read"
}
`,
	})

	db, _, err := decodeBlockResult(t, input, files, `{"_dd_id": "./aws_db_instance.db[0]", "path": ["publicly_accessible"]}`)
	require.NoError(t, err)
	require.Equal(t, "aws_db_instance", db.ResourceType)
	require.Equal(t, "db", db.ResourceName)
	require.Equal(t, "aws_db_instance.db[0]", db.ResourceID)
	require.Equal(t, "aws_db_instance.db[0].publicly_accessible", db.SearchKey)

	open, _, err := decodeBlockResult(t, input, files, `{"_dd_id": "./aws_s3_bucket.b[\"open\"]", "path": ["acl"]}`)
	require.NoError(t, err)
	require.Equal(t, "b", open.ResourceName)
	require.Equal(t, `aws_s3_bucket.b["open"]`, open.ResourceID)
	require.Equal(t, ".", open.RootModule)
	require.Equal(t, `aws_s3_bucket.b["open"].acl`, open.SearchKey)

	closed, _, err := decodeBlockResult(t, input, files, `{"_dd_id": "./aws_s3_bucket.b[\"closed\"]", "path": ["acl"]}`)
	require.NoError(t, err)
	require.Equal(t, "b", closed.ResourceName)
	require.Equal(t, closed.ResourceID, "aws_s3_bucket.b[\"closed\"]")
	require.Equal(t, model.FindingIdentity(open), model.FindingIdentity(closed),
		"HCL finding identity keeps main's historical bare block name")
	aclOtherPath, _, err := decodeBlockResult(t, input, files, `{"_dd_id": "./aws_s3_bucket.b[\"open\"]", "path": ["bucket"]}`)
	require.NoError(t, err)
	require.Equal(t, model.FindingIdentity(open), model.FindingIdentity(aclOtherPath),
		"different attribute paths on the same resource keep main's identity semantics")

	rawKey := "${literal}"
	suffix := address.InstanceSuffix(cty.StringVal(rawKey))
	result, err := json.Marshal(map[string]interface{}{"_dd_id": "./aws_s3_bucket.special" + suffix, "path": []string{}})
	require.NoError(t, err)
	special, _, err := decodeBlockResult(t, input, files, string(result))
	require.NoError(t, err)
	require.Equal(t, "special", special.ResourceName)
	require.Equal(t, "aws_s3_bucket.special"+suffix, special.ResourceID)
	require.Equal(t, "aws_s3_bucket.special"+suffix, special.SearchKey)
	require.Equal(t, ".", special.RootModule)
	summary := model.CreateSummary(context.Background(), model.Counters{}, []model.Vulnerability{*special}, "scan", nil, "/repo", model.SCIInfo{})
	wantFingerprint := model.GetDatadogFingerprintHash(
		model.SCIInfo{}, summary.Queries[0].Files[0].FileName, special.Platform, special.ResourceType,
		special.ResourceName, special.QueryID, "", "",
	)
	require.Equal(t, wantFingerprint, summary.Queries[0].Files[0].Fingerprint)

	t.Run("plan keeps its historical qualified instance name", func(t *testing.T) {
		repo := t.TempDir()
		planPath := filepath.Join(repo, "stacks", "prod", "tfplan.json")
		require.NoError(t, os.MkdirAll(filepath.Dir(planPath), 0o755))
		plan := `{"format_version":"1.2","terraform_version":"1.6.0",
"planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.this[\"${literal}\"]","mode":"managed","type":"aws_s3_bucket","name":"this","index":"${literal}","values":{"bucket":"literal"},"sensitive_values":{}}],"child_modules":[{"address":"module.m[\"modkey\"]","resources":[{"address":"module.m[\"modkey\"].aws_s3_bucket.child[\"${literal}\"]","mode":"managed","type":"aws_s3_bucket","name":"child","index":"${literal}","values":{"bucket":"literal"},"sensitive_values":{}}]}]}},
"configuration":{"root_module":{"resources":[{"address":"aws_s3_bucket.this","mode":"managed","type":"aws_s3_bucket","name":"this","provider_config_key":"aws","expressions":{"bucket":{"constant_value":"literal"}},"schema_version":0}],"module_calls":{"m":{"source":"./m","for_each_expression":{"constant_value":["modkey"]},"module":{"resources":[{"address":"aws_s3_bucket.child","mode":"managed","type":"aws_s3_bucket","name":"child","provider_config_key":"aws","expressions":{"bucket":{"constant_value":"literal"}},"schema_version":0}]}}}}}}`
		require.NoError(t, os.WriteFile(planPath, []byte(plan), 0o600))
		scan, err := tfmodel.Load(context.Background(), repo, &tfmodel.Options{Plans: []string{planPath}})
		require.NoError(t, err)
		require.Len(t, scan.Roots, 1)
		require.False(t, scan.Roots[0].Degraded, "%#v", scan.Roots[0].Notes)
		projection := project.Project(scan.Roots, project.Options{Placeholder: resultsTestPlaceholder})
		var blockID, canonicalID, moduleBlockID, moduleCanonicalID string
		for id, loc := range projection.Blocks {
			if loc.Kind != address.KindResource || loc.Type != "aws_s3_bucket" {
				continue
			}
			switch loc.Block.Name {
			case "this":
				blockID, canonicalID = id, loc.Address
			case "child":
				moduleBlockID, moduleCanonicalID = id, loc.Address
			}
		}
		require.NotEmpty(t, blockID, "%#v", projection.Blocks)
		require.NotEmpty(t, moduleBlockID)
		lines := strings.Split(plan, "\n")
		file := &model.FileMetadata{ID: "plan", FilePath: planPath, Kind: model.KindTerraformPlan,
			OriginalData: plan, LinesOriginalData: &lines}
		input := &terraformInput{
			projection: projection, base: repo, repoPath: repo,
			files:       keyedFiles(map[string]*model.FileMetadata{planPath: file}),
			placeholder: resultsTestPlaceholder, outputLines: 3,
			attribution: &terraformAttribution{cache: newModuleAttributionCache()}, written: newWrittenFindings(),
		}
		for _, tc := range []struct {
			blockID, canonicalID, name string
		}{
			{blockID, canonicalID, `this["${literal}"]`},
			{moduleBlockID, moduleCanonicalID, `module.m["modkey"].child["${literal}"]`},
		} {
			result, err := json.Marshal(map[string]interface{}{"_dd_id": tc.blockID, "path": []string{}})
			require.NoError(t, err)
			v, _, err := decodeBlockResult(t, input, map[string]*model.FileMetadata{"plan": file}, string(result))
			require.NoError(t, err)
			require.Equal(t, tc.name, v.ResourceName)
			require.Equal(t, tc.canonicalID, v.ResourceID)
			require.Equal(t, "stacks/prod/tfplan.json", v.RootModule)
			require.Empty(t, v.ModuleCallChain)
			summary := model.CreateSummary(context.Background(), model.Counters{}, []model.Vulnerability{*v}, "scan", nil, repo, model.SCIInfo{})
			want := model.GetDatadogFingerprintHash(model.SCIInfo{}, summary.Queries[0].Files[0].FileName,
				v.Platform, v.ResourceType, v.ResourceName, v.QueryID, "", "")
			require.Equal(t, want, summary.Queries[0].Files[0].Fingerprint)
		}
	})
}

func TestTerraformBlockResult_Errors(t *testing.T) {
	input, files := terraformResultsInput(t, map[string]string{"main.tf": resultsMain, "mod/main.tf": resultsModule})

	_, qCtx, err := decodeBlockResult(t, input, files, `{"_dd_id": "./aws_s3_bucket.none", "path": []}`)
	require.ErrorIs(t, err, errUnknownBlock)
	require.Equal(t, 1, qCtx.unknownBlocks)

	_, _, err = decodeBlockResult(t, input, files, `{"_dd_id": "./aws_security_group.sg", "path": "name"}`)
	require.Error(t, err)

	_, qCtx, err = decodeBlockResult(t, nil, files, `{"_dd_id": "./aws_security_group.sg", "path": []}`)
	require.ErrorIs(t, err, errUnknownBlock, "a block result outside a Terraform v2 evaluation")
	require.Equal(t, 1, qCtx.unknownBlocks)
}

func TestTerraformBlockResult_PlaceholderInRemediation(t *testing.T) {
	input, files := terraformResultsInput(t, map[string]string{"main.tf": resultsMain})
	v, _, err := decodeBlockResult(t, input, files, `{"_dd_id": "./aws_security_group.sg", "path": ["name"],
		"remediation": "name = \"\u0000dd-unknown-test\"", "remediationType": "replacement"}`)
	require.NoError(t, err)
	require.Equal(t, `name = "${...}"`, v.Remediation)
}

// Blocks written once in a module (variables, nested module calls) are
// reported once on what is written, however many instances model them.
func TestTerraformBlockResult_ModuleStaticBlocksOnce(t *testing.T) {
	input, files := terraformResultsInput(t, map[string]string{
		"main.tf": resultsMain,
		"mod/main.tf": resultsModule + `
variable "name" {}

module "inner" {
  source = "./inner"
}
`,
		"mod/inner/main.tf": `variable "x" {}`,
	})
	decoded := map[string]int{}
	for id, loc := range input.projection.Blocks {
		if loc.Block.Module == nil || loc.Block.Module.Address == "" {
			continue
		}
		v, _, err := decodeBlockResult(t, input, files, `{"_dd_id": "`+id+`", "path": []}`)
		if errors.Is(err, ErrNoResult) {
			continue
		}
		require.NoError(t, err)
		decoded[loc.Kind+" "+v.SearchKey]++
		if staticInModule(loc) {
			require.Nil(t, v.ModuleAttribution, id)
			require.Empty(t, v.ModuleCallChain, id)
			require.Empty(t, v.ResourceID, id)
			require.Empty(t, v.RootModule, id)
		} else if loc.Kind == address.KindResource {
			require.NotEmpty(t, v.ResourceID, id)
			require.Equal(t, ".", v.RootModule, id)
		}
	}
	require.Equal(t, map[string]int{
		"resource module.m[0].aws_s3_bucket.b[0]": 1,
		"resource module.m[0].aws_s3_bucket.b[1]": 1,
		"resource module.m[1].aws_s3_bucket.b[0]": 1,
		"resource module.m[1].aws_s3_bucket.b[1]": 1,
		"variable var.name":                       1,
		"variable var.x":                          1,
		"module module.inner":                     1,
	}, decoded)
}

// The in-memory filesystem keys files by slash paths; a lookup built with the
// OS separator still finds them.
func TestTerraformInputFileMatchesSlashPaths(t *testing.T) {
	f := &model.FileMetadata{ID: "main.tf"}
	input := &terraformInput{files: keyedFiles(map[string]*model.FileMetadata{"/repo/stack/../main.tf": f})}
	require.Same(t, f, input.file("/repo/main.tf"))
	require.Same(t, f, input.file(project.JoinRoot("/repo", "main.tf")))
	if runtime.GOOS == "windows" {
		require.Same(t, f, input.file(`\repo\main.tf`))
	}
}
