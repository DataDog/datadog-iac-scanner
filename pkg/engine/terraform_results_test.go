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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
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
`

const resultsModule = `resource "aws_s3_bucket" "b" {
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
	scan, err := tfmodel.Load(context.Background(), dir, tfmodel.Options{})
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
		name, result           string
		line, remediation      int
		searchKey, identityKey string
	}{
		{"block header", `{"_dd_id": "./aws_security_group.sg", "path": []}`, 1, 12, "aws_security_group.sg", ""},
		{"attribute", `{"_dd_id": "./aws_security_group.sg", "path": ["name"]}`, 2, 2, "aws_security_group.sg.name", `[["name"],""]`},
		{"nested block element", `{"_dd_id": "./aws_security_group.sg", "path": ["ingress", 1, "from_port"]}`,
			10, 10, "aws_security_group.sg.ingress[1].from_port", `[["ingress","1","from_port"],""]`},
		{"missing leaf", `{"_dd_id": "./aws_security_group.sg", "path": ["ingress", 0, "cidr_blocks"]}`,
			4, 5, "aws_security_group.sg.ingress[0].cidr_blocks", `[["ingress","0","cidr_blocks"],""]`},
		{"key on a nested block list", `{"_dd_id": "./aws_security_group.sg", "path": ["ingress"], "key": 22}`,
			4, 5, `aws_security_group.sg.ingress["22"]`, `[["ingress"],"22"]`},
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
			require.Equal(t, tt.searchKey, v.SearchKey)
			require.Equal(t, tt.identityKey, v.IdentityKey)
			require.Equal(t, "rule-id", v.QueryID)
			require.Equal(t, model.SeverityHigh, string(v.Severity))
			require.Equal(t, 1, v.VulnerabilityLocation.Start.Line)
			require.Equal(t, 13, v.VulnerabilityLocation.End.Line)
			require.Equal(t, tt.remediation, v.RemediationLocation.Start.Line, "the legacy insertion point")
			require.Equal(t, files["main.tf"].Lines(), v.FileSource, "fixes are built on the file's lines")
			require.Empty(t, v.ModuleCallChain)
		})
	}
}

func TestTerraformBlockResult_ModuleInstance(t *testing.T) {
	input, files := terraformResultsInput(t, map[string]string{"main.tf": resultsMain, "mod/main.tf": resultsModule})

	v, _, err := decodeBlockResult(t, input, files,
		`{"_dd_id": "./module.m[1].aws_s3_bucket.b", "path": ["acl"], "evidence": [["./aws_security_group.sg", ["name"]]]}`)
	require.NoError(t, err)
	require.Equal(t, files["mod/main.tf"].FilePath, v.FileName)
	require.Equal(t, 3, v.Line)
	require.Equal(t, "aws_s3_bucket", v.ResourceType)
	require.Equal(t, "b", v.ResourceName, "no resource instance key; the module key is in ModuleCallChain")
	require.Equal(t, "main.tf|module.m[1]", v.ModuleCallChain)
	require.NotNil(t, v.ModuleAttribution)
	require.Equal(t, "main.tf", v.ModuleAttribution.CallSite.Filename)
	require.Equal(t, 16, v.ModuleAttribution.CallSite.LineStart, "the root call's source argument")
	require.Equal(t, []model.SourceLocation{{Filename: "main.tf", LineStart: 2, LineEnd: 2, ColumnStart: 3, ColumnEnd: 14}},
		v.RelatedLocations)
}

// Root count and for_each instances put the instance key in ResourceName so
// SARIF resource identity and FindingIdentity tell them apart.
func TestTerraformBlockResult_InstanceKeyInResourceName(t *testing.T) {
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
`,
	})

	db, _, err := decodeBlockResult(t, input, files, `{"_dd_id": "./aws_db_instance.db[0]", "path": ["publicly_accessible"]}`)
	require.NoError(t, err)
	require.Equal(t, "aws_db_instance", db.ResourceType)
	require.Equal(t, "db[0]", db.ResourceName)
	require.Equal(t, "aws_db_instance.db[0].publicly_accessible", db.SearchKey)
	require.Equal(t, `[["publicly_accessible"],""]`, db.IdentityKey)

	open, _, err := decodeBlockResult(t, input, files, `{"_dd_id": "./aws_s3_bucket.b[\"open\"]", "path": ["acl"]}`)
	require.NoError(t, err)
	require.Equal(t, `b["open"]`, open.ResourceName)
	require.Equal(t, `aws_s3_bucket.b["open"].acl`, open.SearchKey)

	closed, _, err := decodeBlockResult(t, input, files, `{"_dd_id": "./aws_s3_bucket.b[\"closed\"]", "path": ["acl"]}`)
	require.NoError(t, err)
	require.Equal(t, `b["closed"]`, closed.ResourceName)
	require.NotEqual(t, model.FindingIdentity(open), model.FindingIdentity(closed),
		"instance keys in ResourceName keep for_each findings distinct")
	require.Equal(t, open.IdentityKey, closed.IdentityKey, "IdentityKey is still the path/key pair")
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

func TestFindingIdentity_BlockResultKey(t *testing.T) {
	a := model.Vulnerability{FileName: "main.tf", Platform: "Terraform", ResourceType: "t", ResourceName: "n", QueryID: "q"}
	b := a
	b.IdentityKey = `[["ingress"],"22"]`
	require.NotEqual(t, model.FindingIdentity(&a), model.FindingIdentity(&b))
	idA, _ := model.IdentityBeforeLine(&a)
	idB, _ := model.IdentityBeforeLine(&b)
	require.Equal(t, model.FindingIdentity(&b), idB.WithChain(""))
	require.NotEqual(t, idA.WithChain(""), idB.WithChain(""))

	keyed := a
	keyed.ResourceName = `n["open"]`
	require.NotEqual(t, model.FindingIdentity(&a), model.FindingIdentity(&keyed),
		"ResourceName instance keys distinguish findings even with the same IdentityKey")
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
		}
	}
	require.Equal(t, map[string]int{
		"resource module.m[0].aws_s3_bucket.b": 1,
		"resource module.m[1].aws_s3_bucket.b": 1,
		"variable var.name":                    1,
		"variable var.x":                       1,
		"module module.inner":                  1,
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
