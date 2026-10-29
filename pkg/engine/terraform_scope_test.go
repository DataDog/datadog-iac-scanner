/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/stretchr/testify/require"
)

func TestRepoRelativeDirNeverEscapesTheRepository(t *testing.T) {
	require.Equal(t, "stack/modules/bucket", repoRelativeDir("/repo/stack/modules/bucket", "/repo", nil))
	require.Equal(t, ".", repoRelativeDir("/repo", "/repo", nil))
	// A directory outside the repository (an external or remote module) is
	// named relative to the innermost external root containing it.
	outside := repoRelativeDir("/tmp/modules-x/bucket", "/repo", map[string]bool{"/tmp/modules-x": true})
	require.Equal(t, "modules-x/bucket", outside)
	require.NotContains(t, outside, "..")
	// Without a matching external root it falls back to the directory name.
	require.Equal(t, "bucket", repoRelativeDir("/tmp/other/bucket", "/repo", nil))
	// Content-push mode keeps the pushed path shape.
	require.Equal(t, "stack", repoRelativeDir("stack", "", nil))
}

func TestDocumentBlocks(t *testing.T) {
	doc := model.Document{
		"resource": model.Document{
			"aws_s3_bucket": model.Document{"this": model.Document{}, "_dd_lines": model.Document{}},
			"aws_sqs_queue": []interface{}{model.Document{}},
		},
		"moved":     []interface{}{model.Document{}, model.Document{}},
		"data":      model.Document{"aws_ami": model.Document{"ubuntu": model.Document{}}},
		"module":    model.Document{"network": model.Document{}},
		"variable":  model.Document{"size": model.Document{}},
		"output":    model.Document{"config": model.Document{}},
		"check":     model.Document{"health": model.Document{}},
		"locals":    model.Document{"name": "value"},
		"provider":  model.Document{"aws": []interface{}{model.Document{"alias": "west"}, model.Document{}}},
		"terraform": model.Document{},
	}
	blocks := documentBlocks(doc)
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindResource, Type: "aws_s3_bucket", Name: "this"}])
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindData, Type: "aws_ami", Name: "ubuntu"}])
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindModule, Name: "network"}])
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindVariable, Name: "size"}])
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindOutput, Name: "config"}])
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindCheck, Name: "health"}])
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindLocal, Name: "name"}])
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindProvider, Type: "aws", Name: "west"}])
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindProvider, Type: "aws", Name: ""}])
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindTerraform}])
	// Repeated blocks: a nameless resource parses to a list (its type is still
	// declared) and repeated unlabeled blocks (moved) are indexed so two moved
	// blocks never share an identity.
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindResource, Type: "aws_sqs_queue"}])
	require.True(t, blocks[model.TerraformBlock{Kind: "moved", Name: "0"}])
	require.True(t, blocks[model.TerraformBlock{Kind: "moved", Name: "1"}])
	require.False(t, blocks[model.TerraformBlock{Kind: "moved"}],
		"two repeated blocks must not collapse onto the bare type")
	// A lone unlabeled block keeps the bare type.
	doc["import"] = model.Document{}
	require.True(t, documentBlocks(doc)[model.TerraformBlock{Kind: "import"}])
	// Underscore labels are legal Terraform and are indexed; only the
	// parser's exact bookkeeping keys are skipped.
	doc["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["_secret"] = model.Document{}
	doc["variable"].(model.Document)["_dd_config"] = model.Document{}
	blocks = documentBlocks(doc)
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindResource, Type: "aws_s3_bucket", Name: "_secret"}])
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindVariable, Name: "_dd_config"}],
		"a label starting with _dd_ is legal Terraform, not bookkeeping")
	require.False(t, blocks[model.TerraformBlock{Kind: address.KindResource, Type: "aws_s3_bucket", Name: "_dd_lines"}],
		"parser bookkeeping keys are not blocks")
}

// resolveTerraformBlock must map a rule's kind+name onto the block it names,
// and fall back to data when the pair is only declared as a data block.
func TestResolveTerraformBlock(t *testing.T) {
	scope := &model.TerraformScope{Blocks: map[model.TerraformBlock]bool{
		{Kind: address.KindResource, Type: "aws_s3_bucket", Name: "this"}: true,
		{Kind: address.KindData, Type: "aws_ami", Name: "ubuntu"}:         true,
	}}

	block, ok := resolveTerraformBlock(scope, "aws_s3_bucket", "this")
	require.True(t, ok)
	require.Equal(t, address.Block{Kind: address.KindResource, Type: "aws_s3_bucket", Name: "this"}, block)

	// A data rule may name its type without the "data." prefix.
	block, ok = resolveTerraformBlock(scope, "aws_ami", "ubuntu")
	require.True(t, ok)
	require.Equal(t, address.Block{Kind: address.KindData, Type: "aws_ami", Name: "ubuntu"}, block)
	block, ok = resolveTerraformBlock(scope, "data.aws_ami", "ubuntu")
	require.True(t, ok)
	require.Equal(t, address.Block{Kind: address.KindData, Type: "aws_ami", Name: "ubuntu"}, block)

	// A pair naming no declared block misses, both unprefixed and prefixed.
	_, ok = resolveTerraformBlock(scope, "aws_s3_bucket", "other")
	require.False(t, ok)
	_, ok = resolveTerraformBlock(scope, "data.aws_s3_bucket", "other")
	require.False(t, ok)

	// Indexed unlabeled blocks resolve by their list index; an empty name
	// against an indexed declaration cannot pick a block.
	indexed := &model.TerraformScope{Blocks: map[model.TerraformBlock]bool{
		{Kind: "moved", Name: "0"}: true,
		{Kind: "moved", Name: "1"}: true,
	}}
	block, ok = resolveTerraformBlock(indexed, "moved", "1")
	require.True(t, ok)
	require.Equal(t, address.Block{Kind: "moved", Name: "1"}, block)
	_, ok = resolveTerraformBlock(indexed, "moved", "")
	require.False(t, ok)
	_, ok = resolveTerraformBlock(indexed, "moved", "2")
	require.False(t, ok)

	// Without a document to verify against, the pair is accepted as named.
	_, ok = resolveTerraformBlock(&model.TerraformScope{}, "variable", "size")
	require.True(t, ok)

	// Ephemeral blocks resolve with and without the "ephemeral." prefix.
	ephemeral := &model.TerraformScope{Blocks: map[model.TerraformBlock]bool{
		{Kind: address.KindEphemeral, Type: "aws_secret", Name: "login"}: true,
	}}
	block, ok = resolveTerraformBlock(ephemeral, "ephemeral.aws_secret", "login")
	require.True(t, ok)
	require.Equal(t, address.Block{Kind: address.KindEphemeral, Type: "aws_secret", Name: "login"}, block)
	block, ok = resolveTerraformBlock(ephemeral, "aws_secret", "login")
	require.True(t, ok, "an unprefixed ephemeral type falls back to the ephemeral block")
	require.Equal(t, address.Block{Kind: address.KindEphemeral, Type: "aws_secret", Name: "login"}, block)
}

// A provider rule resolves exactly: an aliased name never resolves to the
// default provider and a bare name never resolves to an alias.
func TestResolveTerraformBlock_ProviderAliasIsExact(t *testing.T) {
	scope := &model.TerraformScope{Blocks: map[model.TerraformBlock]bool{
		{Kind: address.KindProvider, Type: "aws", Name: "west"}: true,
	}}
	block, ok := resolveTerraformBlock(scope, "provider", "aws.west")
	require.True(t, ok)
	require.Equal(t, address.Block{Kind: address.KindProvider, Type: "aws", Name: "west"}, block)

	// The bare name names the default provider, which the file does not
	// declare: it is an identity gap, not the aliased block.
	_, ok = resolveTerraformBlock(scope, "provider", "aws")
	require.False(t, ok)

	def := &model.TerraformScope{Blocks: map[model.TerraformBlock]bool{
		{Kind: address.KindProvider, Type: "aws", Name: ""}: true,
	}}
	block, ok = resolveTerraformBlock(def, "provider", "aws")
	require.True(t, ok)
	require.Equal(t, address.Block{Kind: address.KindProvider, Type: "aws", Name: ""}, block)
	_, ok = resolveTerraformBlock(def, "provider", "aws.west")
	require.False(t, ok)
}

// Repeated unlabeled blocks are indexed module-wide for the address, while
// the declaration keys rules actually report stay file-local: two files of
// one root each declaring a moved block resolve their own block and carry
// distinct addresses (K9CODESEC-7158).
func TestStampTerraformScopes_UnlabeledBlocksIndexedModuleWide(t *testing.T) {
	dir := t.TempDir()
	fileA := filepath.Join(dir, "a.tf")
	fileB := filepath.Join(dir, "b.tf")
	require.NoError(t, os.WriteFile(fileA, []byte(`
moved {
  from = aws_a.first
  to   = aws_b.first
}
`), 0o644))
	require.NoError(t, os.WriteFile(fileB, []byte(`
moved {
  from = aws_a.second
  to   = aws_b.second
}
`), 0o644))
	files := model.FileMetadatas{parseTerraform(t, fileA)[0], parseTerraform(t, fileB)[0]}

	ins := &Inspector{repoPath: dir}
	ins.stampTerraformScopes(files)

	// The declarations rules report are untouched: a lone moved block keeps
	// its file-local identity in both files.
	for i, f := range files {
		scope := f.TerraformScope
		require.True(t, scope.Blocks[model.TerraformBlock{Kind: "moved", Name: ""}],
			"file %d keeps its local declaration key", i)
		require.False(t, scope.Blocks[model.TerraformBlock{Kind: "moved", Name: "0"}],
			"declaration keys are never rewritten to module-wide indexes")
	}

	// The module-wide index lives in its own map and makes the addresses
	// distinct without touching the declarations.
	block, ok := resolveTerraformBlock(files[0].TerraformScope, "moved", "")
	require.True(t, ok)
	require.Equal(t, "moved.0", terraformInstanceAddress(files[0].TerraformScope, block))
	block, ok = resolveTerraformBlock(files[1].TerraformScope, "moved", "")
	require.True(t, ok, "file b still declares its own moved block")
	require.Equal(t, "moved.1", terraformInstanceAddress(files[1].TerraformScope, block))
	require.NotEqual(t,
		terraformInstanceAddress(files[0].TerraformScope, block),
		terraformInstanceAddress(files[1].TerraformScope, block))

	// A lone moved block in a module keeps the bare address: no index entry,
	// no invented name.
	solo := filepath.Join(t.TempDir(), "solo.tf")
	require.NoError(t, os.WriteFile(solo, []byte("moved {\n  from = aws_a.x\n  to = aws_b.x\n}\n"), 0o644))
	soloFiles := model.FileMetadatas{parseTerraform(t, solo)[0]}
	(&Inspector{repoPath: filepath.Dir(solo)}).stampTerraformScopes(soloFiles)
	block, ok = resolveTerraformBlock(soloFiles[0].TerraformScope, "moved", "")
	require.True(t, ok)
	require.Equal(t, "moved", terraformInstanceAddress(soloFiles[0].TerraformScope, block))
}

// A block whose label starts with an underscore is content, not bookkeeping:
// removing an instantiated sibling must not drop it with the line markers.
func TestRemoveInstantiatedResources_KeepsUnderscoreNamedBlocks(t *testing.T) {
	doc := model.Document{
		"resource": model.Document{
			"aws_s3_bucket": model.Document{
				"_dd_lines":  model.Document{},
				"instance":   model.Document{},
				"_secret":    model.Document{},
				"_dd_config": model.Document{},
			},
		},
	}
	removeInstantiatedResources(doc, map[string]map[string]bool{
		"aws_s3_bucket": {"instance": true},
	})
	buckets, _ := asStringMap(doc["resource"])
	byType, _ := asStringMap(buckets["aws_s3_bucket"])
	require.Contains(t, byType, "_secret", "an underscore-named block is content")
	require.Contains(t, byType, "_dd_config", "a _dd_-prefixed label is legal Terraform, not bookkeeping")
	require.NotContains(t, byType, "instance")
	require.True(t, onlyMetadataKeys(map[string]interface{}{"_dd_lines": model.Document{}, "_dd__default": model.Document{}}))
	require.False(t, onlyMetadataKeys(map[string]interface{}{"_secret": model.Document{}}))
}
