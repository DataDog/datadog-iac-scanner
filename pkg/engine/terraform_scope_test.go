/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
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
// distinct addresses.
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

// Terraform merges the terraform {} blocks of a module, so one per file is
// legal; each keeps its own address.
func TestStampTerraformScopes_TerraformBlocksIndexedModuleWide(t *testing.T) {
	dir := t.TempDir()
	fileA := filepath.Join(dir, "a.tf")
	fileB := filepath.Join(dir, "b.tf")
	require.NoError(t, os.WriteFile(fileA, []byte("terraform {\n  required_version = \">= 1.5\"\n}\n"), 0o644))
	require.NoError(t, os.WriteFile(fileB, []byte("terraform {\n  backend \"s3\" {}\n}\n"), 0o644))
	files := model.FileMetadatas{parseTerraform(t, fileA)[0], parseTerraform(t, fileB)[0]}
	(&Inspector{repoPath: dir}).stampTerraformScopes(files)

	for i, want := range []string{"terraform.0", "terraform.1"} {
		block, ok := resolveTerraformBlock(files[i].TerraformScope, "terraform", "")
		require.True(t, ok)
		require.Equal(t, want, terraformInstanceAddress(files[i].TerraformScope, block))
	}
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

func TestStampTerraformScopesAddsMeta(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "envs", "prod", "main.tf")
	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
	require.NoError(t, os.WriteFile(file, []byte(`
resource "aws_s3_bucket" "b" {
  bucket = "x"
}
data "aws_iam_policy_document" "p" {
  version = "2012-10-17"
}
ephemeral "random_password" "pw" {
  length = 8
}
`), 0o644))
	files := model.FileMetadatas{parseTerraform(t, file)[0]}
	(&Inspector{repoPath: dir}).stampTerraformScopes(files)

	want := func(addr, attr, provider string) map[string]interface{} {
		return map[string]interface{}{"address": addr, configuredKey: map[string]interface{}{attr: true}, "provider": provider}
	}
	for section, c := range map[string][5]string{
		"resource":       {"aws_s3_bucket", "b", "aws_s3_bucket.b", "bucket", "aws"},
		"data":           {"aws_iam_policy_document", "p", "data.aws_iam_policy_document.p", "version", "aws"},
		ephemeralSection: {"random_password", "pw", "ephemeral.random_password.pw", "length", "random"},
	} {
		sec, _ := asStringMap(files[0].Document[section])
		byType, _ := asStringMap(sec[c[0]])
		block, ok := asStringMap(byType[c[1]])
		require.True(t, ok, section)
		require.Equal(t, want(c[2], c[3], c[4]), block[ddMetaKey], section)
	}
}

func TestStampTerraformScopesKeepsListShapedTypesAndReplacesUserMeta(t *testing.T) {
	list := []interface{}{map[string]interface{}{"a": 1}}
	doc := model.Document{
		"resource": map[string]interface{}{
			"aws_x": list,
			"aws_y": map[string]interface{}{
				"n": map[string]interface{}{ddMetaKey: map[string]interface{}{"address": "user"}},
				"s": map[string]interface{}{ddMetaKey: "user"},
			},
		},
	}
	stampWrittenMeta(doc)
	res, _ := asStringMap(doc["resource"])
	require.Equal(t, []interface{}{map[string]interface{}{"a": 1}}, res["aws_x"])
	y, _ := asStringMap(res["aws_y"])
	want := resourceMeta("aws_y.n", blockMetaExtras{})
	n, _ := asStringMap(y["n"])
	require.Equal(t, want, n[ddMetaKey])
	str, _ := asStringMap(y["s"])
	require.Equal(t, resourceMeta("aws_y.s", blockMetaExtras{}), str[ddMetaKey])
}

func TestDocumentBlocksIndexesBlocksNamedDDMeta(t *testing.T) {
	doc := model.Document{
		"resource": model.Document{"t": model.Document{ddMetaKey: model.Document{"x": 1}}},
		"variable": model.Document{ddMetaKey: model.Document{"default": 1}},
	}
	blocks := documentBlocks(doc)
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindResource, Type: "t", Name: ddMetaKey}])
	require.True(t, blocks[model.TerraformBlock{Kind: address.KindVariable, Name: ddMetaKey}])

	stampWrittenMeta(doc)
	res, _ := asStringMap(doc["resource"])
	byName, _ := asStringMap(res["t"])
	block, _ := asStringMap(byName[ddMetaKey])
	require.Equal(t, resourceMeta("t."+ddMetaKey, blockMetaExtras{}), block[ddMetaKey])
}

func TestStampTerraformScopesCopiesPlanAddresses(t *testing.T) {
	doc := model.Document{
		"resource": map[string]interface{}{
			"aws_s3_bucket": map[string]interface{}{
				"module.m.aws_s3_bucket.b[1]": map[string]interface{}{
					"bucket":  "x",
					ddMetaKey: map[string]interface{}{"address": "module.m.aws_s3_bucket.b[1]"},
				},
				"r": map[string]interface{}{
					"bucket": "y",
					ddMetaKey: map[string]interface{}{
						"address":    "aws_s3_bucket.r",
						"references": map[string]interface{}{"kms_key_id": []interface{}{"data.aws_kms_key.k"}},
						"unknown":    map[string]interface{}{"arn": true},
					},
				},
			},
		},
		"data": map[string]interface{}{
			"aws_kms_key": map[string]interface{}{
				"k": map[string]interface{}{
					ddMetaKey: map[string]interface{}{"address": "data.aws_kms_key.k"},
				},
			},
		},
	}
	f := &model.FileMetadata{FilePath: "stacks/prod/tfplan.json", Kind: model.KindTerraformPlan, Document: doc}
	(&Inspector{}).stampTerraformScopes(model.FileMetadatas{f})

	require.Equal(t, map[[2]string]string{
		{"aws_s3_bucket", "module.m.aws_s3_bucket.b[1]"}: "module.m.aws_s3_bucket.b[1]",
		{"aws_s3_bucket", "r"}:                           "aws_s3_bucket.r",
		{"data.aws_kms_key", "k"}:                        "data.aws_kms_key.k",
	}, f.TerraformScope.PlanAddresses)
	require.NotContains(t, doc, "_dd_tfplan_meta")
	buckets, _ := asStringMap(doc["resource"].(map[string]interface{})["aws_s3_bucket"])
	r, _ := asStringMap(buckets["r"])
	require.Equal(t, map[string]interface{}{"kms_key_id": []interface{}{"data.aws_kms_key.k"}}, r[ddMetaKey].(map[string]interface{})["references"])
	require.Equal(t, map[string]interface{}{"arn": true}, r[ddMetaKey].(map[string]interface{})["unknown"])
}

func TestPlanIdentityDataFallbackAndConfigurationBlocks(t *testing.T) {
	var doc model.Document
	require.NoError(t, json.Unmarshal([]byte(`{
		"data": {"aws_iam_policy_document": {"p": {"_dd_meta": {"address": "data.aws_iam_policy_document.p"}}}},
		"provider": {"aws": [
			{"region": "us-east-1", "_dd_meta": {"address": "provider.aws"}},
			{"alias": "west", "region": "us-west-2", "_dd_meta": {"address": "provider.aws.west"}}
		]},
		"configuration": {"root_module": {
			"variables": {"region": {}},
			"outputs": {"arn": {"expression": {"references": ["aws_s3_bucket.b.arn"]}}},
			"module_calls": {"wrapper": {
				"source": "./wrapper",
				"module": {
					"variables": {"name": {}},
					"outputs": {"id": {}},
					"module_calls": {"acm": {"source": "./acm", "module": {"variables": {"domain": {}}}}}
				}
			}}
		}}
	}`), &doc))
	f := &model.FileMetadata{FilePath: "stacks/prod/tfplan.json", Kind: model.KindTerraformPlan, Document: doc}
	(&Inspector{}).stampTerraformScopes(model.FileMetadatas{f})

	for _, tc := range []struct{ typ, name, want string }{
		{"aws_iam_policy_document", "p", "data.aws_iam_policy_document.p"},
		{"data.aws_iam_policy_document", "p", "data.aws_iam_policy_document.p"},
		{"variable", "region", "var.region"},
		{"output", "arn", "output.arn"},
		{"module", "wrapper", "module.wrapper"},
		{"variable", "module.wrapper.name", "module.wrapper.var.name"},
		{"output", "module.wrapper.id", "module.wrapper.output.id"},
		{"module", "module.wrapper.module.acm", "module.wrapper.module.acm"},
		{"variable", "module.wrapper.module.acm.domain", "module.wrapper.module.acm.var.domain"},
		{"provider", "aws", "provider.aws"},
		{"provider", "aws.west", "provider.aws.west"},
	} {
		id, ok := terraformIdentityFor(f, tc.typ, tc.name)
		require.True(t, ok, "%s %s", tc.typ, tc.name)
		require.Equal(t, tc.want, id.ResourceID, "%s %s", tc.typ, tc.name)
	}
	_, ok := terraformIdentityFor(f, "variable", "missing")
	require.False(t, ok)
	_, ok = terraformIdentityFor(f, "data.aws_s3_bucket", "p")
	require.False(t, ok)
}

// movedRule fires once per document with a moved block, reporting the block
// the way rules do: the resource type alone, with the file-local name (empty
// for a lone block in the file).
const movedRule = `package datadog

DatadogPolicy contains result if {
	some i
	m := input.document[i].moved
	m.from

	result := {
		"documentId": input.document[i].id,
		"resourceType": "moved",
		"resourceName": "",
		"searchKey": "moved",
	}
}
`

// Two files of one root each declaring a moved block: both findings resolve
// their own block under the file-local name rules report, carry distinct
// module-wide addresses (moved.0 / moved.1) and so distinct fingerprints, and
// none of them falls back to the legacy fingerprint (zero identity gaps).
func TestInspect_RepeatedUnlabeledBlocksKeepDistinctIdentities(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.tf", "b.tf"} {
		body := "moved {\n  from = aws_a." + name + "\n  to   = aws_b." + name + "\n}\n"
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(body), 0o644))
	}
	files := parseTerraform(t, filepath.Join(root, "a.tf"))
	files = append(files, parseTerraform(t, filepath.Join(root, "b.tf"))...)

	tr := &tracker.CITracker{}
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "moved_rule", Content: movedRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "moved-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		tracker:       tr,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2, "one finding per moved block")

	ids := map[string]bool{}
	for i := range vulns {
		require.NotEmpty(t, vulns[i].ResourceID, "each finding carries its Terraform address")
		require.Equal(t, ".", vulns[i].RootModule)
		ids[vulns[i].ResourceID] = true
	}
	idList := make([]string, 0, len(ids))
	for id := range ids {
		idList = append(idList, id)
	}
	require.ElementsMatch(t, []string{"moved.0", "moved.1"}, idList,
		"the two blocks are distinguished by their module-wide index")
	require.EqualValues(t, 0, tr.IdentityGaps, "no finding falls back to the legacy fingerprint")

	// Distinct addresses must mean distinct fingerprints.
	require.NotEqual(t, vulns[0].ResourceID, vulns[1].ResourceID)
}

// movedFileRule fires once per moved block of a document, reporting the
// block with its file-local list index — the name rules actually report.
// The parser renders a file's repeated moved blocks as a list and a lone one
// as a plain object, so the rule has a branch for each shape.
const movedFileRule = `package datadog

DatadogPolicy contains result if {
	some i
	doc := input.document[i]
	is_array(doc.moved)
	some idx
	m := doc.moved[idx]
	m.from

	result := {
		"documentId": doc.id,
		"resourceType": "moved",
		"resourceName": sprintf("%d", [idx]),
		"searchKey": sprintf("moved[%d]", [idx]),
	}
}

DatadogPolicy contains result if {
	some i
	doc := input.document[i]
	is_object(doc.moved)
	doc.moved.from

	result := {
		"documentId": doc.id,
		"resourceType": "moved",
		"resourceName": "",
		"searchKey": "moved",
	}
}
`

// Two files of one external module each declare ONE moved block — both files
// report the same bare declaration key for their lone block — routed through
// one call: the module-wide index orders the blocks across files (first
// file's block is .0, second file's .1), so the two routed copies keep distinct addresses and both
// findings survive. With file-local indexing each lone block kept the bare
// address, both copies were addressed module.m.moved and the second finding
// collapsed into the first.
func TestInspect_ExternalModuleFileUnlabeledBlocksStayDistinct(t *testing.T) {
	root := t.TempDir()
	cacheDir := filepath.Join(root, "cache")
	stackDir := filepath.Join(root, "stack")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))
	require.NoError(t, os.MkdirAll(stackDir, 0o755))

	// The external module: two files, one moved block each. Neither file
	// alone has a collision, so only the module-wide index tells them apart.
	firstPath := filepath.Join(cacheDir, "first.tf")
	require.NoError(t, os.WriteFile(firstPath, []byte(`
moved {
  from = aws_a.first
  to   = aws_b.first
}
`), 0o644))
	secondPath := filepath.Join(cacheDir, "second.tf")
	require.NoError(t, os.WriteFile(secondPath, []byte(`
moved {
  from = aws_a.second
  to   = aws_b.second
}
`), 0o644))

	callerPath := filepath.Join(stackDir, "main.tf")
	require.NoError(t, os.WriteFile(callerPath, []byte(`
module "m" {
  source = "../cache"
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, firstPath)...)
	files = append(files, parseTerraform(t, secondPath)...)
	files = append(files, parseTerraform(t, callerPath)...)

	tr := &tracker.CITracker{}
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "moved_rule", Content: movedFileRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "moved-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		tracker:       tr,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetExternalModulePaths([]string{cacheDir})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	require.Len(t, vulns, 2, "each file's moved block is reported through the call")
	ids := map[string]bool{}
	for i := range vulns {
		require.NotEmpty(t, vulns[i].ResourceID, "each routed copy carries its address")
		ids[vulns[i].ResourceID] = true
	}
	require.Len(t, ids, 2, "the two routed addresses are distinct")
	require.Contains(t, ids, "module.m.moved.0", "first file's block is indexed first")
	require.Contains(t, ids, "module.m.moved.1", "second file's block keeps a distinct index")
	require.EqualValues(t, 0, tr.IdentityGaps, "no finding falls back to the legacy fingerprint")
}
