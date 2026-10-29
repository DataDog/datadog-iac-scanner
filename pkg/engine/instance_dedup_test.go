package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// aclInstanceRule reports every aws_s3_bucket whose acl is public-read. Its
// searchKey and resourceName come from the document key, which for an
// expanded instance is the block's base name.
var aclInstanceRule = []model.QueryMetadata{{
	Query: "acl_rule", Content: `package datadog

DatadogPolicy contains result if {
	some name, i
	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.acl == "public-read"

	result := {
		"documentId": input.document[i].id,
		"platform": "Terraform",
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
	}
}
`, InputData: "{}", Platform: "terraform",
	Metadata: map[string]interface{}{"id": "acl-rule", "platform": "Terraform"}, Aggregation: 1,
}}

func instanceRoot(t *testing.T, content string) (string, model.FileMetadatas) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "main.tf")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return filepath.Dir(path), parseTerraform(t, path)
}

// Two count instances with identical attributes fold into one OPA document,
// and the primary's findings are cloned onto the second instance with its own
// index in the address.
func TestInspect_IdenticalCountInstancesShareOneDocument(t *testing.T) {
	root, files := instanceRoot(t, `
resource "aws_s3_bucket" "b" {
  count  = 2
  bucket = "static"
  acl    = "public-read"
}
`)

	targets := ruleTargetedResourceTypes(aclInstanceRule)
	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, targets, nil, nil, nil, nil)
	require.Len(t, res.docs, 1, "identical instances share one document")
	require.Len(t, res.syntheticFiles, 1)
	require.Empty(t, res.extras, "module-caller dedup does not apply to root instances")
	require.Len(t, res.instanceExtras, 1, "the second instance is recorded as a member of the primary")

	var primaryID string
	for id := range res.instanceExtras {
		primaryID = id
	}
	members := res.instanceExtras[primaryID]
	require.Len(t, members, 1)
	require.Equal(t, ".", members[0].rootModule,
		"the member keeps the primary's root module: same root, same blocks")
	require.Equal(t, map[model.TerraformBlock]string{
		{Kind: "resource", Type: "aws_s3_bucket", Name: "b"}: "[1]",
	}, members[0].instances, "the member carries the second instance's key")

	ins := newTestInspector(t, inspectorOpts{
		queries:       aclInstanceRule,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetCompactFindingsAtDecode(true)
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2, "one finding per instance")

	ids := map[string]string{}
	for i := range vulns {
		ids[vulns[i].ResourceID] = vulns[i].RootModule
	}
	require.Equal(t, map[string]string{
		"aws_s3_bucket.b[0]": ".",
		"aws_s3_bucket.b[1]": ".",
	}, ids, "each instance reports its own address, under the file's root module")

	// The clone is the primary's finding with the suffix substituted: the
	// resolved line text and region are identical.
	require.Equal(t, vulns[0].Line, vulns[1].Line)
	require.Equal(t, vulns[0].SearchKey, vulns[1].SearchKey)

	fingerprints := map[string]bool{}
	for i := range vulns {
		fingerprints[model.FindingIdentity(&vulns[i])] = true
	}
	require.Len(t, fingerprints, 2, "distinct addresses are distinct identities")
}

// count.index makes the rendered attributes differ per instance: the
// documents stay separate and nothing is cloned.
func TestInspect_DifferingCountInstancesKeepSeparateDocuments(t *testing.T) {
	root, files := instanceRoot(t, `
resource "aws_s3_bucket" "b" {
  count  = 2
  bucket = "b-${count.index}"
  acl    = "public-read"
}
`)

	targets := ruleTargetedResourceTypes(aclInstanceRule)
	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, targets, nil, nil, nil, nil)
	require.Len(t, res.docs, 2, "each instance resolves its own attributes")
	require.Empty(t, res.instanceExtras, "differing content is never folded")

	ins := newTestInspector(t, inspectorOpts{
		queries:       aclInstanceRule,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetCompactFindingsAtDecode(true)
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Len(t, vulns, 2)
	ids := map[string]string{}
	for i := range vulns {
		ids[vulns[i].ResourceID] = ""
	}
	require.Equal(t, map[string]string{
		"aws_s3_bucket.b[0]": "",
		"aws_s3_bucket.b[1]": "",
	}, ids)
}

// for_each keys are part of the resolved attributes the evaluator renders
// into the document, so instances keyed differently keep separate documents
// even when every other attribute matches — and each reports its own key.
func TestInspect_ForEachInstancesStaySeparateDocuments(t *testing.T) {
	root, files := instanceRoot(t, `
resource "aws_s3_bucket" "b" {
  for_each = toset(["x", "y"])
  bucket   = "static"
  acl      = "public-read"
}
`)

	targets := ruleTargetedResourceTypes(aclInstanceRule)
	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, targets, nil, nil, nil, nil)
	require.Len(t, res.docs, 2, "the rendered attributes differ per key, so the documents do not fold")
	require.Empty(t, res.instanceExtras)

	ins := newTestInspector(t, inspectorOpts{
		queries:       aclInstanceRule,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetCompactFindingsAtDecode(true)
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Len(t, vulns, 2)
	ids := map[string]bool{}
	for i := range vulns {
		ids[vulns[i].ResourceID] = true
	}
	require.Equal(t, map[string]bool{
		`aws_s3_bucket.b["x"]`: true,
		`aws_s3_bucket.b["y"]`: true,
	}, ids)
}

// A group that also carries a plain sibling joined for context keeps the
// exact content key: the sibling's ownership (one finding per sibling, owned
// by the first layer) is unchanged, and the expanded instances are not folded.
func TestInspect_MixedExpandedAndPlainSiblingLayersFold(t *testing.T) {
	root, files := instanceRoot(t, `
resource "aws_s3_bucket" "plain" {
  bucket = "plain"
  acl    = "public-read"
}

resource "aws_s3_bucket" "inst" {
  count  = 2
  bucket = "static"
  acl    = "public-read"
}
`)

	targets := ruleTargetedResourceTypes(aclInstanceRule)
	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, targets, nil, nil, nil, nil)
	require.Len(t, res.docs, 1, "identical layers fold: the plain sibling is identical in both")
	require.Len(t, res.instanceExtras, 1, "the folded-away layer is recorded for its instance identity")
	for _, extras := range res.instanceExtras {
		require.Len(t, extras, 1)
		require.Equal(t, "[1]", extras[0].instances[model.TerraformBlock{Kind: "resource", Type: "aws_s3_bucket", Name: "inst"}])
	}

	ins := newTestInspector(t, inspectorOpts{
		queries:       aclInstanceRule,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetCompactFindingsAtDecode(true)
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Len(t, vulns, 3, "one finding per sibling, one per instance")

	ids := map[string]int{}
	for i := range vulns {
		ids[vulns[i].ResourceID]++
	}
	require.Equal(t, map[string]int{
		"aws_s3_bucket.plain":   1,
		"aws_s3_bucket.inst[0]": 1,
		"aws_s3_bucket.inst[1]": 1,
	}, ids, "the plain sibling yields exactly one finding despite being joined into both layers")
}

// A plain sibling joined into every layer folds with them: it carries no
// instance suffix, is identical in every layer, and yields exactly one
// finding from the layer that owns it.

// Module-scoped groups keep the exact content key: a count block inside a
// called module deduplicates on the full instance name like before, and its
// findings route through the module-caller extras, not the instance ones.
func TestInspect_ModuleCountInstancesKeepModuleDedup(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "modules", "m")
	modPath := filepath.Join(modDir, "main.tf")
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	require.NoError(t, os.WriteFile(modPath, []byte(`
resource "aws_s3_bucket" "b" {
  count  = 2
  bucket = "static"
  acl    = "public-read"
}
`), 0o644))
	stackPath := filepath.Join(root, "stack", "main.tf")
	require.NoError(t, os.MkdirAll(filepath.Dir(stackPath), 0o755))
	require.NoError(t, os.WriteFile(stackPath, []byte(`
module "m" {
  source = "../modules/m"
}
`), 0o644))
	files := parseTerraform(t, modPath)
	files = append(files, parseTerraform(t, stackPath)...)

	targets := ruleTargetedResourceTypes(aclInstanceRule)
	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, targets, nil, nil, nil, nil)
	require.Len(t, res.docs, 2, "one document per module instance layer")
	require.Empty(t, res.instanceExtras, "module-scoped groups never fold on base names")
	require.Empty(t, res.extras, "one root, one caller: no module dedup either")

	ins := newTestInspector(t, inspectorOpts{
		queries:       aclInstanceRule,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetCompactFindingsAtDecode(true)
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Len(t, vulns, 2)
	ids := map[string]bool{}
	for i := range vulns {
		ids[vulns[i].ResourceID] = true
	}
	require.Equal(t, map[string]bool{
		"module.m.aws_s3_bucket.b[0]": true,
		"module.m.aws_s3_bucket.b[1]": true,
	}, ids)
}

// The instance content key is keyed on base names, so two documents carrying
// the same blocks at the same resolved attributes share a key however their
// instance suffixes differ; the layer index is left out with them. The
// module-scoped key still distinguishes full instance names.
func TestInstanceGroupContentKeyIgnoresInstanceIdentity(t *testing.T) {
	fm := &model.FileMetadata{ID: "file-1"}
	entry := func(fullName string, attrsHash uint64) instantiatedResource {
		return instantiatedResource{
			typ:       "resource",
			baseName:  "b",
			fullName:  fullName,
			defLine:   3,
			attrsHash: attrsHash,
		}
	}
	group := func(entries ...instantiatedResource) *docGroup {
		return &docGroup{fm: fm, layer: 0, entries: entries}
	}

	// Same content, different suffixes and different layers: one key.
	require.Equal(t,
		instanceGroupContentKey(group(entry("b[0]", 42))),
		instanceGroupContentKey(group(entry("b[1]", 42))),
		"identical attributes at different instance keys fold together")

	// Differing attributes: different keys.
	require.NotEqual(t,
		instanceGroupContentKey(group(entry("b[0]", 42))),
		instanceGroupContentKey(group(entry("b[1]", 43))),
		"differing attributes are never folded")

	// Different defining files: different keys.
	other := &docGroup{fm: &model.FileMetadata{ID: "file-2"}, entries: []instantiatedResource{entry("b[0]", 42)}}
	require.NotEqual(t, instanceGroupContentKey(group(entry("b[0]", 42))), instanceGroupContentKey(other))

	// Different block sets: different keys, base names hashed.
	byType := &docGroup{fm: fm, entries: []instantiatedResource{{
		typ: "data.aws_ami", baseName: "b", fullName: `b["x"]`, defLine: 3, attrsHash: 42,
	}}}
	require.NotEqual(t, instanceGroupContentKey(group(entry("b[0]", 42))), instanceGroupContentKey(byType))
}

// The supersedes check must count a member's identity, or a compacting set
// would skip a result whose route still produces a finding for the member.
func TestFindingSet_InstanceMemberIdentitiesKeepSupersedeSound(t *testing.T) {
	scope := &model.TerraformScope{
		RootModule: "stack",
		Blocks: map[model.TerraformBlock]bool{
			{Kind: "resource", Type: "aws_s3_bucket", Name: "b"}:     true,
			{Kind: "resource", Type: "aws_s3_bucket", Name: "plain"}: true,
		},
		Instances: map[model.TerraformBlock]string{
			{Kind: "resource", Type: "aws_s3_bucket", Name: "b"}: "[0]",
		},
	}
	routing := newFindingRouting(nil, map[string][]extraInstanceInfo{
		"doc": {{
			docID:      "member",
			rootModule: "stack",
			instances: map[model.TerraformBlock]string{
				{Kind: "resource", Type: "aws_s3_bucket", Name: "b"}: "[1]",
			},
			scope: scope,
		}},
	}, nil, nil, "/repo")

	finding := func(resourceType, resourceName, resourceID string) model.Vulnerability {
		return model.Vulnerability{
			FileID: "doc", FileName: "main.tf", Platform: "Terraform", QueryID: "q",
			ResourceType: resourceType, ResourceName: resourceName,
			RootModule: "stack", ResourceID: resourceID,
		}
	}

	// Two identical results: the second routes to the same identities the
	// first already kept, so nothing new is kept for it.
	kept := decodeAll(newFindingSet(true, routing), []model.Vulnerability{
		finding("aws_s3_bucket", "b", "aws_s3_bucket.b[0]"),
		finding("aws_s3_bucket", "b", "aws_s3_bucket.b[0]"),
	})
	require.Len(t, kept, 2, "the primary and its member are both kept, once each")
	require.Equal(t, "aws_s3_bucket.b[0]", kept[0].ResourceID)
	require.Equal(t, "aws_s3_bucket.b[1]", kept[1].ResourceID)
	require.Equal(t, "member", kept[1].FileID)

	// What the decode-time identity check computes must be exactly what route
	// produced: the primary's identity, then the member's.
	file := &model.FileMetadata{ID: "doc", FilePath: "main.tf", Kind: model.KindTerraform, TerraformScope: scope}
	set := newFindingSet(true, routing)
	ids, known := set.findingIdentities(file, "Terraform", "aws_s3_bucket", "b", "q", "")
	require.True(t, known)
	want := make([]string, 0, len(kept))
	for i := range kept {
		want = append(want, terraformIdentityInput("q", model.TerraformIdentity{
			RootModule: kept[i].RootModule, ResourceID: kept[i].ResourceID,
		}))
	}
	require.Equal(t, want, ids)

	// A finding whose block is not an expanded instance is never cloned.
	unexpanded := decodeAll(newFindingSet(true, routing), []model.Vulnerability{
		finding("aws_s3_bucket", "plain", "aws_s3_bucket.plain"),
	})
	require.Len(t, unexpanded, 1, "no member identity for a block outside the instances map")

	unresolved := decodeAll(newFindingSet(true, routing), []model.Vulnerability{
		finding("not_a_block", "b", ""),
	})
	require.Len(t, unresolved, 1, "no member identity for a block the scope cannot resolve")
}
