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

// keyedItemsModule is called with a for_each map whose keys differ per caller
// and whose values are unknown: the module sees a map with known keys and
// unknown values, so every instance expands with its own key while the bucket
// and acl attributes stay identical.
const keyedItemsModule = `
variable "items" {
  type = map(number)
}

resource "aws_s3_bucket" "b" {
  for_each = var.items
  bucket   = "static"
  acl      = "public-read"
}
`

// keyedRoot writes a caller root whose for_each key is name-derived.
func keyedRoot(t *testing.T, root, name, key string) model.FileMetadatas {
	t.Helper()
	dir := filepath.Join(root, name)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(path, []byte(`
resource "aws_instance" "src" {
  ami = "ami-1"
}

module "m" {
  source = "../modules/m"
  items  = { `+key+` = aws_instance.src.arn }
}
`), 0o644))
	return parseTerraform(t, path)
}

func keyedModuleFiles(t *testing.T, root string) model.FileMetadatas {
	modDir := filepath.Join(root, "modules", "m")
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	modPath := filepath.Join(modDir, "main.tf")
	require.NoError(t, os.WriteFile(modPath, []byte(keyedItemsModule), 0o644))
	return parseTerraform(t, modPath)
}

func keyedAclRule() []model.QueryMetadata {
	return []model.QueryMetadata{{
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
}

func keysOfTest(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The content key of a group hashes the full instance name of every entry: two
// entries that render identical attributes but carry different instance
// suffixes are different instances, and their documents must never merge —
// without the suffix in the hash the second root would dedupe onto the first
// caller's document and report the first caller's instance keys
// (K9CODESEC-7158).
func TestGroupContentKeyDistinguishesInstanceSuffixes(t *testing.T) {
	fm := &model.FileMetadata{ID: "file-1"}
	entry := func(fullName string) instantiatedResource {
		return instantiatedResource{
			typ:       "resource",
			baseName:  "b",
			fullName:  fullName,
			defLine:   3,
			attrsHash: 42, // identical rendered attributes
		}
	}
	group := func(fullName string) *docGroup {
		return &docGroup{
			fm:            fm,
			moduleAddress: "module.m",
			layer:         0,
			entries:       []instantiatedResource{entry(fullName)},
		}
	}

	require.NotEqual(t, groupContentKey(group(`b["x"]`)), groupContentKey(group(`b["y"]`)),
		"same attributes, different instance keys: different documents")
	require.Equal(t, groupContentKey(group(`b["x"]`)), groupContentKey(group(`b["x"]`)),
		"identical entries: one document, deduplicated callers route through it")
}

// Two roots iterating different for_each keys over unknown-valued maps each
// report their own keyed instance — with decode-time compaction on and off
// (K9CODESEC-7158). The rendered attributes of the two instances differ only
// in the for_each reference text, so this also pins that a keyed instance is
// never reported with the primary caller's key.
func TestInspect_KeyedInstancesAcrossRootsStayDistinct(t *testing.T) {
	for _, compact := range []bool{false, true} {
		t.Run(map[bool]string{false: "compaction off", true: "compaction on"}[compact], func(t *testing.T) {
			root := t.TempDir()
			var files model.FileMetadatas
			files = append(files, keyedModuleFiles(t, root)...)
			files = append(files, keyedRoot(t, root, "stack-a", "x")...)
			files = append(files, keyedRoot(t, root, "stack-b", "y")...)

			ins := newTestInspector(t, inspectorOpts{
				queries:       keyedAclRule(),
				repoPath:      root,
				vb:            DefaultVulnerabilityBuilder,
				flagEvaluator: featureflags.NewLocalEvaluator(),
			})
			ins.SetCompactFindingsAtDecode(compact)

			vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
			require.NoError(t, err)
			require.Empty(t, ins.GetFailedQueries())
			require.Len(t, vulns, 2, "one finding per root's own keyed instance")

			ids := map[string]bool{}
			roots := map[string]string{}
			for i := range vulns {
				ids[vulns[i].ResourceID] = true
				roots[vulns[i].ResourceID] = vulns[i].RootModule
			}
			idList := make([]string, 0, len(ids))
			for id := range ids {
				idList = append(idList, id)
			}
			require.ElementsMatch(t, []string{
				`module.m.aws_s3_bucket.b["x"]`,
				`module.m.aws_s3_bucket.b["y"]`,
			}, idList, "each root reports its own for_each key")
			require.Equal(t, "stack-a", roots[`module.m.aws_s3_bucket.b["x"]`],
				"stack-a's finding carries stack-a's key, not the primary caller's")
			require.Equal(t, "stack-b", roots[`module.m.aws_s3_bucket.b["y"]`])

			// Distinct addresses must mean distinct fingerprints.
			fingerprints := map[string]bool{}
			for i := range vulns {
				fingerprints[model.FindingIdentity(&vulns[i])] = true
			}
			require.Len(t, fingerprints, 2)
		})
	}
}

// Two roots iterating the SAME key with identical rendered attributes
// deduplicate onto one keyed document: the second caller is recorded in the
// primary document's extras, not emitted as a second document.
func TestInspect_IdenticalKeyedInstancesAcrossRootsStillDedup(t *testing.T) {
	root := t.TempDir()
	var files model.FileMetadatas
	files = append(files, keyedModuleFiles(t, root)...)
	files = append(files, keyedRoot(t, root, "stack-a", "x")...)
	files = append(files, keyedRoot(t, root, "stack-b", "x")...)

	targets := ruleTargetedResourceTypes(keyedAclRule())
	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, targets, nil, nil, nil, nil)
	require.Len(t, res.docs, 1, "identical instances share one keyed document")
	require.Len(t, res.syntheticFiles, 1)
	require.Len(t, res.extras, 1, "the second caller is recorded in extras")

	var primaryID string
	for id := range res.extras {
		primaryID = id
	}
	extras := res.extras[primaryID]
	require.Len(t, extras, 1)
	require.Equal(t, "stack-b", extras[0].rootModule,
		"the extra caller keeps its own root, only the document is shared")

	// End to end: both callers report the shared instance, each under its own root.
	ins := newTestInspector(t, inspectorOpts{
		queries:       keyedAclRule(),
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetCompactFindingsAtDecode(true)
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2, "one finding per caller, both on the shared instance")
	roots := map[string]bool{}
	for i := range vulns {
		require.Equal(t, `module.m.aws_s3_bucket.b["x"]`, vulns[i].ResourceID)
		roots[vulns[i].RootModule] = true
	}
	require.Equal(t, map[string]bool{"stack-a": true, "stack-b": true}, roots)
}
