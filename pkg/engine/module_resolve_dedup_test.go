package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestReferencesSplitDedup(t *testing.T) {
	const module = `
variable "subnet_id" {}

resource "aws_route_table_association" "a" {
  subnet_id = var.subnet_id
}
`
	call := func(subnet string) string {
		return `
resource "aws_subnet" "` + subnet + `" {
  cidr_block = "10.0.0.0/24"
}

module "m" {
  source    = "../../modules/m"
  subnet_id = aws_subnet.` + subnet + `.id
}
`
	}
	refsOf := func(doc model.Document) interface{} {
		return metaOf(t, doc, "resource", "aws_route_table_association", "a")[referencesKey]
	}

	res, _ := resolveModuleFixture(t, map[string]string{"envs/a": call("a"), "envs/b": call("b")}, module)
	require.Len(t, res.docs, 2)
	got := []interface{}{refsOf(res.docs[0]), refsOf(res.docs[1])}
	require.ElementsMatch(t, []interface{}{
		map[string]interface{}{"subnet_id": []interface{}{"aws_subnet.a"}},
		map[string]interface{}{"subnet_id": []interface{}{"aws_subnet.b"}},
	}, got)

	res, _ = resolveModuleFixture(t, map[string]string{"envs/a": call("a"), "envs/b": call("a")}, module)
	require.Len(t, res.docs, 1)
	docID, _ := res.docs[0]["id"].(string)
	require.Len(t, res.extras[docID], 1)
	require.Equal(t, map[string]interface{}{"subnet_id": []interface{}{"aws_subnet.a"}}, refsOf(res.docs[0]))
}

func TestUnknownSplitsDedup(t *testing.T) {
	const module = `
variable "x" {}

resource "aws_s3_bucket" "b" {
  bucket = var.x
}
`
	res, _ := resolveModuleFixture(t, map[string]string{
		"envs/a": "module \"m\" {\n  source = \"../../modules/m\"\n  x      = \"$${var.x}\"\n}\n",
		"envs/b": "module \"m\" {\n  source = \"../../modules/m\"\n}\n",
	}, module)
	require.Len(t, res.docs, 2)
	var unknowns []interface{}
	for _, doc := range res.docs {
		require.Equal(t, "${var.x}", docAsMap(docAsMap(doc["resource"])["aws_s3_bucket"])["b"].(map[string]interface{})["bucket"])
		unknowns = append(unknowns, metaOf(t, doc, "resource", "aws_s3_bucket", "b")[unknownKey])
	}
	require.ElementsMatch(t, []interface{}{nil, map[string]interface{}{"bucket": true}}, unknowns)

	unsetCall := "variable \"x\" {}\n\nmodule \"m\" {\n  source = \"../../modules/m\"\n  x      = var.x\n}\n"
	res, _ = resolveModuleFixture(t, map[string]string{"envs/a": unsetCall, "envs/b": unsetCall}, module)
	require.Len(t, res.docs, 1)
	docID, _ := res.docs[0]["id"].(string)
	require.Len(t, res.extras[docID], 1)
	require.Equal(t, map[string]interface{}{"bucket": true}, metaOf(t, res.docs[0], "resource", "aws_s3_bucket", "b")[unknownKey])
}

const multiRootNetworkModule = `
variable "n" {}
variable "nsg_id" {}
locals {
  ids = aws_subnet.s[*].id
}
resource "aws_subnet" "s" {
  count      = var.n
  cidr_block = "10.0.${count.index}.0/24"
}
resource "aws_network_security_group" "g" {
  name = "g"
}
resource "azurerm_subnet_network_security_group_association" "a" {
  count     = var.n
  subnet_id = local.ids[count.index]
  nsg       = var.nsg_id
}
module "rules" {
  source = "./rules"
  nsg_id = var.nsg_id
}
`

const multiRootRulesModule = `
variable "nsg_id" {}
resource "aws_network_security_rule" "r" {
  nsg = var.nsg_id
}
`

var multiRootTargets = &ruleTargets{types: map[string]bool{
	"aws_subnet": true, "aws_network_security_group": true, "aws_s3_bucket": true,
	"azurerm_subnet_network_security_group_association": true, "aws_network_security_rule": true,
}}

// writeMultiRootRepo writes roots identical roots calling a shared module twice,
// each with plain targeted blocks reading a variable and a local.
func writeMultiRootRepo(tb testing.TB, roots, subnets, plain int) (string, model.FileMetadatas) {
	tb.Helper()
	repo := tb.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(repo, filepath.FromSlash(name))
		require.NoError(tb, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(tb, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	files := model.FileMetadatas{}
	files = append(files, parseTerraform(tb, write("modules/network/main.tf", multiRootNetworkModule))...)
	files = append(files, parseTerraform(tb, write("modules/network/rules/main.tf", multiRootRulesModule))...)
	var blocks strings.Builder
	for j := range plain {
		fmt.Fprintf(&blocks, "resource \"aws_s3_bucket\" \"plain%d\" {\n  bucket = \"${var.name}-%d\"\n  tags   = local.tags\n  policy = aws_network_security_group.root.id\n}\n", j, j)
	}
	for i := range roots {
		files = append(files, parseTerraform(tb, write(fmt.Sprintf("root%d/main.tf", i), fmt.Sprintf(`
variable "name" {
  default = "app"
}
locals {
  tags = { team = var.name }
}
resource "aws_network_security_group" "root" {
  name = "root%d"
}
module "net" {
  source = "../modules/network"
  n      = %d
  nsg_id = aws_network_security_group.root.id
}
module "net_one" {
  source = "../modules/network"
  n      = 1
  nsg_id = aws_network_security_group.root.id
}
%s`, i, subnets, blocks.String())))...)
	}
	return repo, files
}

func TestMultiRootRepoDedup(t *testing.T) {
	counts := map[int]int{}
	for _, roots := range []int{10, 50} {
		repo, files := writeMultiRootRepo(t, roots, 3, 2)
		res := resolveModuleDocuments(context.Background(), files, repo, relDirForTest(repo), nil, multiRootTargets, nil, nil, nil, nil)
		require.True(t, res.ok, "roots=%d", roots)
		require.Len(t, res.written, roots*6, "roots=%d", roots)
		counts[roots] = len(res.docs)
	}
	require.Equal(t, 6, counts[10])
	require.Equal(t, counts[10], counts[50])
}

func TestInPlaceValuesAddNoDocument(t *testing.T) {
	repo, files := writeMultiRootRepo(t, 10, 8, 5)
	res := resolveModuleDocuments(context.Background(), files, repo, relDirForTest(repo), nil, multiRootTargets, nil, nil, nil, nil)
	require.True(t, res.ok)
	patchWrittenBlocks(files, res.written)
	require.Len(t, res.docs, 11)
	require.Len(t, res.syntheticFiles, 11)
	require.Len(t, files, 12)
	plain := docAsMap(docAsMap(files[len(files)-1].Document["resource"])["aws_s3_bucket"])["plain0"]
	require.Equal(t, "app-0", docAsMap(plain)["bucket"])
	require.Equal(t, map[string]interface{}{"team": "app"}, docAsMap(plain)["tags"])
}

// sampleHeapInuse records the highest HeapInuse seen every millisecond until stopped.
func sampleHeapInuse() (stop func() uint64) {
	var peak uint64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			peak = max(peak, ms.HeapInuse)
			select {
			case <-done:
				return
			case <-ticker.C:
			}
		}
	}()
	return func() uint64 {
		close(done)
		wg.Wait()
		return peak
	}
}

func BenchmarkResolveMultiRoot(b *testing.B) {
	for _, bc := range []struct {
		name         string
		roots, plain int
	}{
		{"roots=10", 10, 5},
		{"roots=50", 50, 5},
		{"roots=200", 200, 5},
		{"plain=50", 10, 50},
	} {
		b.Run(bc.name, func(b *testing.B) {
			repo, files := writeMultiRootRepo(b, bc.roots, 3, bc.plain)
			relDir := relDirForTest(repo)
			runtime.GC()
			b.ReportAllocs()
			b.ResetTimer()
			stop := sampleHeapInuse()
			for range b.N {
				res := resolveModuleDocuments(context.Background(), files, repo, relDir, nil, multiRootTargets, nil, nil, nil, nil)
				if !res.ok {
					b.Fatal("resolveModuleDocuments ok = false")
				}
				patchWrittenBlocks(files, res.written)
			}
			b.StopTimer()
			b.ReportMetric(float64(stop()), "peak-heap-B")
		})
	}
}

func requireNoRootModules(t *testing.T, doc model.Document) {
	t.Helper()
	if doc == nil {
		return
	}
	for _, section := range []string{"resource", "data", "ephemeral"} {
		byType, _ := asStringMap(doc[section])
		for _, typeBlocks := range byType {
			byName, _ := asStringMap(typeBlocks)
			for _, raw := range byName {
				block, _ := asStringMap(raw)
				meta, _ := asStringMap(block[ddMetaKey])
				require.NotContains(t, meta, "root_modules")
			}
		}
	}
}

func requireDocsHaveNoRootModules(t *testing.T, files model.FileMetadatas, docs []model.Document) {
	t.Helper()
	for _, f := range files {
		if f != nil {
			requireNoRootModules(t, f.Document)
		}
	}
	for _, doc := range docs {
		requireNoRootModules(t, doc)
	}
}

func TestDocRoots(t *testing.T) {
	t.Run("multi-root dedup", func(t *testing.T) {
		repo, files := writeMultiRootRepo(t, 3, 2, 1)
		ins := newTestInspector(t, inspectorOpts{repoPath: repo})
		ins.stampTerraformScopes(files)
		docs, _, extras, _, docRoots := ins.instantiateLocalModules(context.Background(), files, multiRootTargets)
		require.NotEmpty(t, extras)
		require.NotEmpty(t, docRoots)
		requireDocsHaveNoRootModules(t, files, docs)
	})

	t.Run("fallback roots and a plan file", func(t *testing.T) {
		repo := t.TempDir()
		modFile := writeFile(t, filepath.Join(repo, "modules", "m"), "main.tf", `resource "aws_s3_bucket" "b" {}`)
		mod := fileMeta("mod-id", modFile)
		mod.Kind = model.KindTerraform
		mod.Document = blocksDoc("resource", map[string][]string{"aws_s3_bucket": {"b"}})
		files := model.FileMetadatas{mod}
		for _, dir := range []string{"envs/a", "envs/b"} {
			f := fileMeta(dir+"-root", filepath.Join(repo, dir, "main.tf"))
			f.Kind = model.KindTerraform
			f.Document = model.Document{"module": map[string]interface{}{
				"m": map[string]interface{}{"source": "../../modules/m"},
			}}
			files = append(files, f)
		}
		ok := fileMeta("ok-root", writeFile(t, filepath.Join(repo, "ok"), "main.tf", `resource "aws_s3_bucket" "ok" {}`))
		ok.Kind = model.KindTerraform
		ok.Document = blocksDoc("resource", map[string][]string{"aws_s3_bucket": {"ok"}})
		plan := &model.FileMetadata{
			ID: "plan-id", FilePath: filepath.Join(repo, "stacks", "prod", "tfplan.json"), Kind: model.KindTerraformPlan,
			Document: model.Document{
				"resource": map[string]interface{}{"aws_s3_bucket": map[string]interface{}{"r": map[string]interface{}{}}},
				"_dd_tfplan_meta": map[string]interface{}{"aws_s3_bucket": map[string]interface{}{
					"r": map[string]interface{}{"address": "aws_s3_bucket.r"},
				}},
			},
		}
		files = append(files, ok, plan)
		ins := newTestInspector(t, inspectorOpts{repoPath: repo})
		ins.stampTerraformScopes(files)
		docs, _, _, _, docRoots := ins.instantiateLocalModules(context.Background(), files, nil)
		require.Equal(t, []string{"envs/a", "envs/b", "modules/m"}, docRoots["mod-id"])
		require.Equal(t, []string{"stacks/prod/tfplan.json"}, docRoots["plan-id"])
		require.Equal(t, []string{"ok"}, docRoots["ok-root"])
		requireDocsHaveNoRootModules(t, files, docs)
	})

	t.Run("external module file reached by calls", func(t *testing.T) {
		repo, pkg := t.TempDir(), t.TempDir()
		const source = "example/mod/aws"
		modFile := writeFile(t, filepath.Join(pkg, "mod"), "main.tf", `variable "name" {}
resource "aws_s3_bucket" "b" {
  bucket = var.name
}
resource "aws_sqs_queue" "q" {}
`)
		files := parseTerraform(t, modFile)
		modID := files[0].ID
		dirs := map[string]RemoteModuleDirectory{}
		for _, stack := range []string{"stack-a", "stack-b"} {
			dir := filepath.Join(repo, stack)
			files = append(files, parseTerraform(t, writeFile(t, dir, "main.tf", `module "m" {
  source = "`+source+`"
  name   = "`+stack+`"
}
`))...)
			dirs[RemoteModuleKey(dir, source, "")] = RemoteModuleDirectory{Path: filepath.Join(pkg, "mod"), PackageRoot: pkg}
		}
		ins := newTestInspector(t, inspectorOpts{repoPath: repo})
		ins.remoteModuleDirs = dirs
		ins.externalPathRoots = map[string]bool{filepath.Clean(pkg): true}
		ins.stampTerraformScopes(files)
		docs, _, _, moduleFiles, docRoots := ins.instantiateLocalModules(
			context.Background(), files, &ruleTargets{types: map[string]bool{"aws_s3_bucket": true}})
		mf := moduleFiles[modID]
		require.NotNil(t, mf)
		require.Len(t, mf.calls, 2)
		require.True(t, mf.keptAsWritten("aws_sqs_queue"))
		require.False(t, mf.keptAsWritten("aws_s3_bucket"))
		require.Equal(t, []string{files[0].TerraformScope.RootModule}, docRoots[modID])
		require.Len(t, docs, 2)
		requireDocsHaveNoRootModules(t, files, docs)
	})

	t.Run("module file with routed and kept blocks", func(t *testing.T) {
		for _, keepWritten := range []bool{false, true} {
			scope := &model.TerraformScope{RootModule: "lib"}
			file := &model.FileMetadata{ID: "mod", FilePath: "/repo/lib/main.tf", TerraformScope: scope,
				Document: blocksDoc("resource", map[string][]string{"aws_s3_bucket": {"b"}, "aws_sqs_queue": {"q"}})}
			stampWrittenMeta(file.Document)
			mf := &moduleFileCalls{
				scope: scope, keepWritten: keepWritten, writtenResourceTypes: map[string]bool{"aws_sqs_queue": true},
				calls: []moduleCall{{moduleAddress: "module.m", rootModule: "envs/b"}, {moduleAddress: "module.m", rootModule: "envs/a"}},
			}
			files := model.FileMetadatas{file}
			moduleFiles := map[string]*moduleFileCalls{"mod": mf}
			routeModuleFileRoots(files, moduleFiles)
			require.NotContains(t, metaOf(t, file.Document, "resource", "aws_sqs_queue", "q"), "root_modules")
			docRoots := documentRoots(files, &moduleResolutionResult{moduleFiles: moduleFiles}, "/repo")
			require.Equal(t, []string{"envs/a", "envs/b", "lib"}, docRoots["mod"])
			requireDocsHaveNoRootModules(t, files, nil)
		}
	})
}
