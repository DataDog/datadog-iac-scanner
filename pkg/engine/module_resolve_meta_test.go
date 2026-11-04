/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	jsonparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	"github.com/stretchr/testify/require"
)

// resolveRepo parses every file of a repository, stamps it and runs module
// evaluation, returning the files and the instantiated documents.
func resolveRepo(t *testing.T, sources map[string]string, targets *ruleTargets) (map[string]*model.FileMetadata, []model.Document) {
	t.Helper()
	root := t.TempDir()
	byName := map[string]*model.FileMetadata{}
	var files model.FileMetadatas
	for name, content := range sources {
		path := writeFile(t, filepath.Join(root, filepath.Dir(name)), filepath.Base(name), content)
		if filepath.Ext(name) != ".tf" {
			continue
		}
		f := parseTerraform(t, path)
		require.Len(t, f, 1)
		byName[name] = f[0]
		files = append(files, f...)
	}
	ins := newTestInspector(t, inspectorOpts{repoPath: root})
	ins.stampTerraformScopes(files)
	docs, _, _, _, _ := ins.instantiateLocalModules(context.Background(), files, targets)
	return byName, docs
}

func docMeta(t *testing.T, docs []model.Document, typ, name string) map[string]interface{} {
	t.Helper()
	for _, doc := range docs {
		if _, ok := docAsMap(docAsMap(doc["resource"])[typ])[name]; ok {
			return metaOf(t, doc, "resource", typ, name)
		}
	}
	t.Fatalf("no instantiated %s.%s", typ, name)
	return nil
}

func TestProviderIsResolvedThroughProvidersMaps(t *testing.T) {
	files, docs := resolveRepo(t, map[string]string{
		"main.tf": `
provider "aws" {}

provider "aws" {
  alias = "west"
}

resource "aws_s3_bucket" "root" {
  provider = aws.west
}

resource "aws_sqs_queue" "default" {}

module "west" {
  source    = "./m"
  providers = { aws = aws.west }
}
`,
		"m/main.tf": `
resource "aws_s3_bucket" "b" {}
`,
	}, nil)
	root := files["main.tf"].Document
	require.Equal(t, "aws.west", metaOf(t, root, "resource", "aws_s3_bucket", "root")[providerKey])
	require.Equal(t, "aws", metaOf(t, root, "resource", "aws_sqs_queue", "default")[providerKey])
	require.NotContains(t, docAsMap(docAsMap(root["resource"])["aws_s3_bucket"])["root"], "provider",
		"the meta-argument leaves the body")
	require.Equal(t, "aws.west", docMeta(t, docs, "aws_s3_bucket", "b")[providerKey])
}

// providerParityHCL and providerParityPlan are one configuration, as written
// and as Terraform plans it: root configurations, a providers map, and
// configurations declared in a module and inherited or passed below it.
var providerParityHCL = map[string]string{
	"main.tf": `
provider "aws" {
  region = "us-east-1"
}

provider "aws" {
  alias  = "west"
  region = "us-west-2"
}

resource "aws_s3_bucket" "a" {}

resource "aws_s3_bucket" "w" {
  provider = aws.west
}

module "child" {
  source = "./child"
}

module "west" {
  source    = "./child"
  providers = { aws = aws.west }
}

module "own" {
  source = "./own"
}
`,
	"child/main.tf": `resource "aws_s3_bucket" "c" {}`,
	"own/main.tf": `
provider "aws" {
  region = "eu-west-1"
}

provider "aws" {
  alias  = "x"
  region = "eu-central-1"
}

resource "aws_s3_bucket" "o" {}

resource "aws_s3_bucket" "ox" {
  provider = aws.x
}

module "inner" {
  source = "../child"
}

module "passed" {
  source    = "../child"
  providers = { aws = aws.x }
}
`,
}

const providerParityPlan = `{"format_version":"1.2","terraform_version":"1.9.0",
"planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.a","mode":"managed","type":"aws_s3_bucket","name":"a","values":{}},
  {"address":"aws_s3_bucket.w","mode":"managed","type":"aws_s3_bucket","name":"w","values":{}}],
 "child_modules":[
  {"address":"module.child","resources":[{"address":"module.child.aws_s3_bucket.c","mode":"managed","type":"aws_s3_bucket","name":"c","values":{}}]},
  {"address":"module.west","resources":[{"address":"module.west.aws_s3_bucket.c","mode":"managed","type":"aws_s3_bucket","name":"c","values":{}}]},
  {"address":"module.own","resources":[
    {"address":"module.own.aws_s3_bucket.o","mode":"managed","type":"aws_s3_bucket","name":"o","values":{}},
    {"address":"module.own.aws_s3_bucket.ox","mode":"managed","type":"aws_s3_bucket","name":"ox","values":{}}],
   "child_modules":[
    {"address":"module.own.module.inner","resources":[{"address":"module.own.module.inner.aws_s3_bucket.c","mode":"managed","type":"aws_s3_bucket","name":"c","values":{}}]},
    {"address":"module.own.module.passed","resources":[{"address":"module.own.module.passed.aws_s3_bucket.c","mode":"managed","type":"aws_s3_bucket","name":"c","values":{}}]}]}]}},
"resource_changes":[],
"configuration":{
 "provider_config":{
  "aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","expressions":{"region":{"constant_value":"us-east-1"}}},
  "aws.west":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","alias":"west","expressions":{"region":{"constant_value":"us-west-2"}}},
  "module.own:aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","module_address":"module.own","expressions":{"region":{"constant_value":"eu-west-1"}}},
  "module.own:aws.x":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","alias":"x","module_address":"module.own","expressions":{"region":{"constant_value":"eu-central-1"}}}},
 "root_module":{
  "resources":[
   {"address":"aws_s3_bucket.a","mode":"managed","type":"aws_s3_bucket","name":"a","provider_config_key":"aws","expressions":{}},
   {"address":"aws_s3_bucket.w","mode":"managed","type":"aws_s3_bucket","name":"w","provider_config_key":"aws.west","expressions":{}}],
  "module_calls":{
   "child":{"source":"./child","module":{"resources":[{"address":"aws_s3_bucket.c","mode":"managed","type":"aws_s3_bucket","name":"c","provider_config_key":"aws","expressions":{}}]}},
   "west":{"source":"./child","module":{"resources":[{"address":"aws_s3_bucket.c","mode":"managed","type":"aws_s3_bucket","name":"c","provider_config_key":"aws.west","expressions":{}}]}},
   "own":{"source":"./own","module":{
    "resources":[
     {"address":"aws_s3_bucket.o","mode":"managed","type":"aws_s3_bucket","name":"o","provider_config_key":"module.own:aws","expressions":{}},
     {"address":"aws_s3_bucket.ox","mode":"managed","type":"aws_s3_bucket","name":"ox","provider_config_key":"module.own:aws.x","expressions":{}}],
    "module_calls":{
     "inner":{"source":"../child","module":{"resources":[{"address":"aws_s3_bucket.c","mode":"managed","type":"aws_s3_bucket","name":"c","provider_config_key":"module.own:aws","expressions":{}}]}},
     "passed":{"source":"../child","module":{"resources":[{"address":"aws_s3_bucket.c","mode":"managed","type":"aws_s3_bucket","name":"c","provider_config_key":"module.own:aws.x","expressions":{}}]}}}}}}}}}`

// resourceProviders is the _dd_meta.provider of every resource of docs, by
// address.
func resourceProviders(docs []model.Document) map[string]interface{} {
	out := map[string]interface{}{}
	for _, doc := range docs {
		for _, byName := range docAsMap(doc["resource"]) {
			for _, block := range docAsMap(byName) {
				meta := docAsMap(docAsMap(block)[ddMetaKey])
				if addr, ok := meta["address"].(string); ok {
					out[addr] = meta[providerKey]
				}
			}
		}
	}
	return out
}

func TestProviderAddressIsTheSameForHCLAndPlan(t *testing.T) {
	files, instantiated := resolveRepo(t, providerParityHCL, nil)
	hcl := resourceProviders(append(instantiated, files["main.tf"].Document))

	_, planDocs, _, _, err := (&jsonparser.Parser{}).Parse(context.Background(), []byte(providerParityPlan), "plan.json", false, 0)
	require.NoError(t, err)
	plan := resourceProviders(planDocs)

	require.Equal(t, map[string]interface{}{
		"aws_s3_bucket.a":                          "aws",
		"aws_s3_bucket.w":                          "aws.west",
		"module.child.aws_s3_bucket.c":             "aws",
		"module.west.aws_s3_bucket.c":              "aws.west",
		"module.own.aws_s3_bucket.o":               "module.own:aws",
		"module.own.aws_s3_bucket.ox":              "module.own:aws.x",
		"module.own.module.inner.aws_s3_bucket.c":  "module.own:aws",
		"module.own.module.passed.aws_s3_bucket.c": "module.own:aws.x",
	}, plan)
	require.Equal(t, plan, hcl)

	planProviders := docAsMap(planDocs[0]["provider"])
	hclProviders := docAsMap(files["main.tf"].Document["provider"])
	require.Equal(t, []string{"aws"}, slices.Collect(maps.Keys(withoutLines(planProviders))))
	require.Equal(t, []string{"aws"}, slices.Collect(maps.Keys(withoutLines(hclProviders))))
	regions := func(section map[string]interface{}) []interface{} {
		var out []interface{}
		for _, body := range section["aws"].([]interface{}) {
			out = append(out, []interface{}{docAsMap(body)["alias"], docAsMap(body)["region"]})
		}
		return out
	}
	require.Equal(t, regions(hclProviders), regions(planProviders), "both hold the root module's configurations only")
}

// withoutLines is m without its line table.
func withoutLines(m map[string]interface{}) map[string]interface{} {
	out := maps.Clone(m)
	delete(out, "_dd_lines")
	return out
}

func TestProviderMetaArgumentThatIsNotAReference(t *testing.T) {
	files, _ := resolveRepo(t, map[string]string{
		"main.tf": `
variable "p" {}

resource "aws_s3_bucket" "b" {
  provider = var.p
}
`,
	}, nil)
	meta := metaOf(t, files["main.tf"].Document, "resource", "aws_s3_bucket", "b")
	require.NotContains(t, meta, providerKey, "a value is never a provider configuration")
	require.NotContains(t, docAsMap(meta[unknownKey]), providerKey)
}

// Written blocks next to a dynamic block of unknown for_each are listed with
// their shapes; the unknown marker stands for the blocks it may generate.
func TestStaticBlocksNextToUnknownDynamicBlockAreTheSameForHCLAndPlan(t *testing.T) {
	files, _ := resolveRepo(t, map[string]string{
		"main.tf": `
variable "ports" {}

resource "aws_security_group" "g" {
  name = "g"
  ingress {
    from_port = 1
  }
  dynamic "ingress" {
    for_each = var.ports
    content {
      from_port = ingress.value
    }
  }
}
`,
	}, nil)
	plan := `{"format_version":"1.2","terraform_version":"1.9.0",
"planned_values":{"root_module":{"resources":[{"address":"aws_security_group.g","mode":"managed","type":"aws_security_group","name":"g","values":{"name":"g"}}]}},
"resource_changes":[{"address":"aws_security_group.g","mode":"managed","type":"aws_security_group","name":"g",
 "change":{"actions":["create"],"before":null,"after":{"name":"g"},"after_unknown":{"ingress":true,"id":true}}}],
"configuration":{"root_module":{"resources":[{"address":"aws_security_group.g","mode":"managed","type":"aws_security_group","name":"g",
 "expressions":{"name":{"constant_value":"g"},"ingress":[{"from_port":{"constant_value":1}}]}}]}}}`
	_, planDocs, _, _, err := (&jsonparser.Parser{}).Parse(context.Background(), []byte(plan), "plan.json", false, 0)
	require.NoError(t, err)

	for name, doc := range map[string]model.Document{"hcl": files["main.tf"].Document, "plan": planDocs[0]} {
		group := docAsMap(docAsMap(doc["resource"])["aws_security_group"])["g"]
		ingress, _ := docAsMap(group)["ingress"].([]interface{})
		require.Len(t, ingress, 1, name)
		require.Equal(t, "1", fmt.Sprint(docAsMap(ingress[0])["from_port"]), name)
		meta := metaOf(t, doc, "resource", "aws_security_group", "g")
		require.Equal(t, map[string]interface{}{
			"name":    true,
			"ingress": []interface{}{map[string]interface{}{"from_port": true}},
		}, meta[configuredKey], name)
		require.Equal(t, map[string]interface{}{"ingress": true}, meta[unknownKey], name)
	}
}

func TestDynamicReferencesFollowGeneratedBlocks(t *testing.T) {
	files, _ := resolveRepo(t, map[string]string{
		"main.tf": `
variable "unknown" {}

resource "aws_vpc" "v" {}

resource "aws_security_group" "g" {
  ingress {
    cidr = "10.0.0.0/8"
  }
  dynamic "ingress" {
    for_each = ["a", "b"]
    content {
      cidr = aws_vpc.v.cidr_block
    }
  }
  dynamic "egress" {
    for_each = var.unknown
    content {
      cidr = aws_vpc.v.cidr_block
    }
  }
  dynamic "tag" {
    for_each = []
    content {
      key = aws_vpc.v.id
    }
  }
}
`,
	}, nil)
	doc := files["main.tf"].Document
	group := docAsMap(docAsMap(doc["resource"])["aws_security_group"])["g"]
	ingress, _ := docAsMap(group)["ingress"].([]interface{})
	require.Len(t, ingress, 3)

	refs := docAsMap(metaOf(t, doc, "resource", "aws_security_group", "g")[referencesKey])
	vpc := map[string]interface{}{"cidr": []interface{}{"aws_vpc.v"}}
	require.Equal(t, []interface{}{map[string]interface{}{"cidr": []interface{}{}}, vpc, vpc}, refs["ingress"])
	require.NotContains(t, refs, "egress", "a block kept as written generates nothing")
	require.NotContains(t, refs, "tag", "an empty expansion generates nothing")
}

func TestRootModuleCallAndOutputCarryMeta(t *testing.T) {
	files, _ := resolveRepo(t, map[string]string{
		"main.tf": `
variable "unset" {}

resource "aws_s3_bucket" "b" {}

module "m" {
  source = "./m"
  name   = var.unset
  arn    = aws_s3_bucket.b.arn
}

output "arn" {
  value = aws_s3_bucket.b.arn
}
`,
		"m/main.tf": `
variable "name" {}
variable "arn" {}
`,
	}, nil)
	doc := files["main.tf"].Document

	call := docAsMap(docAsMap(doc["module"])["m"])
	meta := docAsMap(call[ddMetaKey])
	require.Equal(t, "module.m", meta["address"])
	require.Equal(t, map[string]interface{}{"name": true, "arn": true}, meta[unknownKey])
	require.Equal(t, []interface{}{"aws_s3_bucket.b"}, docAsMap(meta[referencesKey])["arn"])
	require.NotContains(t, docAsMap(meta[referencesKey]), "source")

	output := docAsMap(docAsMap(doc["output"])["arn"])
	meta = docAsMap(output[ddMetaKey])
	require.Equal(t, "output.arn", meta["address"])
	require.Equal(t, map[string]interface{}{"value": true}, meta[unknownKey])
	require.Equal(t, map[string]interface{}{"value": []interface{}{"aws_s3_bucket.b"}}, meta[referencesKey])
}

func TestEvaluatedRootBlockReplacesItsTemplates(t *testing.T) {
	files, _ := resolveRepo(t, map[string]string{
		"main.tf": `
variable "ports" {}

resource "aws_security_group" "g" {
  name = var.off
  dynamic "ingress" {
    for_each = var.ports
    content {
      port = ingress.value
    }
  }
}

variable "off" {
  default = null
}
`,
		"terraform.tfvars": "ports = [1, 2]\n",
	}, nil)
	group := docAsMap(docAsMap(docAsMap(files["main.tf"].Document["resource"])["aws_security_group"])["g"])
	require.NotContains(t, group, "dynamic", "the rendered template is replaced by its blocks")
	require.NotContains(t, group, "name", "an attribute evaluated to null is unset")
	require.Len(t, group["ingress"], 2)
}

func TestEvaluatedProviderUnknownFollowsItsValues(t *testing.T) {
	files, _ := resolveRepo(t, map[string]string{
		"main.tf": `
variable "known" {}
variable "unset" {}

provider "aws" {
  default_tags {
    tags = var.known
  }
}

provider "aws" {
  alias = "west"
  default_tags {
    tags = var.unset
  }
}

resource "aws_s3_bucket" "b" {}
`,
		"terraform.tfvars": "known = { Team = \"a\" }\n",
	}, nil)
	providers, _ := docAsMap(files["main.tf"].Document["provider"])["aws"].([]interface{})
	require.Len(t, providers, 2)
	known := docAsMap(providers[0])
	require.NotContains(t, known, ddMetaKey, "every value is known once evaluated")
	require.Equal(t, map[string]interface{}{"Team": "a"}, docAsMap(known["default_tags"].([]interface{})[0])["tags"])
	require.Equal(t, map[string]interface{}{unknownKey: map[string]interface{}{
		"default_tags": []interface{}{map[string]interface{}{"tags": true}},
	}}, docAsMap(providers[1])[ddMetaKey])
}
