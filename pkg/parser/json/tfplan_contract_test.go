/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"context"
	stdjson "encoding/json"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestPlanValuesSingleNestedBlockIsAList(t *testing.T) {
	values, meta := plannedWeb(t, valuesPlanDoc(t,
		`{"timeouts":{"create":"10m","delete":null},"settings":{},"_dd_lines":{"_dd_timeouts":{"_dd_line":5}}}`,
		`{"settings":{"mode":true}}`,
		`{"timeouts":{"create":{"constant_value":"10m"}},"settings":{"mode":{"references":["var.mode"]}}}`))
	require.Equal(t, []interface{}{map[string]interface{}{"create": "10m"}}, values["timeouts"])
	require.Equal(t, []interface{}{map[string]interface{}{"mode": "${__dd_unknown__}"}}, values["settings"])
	require.Equal(t, map[string]interface{}{
		"timeouts": []interface{}{map[string]interface{}{"create": true}},
		"settings": []interface{}{map[string]interface{}{"mode": true}},
	}, meta["configured"])
	require.Equal(t, map[string]interface{}{
		"settings": []interface{}{map[string]interface{}{"mode": true}},
	}, meta["unknown"])
	require.Equal(t, map[string]interface{}{
		"timeouts": []interface{}{map[string]interface{}{"create": []interface{}{}}},
		"settings": []interface{}{map[string]interface{}{"mode": []interface{}{}}},
	}, meta["references"])
	require.Equal(t, map[string]interface{}{"_dd_timeouts": map[string]interface{}{
		"_dd_line": float64(5),
		"_dd_arr":  []interface{}{map[string]interface{}{"_dd__default": map[string]interface{}{"_dd_line": float64(5)}}},
	}}, values["_dd_lines"], "the wrapped block's element keeps the block's line")
}

// An expression with neither a constant nor a reference, such as timestamp(),
// is an attribute that reads nothing; an empty element of a block list is a
// body.
func TestPlanEmptyExpressionIsAnAttribute(t *testing.T) {
	values, meta := plannedWeb(t, valuesPlanDoc(t,
		`{"ingress":[{"from_port":80}]}`,
		`{"stamp":true}`,
		`{"stamp":{},"ingress":[{}]}`))
	require.Equal(t, "${__dd_unknown__}", values["stamp"])
	require.Equal(t, map[string]interface{}{"stamp": true}, meta["unknown"])
	require.Equal(t, map[string]interface{}{"stamp": []interface{}{}}, meta["references"])
	require.Equal(t, map[string]interface{}{
		"stamp":   true,
		"ingress": []interface{}{map[string]interface{}{}},
	}, meta["configured"])

	planned := `{"resources":[{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","values":{}}]}`
	config := `{"outputs":{"at":{"expression":{}}},
		"module_calls":{"m":{"source":"./m","expressions":{"stamp":{},"name":{"constant_value":"x"}}}},
		"resources":[{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","expressions":{}}]}`
	doc := mustParse(t, referencesPlanDoc(t, planned, []string{"aws_s3_bucket.b"}, config))
	call := doc["module"].(map[string]interface{})["m"].(map[string]interface{})
	require.Equal(t, "${__dd_unknown__}", call["stamp"])
	require.Equal(t, "x", call["name"])
	callMeta := call["_dd_meta"].(map[string]interface{})
	require.Equal(t, map[string]interface{}{"stamp": true}, callMeta["unknown"])
	require.Equal(t, map[string]interface{}{"stamp": []interface{}{}, "name": []interface{}{}}, callMeta["references"])
	output := doc["output"].(map[string]interface{})["at"].(map[string]interface{})
	require.Equal(t, "${__dd_unknown__}", output["value"])
	require.Equal(t, map[string]interface{}{"value": []interface{}{}}, output["_dd_meta"].(map[string]interface{})["references"])
}

func TestPlanModuleCallWithoutArgumentsHasNoValue(t *testing.T) {
	planned := `{"resources":[{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","values":{}}]}`
	config := `{"module_calls":{"m":{"source":"./m","expressions":{}}},
		"resources":[{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","expressions":{}}]}`
	doc := mustParse(t, referencesPlanDoc(t, planned, []string{"aws_s3_bucket.b"}, config))
	require.Equal(t, map[string]interface{}{
		"source": "./m",
		"_dd_meta": map[string]interface{}{
			"address":    "module.m",
			"references": map[string]interface{}{},
		},
	}, doc["module"].(map[string]interface{})["m"])
}

const providerPlan = `{"format_version":"1.2","terraform_version":"1.9.0",
	"planned_values":{"root_module":{"resources":[
		{"address":"aws_s3_bucket.a","mode":"managed","type":"aws_s3_bucket","name":"a","values":{}},
		{"address":"aws_s3_bucket.w","mode":"managed","type":"aws_s3_bucket","name":"w","values":{}},
		{"address":"data.aws_caller_identity.me","mode":"data","type":"aws_caller_identity","name":"me","values":{}}],
	"child_modules":[
		{"address":"module.child","resources":[
			{"address":"module.child.aws_s3_bucket.c","mode":"managed","type":"aws_s3_bucket","name":"c","values":{}},
			{"address":"module.child.aws_s3_bucket.legacy","mode":"managed","type":"aws_s3_bucket","name":"legacy","values":{}}]},
		{"address":"module.own","resources":[
			{"address":"module.own.aws_s3_bucket.o","mode":"managed","type":"aws_s3_bucket","name":"o","values":{}}],
		 "child_modules":[{"address":"module.own.module.inner","resources":[
			{"address":"module.own.module.inner.aws_s3_bucket.i","mode":"managed","type":"aws_s3_bucket","name":"i","values":{}}]}]}]}},
	"resource_changes":[],
	"configuration":{
		"provider_config":{
			"aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","expressions":{
				"region":{"constant_value":"us-east-1"},
				"default_tags":[{"tags":{"constant_value":{"Team":"core"}}}],
				"assume_role":{"role_arn":{"references":["var.role"]}}}},
			"aws.west":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","alias":"west","expressions":{
				"region":{"references":["var.region"]}}},
			"random":{"name":"random","full_name":"registry.terraform.io/hashicorp/random","version_constraint":">= 3.0"},
			"module.child:aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","module_address":"module.child"},
			"module.own:aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","module_address":"module.own","expressions":{
				"region":{"constant_value":"eu-west-1"}}},
			"module.own.module.inner:aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","module_address":"module.own.module.inner"}},
		"root_module":{
			"variables":{"region":{"default":"us-west-2","description":"Region"},"role":{"sensitive":true},"plain":{}},
			"resources":[
				{"address":"aws_s3_bucket.a","mode":"managed","type":"aws_s3_bucket","name":"a","provider_config_key":"aws"},
				{"address":"aws_s3_bucket.w","mode":"managed","type":"aws_s3_bucket","name":"w","provider_config_key":"aws.west"},
				{"address":"data.aws_caller_identity.me","mode":"data","type":"aws_caller_identity","name":"me","provider_config_key":"aws.west"}],
			"module_calls":{
				"child":{"source":"./child","module":{"resources":[
					{"address":"aws_s3_bucket.c","mode":"managed","type":"aws_s3_bucket","name":"c","provider_config_key":"module.child:aws"},
					{"address":"aws_s3_bucket.legacy","mode":"managed","type":"aws_s3_bucket","name":"legacy","provider_config_key":"child:aws"}]}},
				"own":{"source":"./own","module":{
					"resources":[{"address":"aws_s3_bucket.o","mode":"managed","type":"aws_s3_bucket","name":"o","provider_config_key":"module.own:aws"}],
					"module_calls":{"inner":{"source":"./inner","module":{"resources":[
						{"address":"aws_s3_bucket.i","mode":"managed","type":"aws_s3_bucket","name":"i","provider_config_key":"module.own.module.inner:aws"}]}}}}}}}}}`

func parsePlanJSON(t *testing.T, raw string) model.Document {
	t.Helper()
	var doc model.Document
	require.NoError(t, stdjson.Unmarshal([]byte(raw), &doc))
	return mustParse(t, doc)
}

func TestPlanResourceProviderAddress(t *testing.T) {
	doc := parsePlanJSON(t, providerPlan)
	for addr, want := range map[string]string{
		"aws_s3_bucket.a":                         "aws",
		"aws_s3_bucket.w":                         "aws.west",
		"data.aws_caller_identity.me":             "aws.west",
		"module.child.aws_s3_bucket.c":            "aws",
		"module.child.aws_s3_bucket.legacy":       "aws",
		"module.own.aws_s3_bucket.o":              "module.own:aws",
		"module.own.module.inner.aws_s3_bucket.i": "module.own:aws",
	} {
		require.Equal(t, want, ddMetaFor(t, doc, addr)["provider"], addr)
	}
}

func TestPlanProviderSection(t *testing.T) {
	doc := parsePlanJSON(t, providerPlan)
	require.Equal(t, map[string]interface{}{
		"aws": []interface{}{
			map[string]interface{}{
				"region":       "us-east-1",
				"default_tags": []interface{}{map[string]interface{}{"tags": map[string]interface{}{"Team": "core"}}},
				"assume_role":  []interface{}{map[string]interface{}{"role_arn": "${__dd_unknown__}"}},
				"_dd_meta": map[string]interface{}{
					"address":  "provider.aws",
					"provider": "aws",
					"unknown": map[string]interface{}{
						"assume_role": []interface{}{map[string]interface{}{"role_arn": true}},
					},
				},
			},
			map[string]interface{}{
				"alias":  "west",
				"region": "${__dd_unknown__}",
				"_dd_meta": map[string]interface{}{
					"address":  "provider.aws.west",
					"provider": "aws.west",
					"unknown":  map[string]interface{}{"region": true},
				},
			},
		},
	}, doc["provider"], "only root provider blocks; a provider that is only required has no block")
}

func TestPlanChildModuleSections(t *testing.T) {
	doc := parsePlanJSON(t, `{
		"format_version":"1.2","terraform_version":"1.9.0",
		"planned_values":{"root_module":{"resources":[]}},
		"configuration":{"root_module":{
			"outputs":{"root_out":{"description":"root"}},
			"module_calls":{"wrapper":{"source":"./wrapper","module":{
				"outputs":{"child_output":{"expression":{"references":["var.x"]}}},
				"variables":{"name":{}},
				"module_calls":{"child":{"source":"git::https://example.invalid/mod.git","module":{
					"outputs":{"deep":{"description":"deep"}}
				}}}
			}}}
		}}}`)
	require.Contains(t, doc["output"], "root_out")
	require.Contains(t, doc["output"], "module.wrapper.child_output")
	require.Contains(t, doc["output"], "module.wrapper.module.child.deep")
	require.Equal(t, "deep", doc["output"].(map[string]any)["module.wrapper.module.child.deep"].(map[string]any)["description"])
	name := doc["variable"].(map[string]any)["module.wrapper.name"].(map[string]any)
	require.Equal(t, true, name["_dd_meta"].(map[string]any)["unknown"].(map[string]any)["type"])
	require.Equal(t, "git::https://example.invalid/mod.git",
		doc["module"].(map[string]any)["module.wrapper.module.child"].(map[string]any)["source"])
	require.Equal(t, "./wrapper", doc["module"].(map[string]any)["wrapper"].(map[string]any)["source"])
}

func TestPlanVariableSection(t *testing.T) {
	doc := parsePlanJSON(t, providerPlan)
	typeUnknown := map[string]interface{}{"unknown": map[string]interface{}{"type": true}}
	require.Equal(t, map[string]interface{}{
		"region": map[string]interface{}{
			"default": "us-west-2", "description": "Region", "_dd_meta": map[string]interface{}{"unknown": typeUnknown["unknown"]},
		},
		"role":  map[string]interface{}{"sensitive": true, "_dd_meta": map[string]interface{}{"unknown": typeUnknown["unknown"]}},
		"plain": map[string]interface{}{"_dd_meta": map[string]interface{}{"unknown": typeUnknown["unknown"]}},
	}, doc["variable"])
}

// A data source or managed resource with state is in both planned_values and
// prior_state. Its values come from planned_values, and so does its line.
func TestPlanHeaderLinesPreferPlannedValues(t *testing.T) {
	raw := `{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.b",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "b",
          "values": {
            "bucket": "planned"
          }
        },
        {
          "address": "data.aws_ami.u",
          "mode": "data",
          "type": "aws_ami",
          "name": "u",
          "values": {
            "id": "planned"
          }
        }
      ]
    }
  },
  "prior_state": {
    "format_version": "1.0",
    "values": {
      "root_module": {
        "resources": [
          {
            "address": "aws_s3_bucket.b",
            "mode": "managed",
            "type": "aws_s3_bucket",
            "name": "b",
            "values": {
              "bucket": "prior"
            }
          },
          {
            "address": "data.aws_ami.u",
            "mode": "data",
            "type": "aws_ami",
            "name": "u",
            "values": {
              "id": "prior"
            }
          },
          {
            "address": "data.aws_ami.prior_only",
            "mode": "data",
            "type": "aws_ami",
            "name": "prior_only",
            "values": {
              "id": "prior"
            }
          }
        ]
      }
    }
  },
  "resource_changes": [],
  "configuration": {
    "root_module": {}
  }
}`
	doc := parseRawPlan(t, raw)
	headerLine := func(section, typ, name string) interface{} {
		lines := doc[section].(map[string]interface{})[typ].(map[string]interface{})["_dd_lines"].(map[string]interface{})
		return lines["_dd_"+name].(map[string]interface{})["_dd_line"]
	}
	require.Equal(t, float64(lineOf(t, raw, `"bucket": "planned"`)-1), headerLine("resource", "aws_s3_bucket", "b"))
	require.Equal(t, float64(lineOf(t, raw, `"id": "planned"`)-1), headerLine("data", "aws_ami", "u"))
	require.Equal(t, "planned", doc["data"].(map[string]interface{})["aws_ami"].(map[string]interface{})["u"].(map[string]interface{})["id"])
	require.Greater(t, headerLine("data", "aws_ami", "prior_only"), float64(lineOf(t, raw, `"prior_state"`)),
		"a data source only prior_state has keeps its prior_state line")
}

// The output, module, variable and provider sections carry line tables the
// way a resource type does, read from the configuration.
func TestPlanConfigSectionLines(t *testing.T) {
	raw := `{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "planned_values": {
    "root_module": {}
  },
  "resource_changes": [],
  "configuration": {
    "provider_config": {
      "aws": {
        "name": "aws",
        "expressions": {
          "region": {
            "constant_value": "us-east-1"
          },
          "default_tags": [
            {
              "tags": {
                "constant_value": {
                  "Team": "core"
                }
              }
            }
          ]
        }
      },
      "aws.west": {
        "name": "aws",
        "alias": "west",
        "expressions": {
          "region": {
            "constant_value": "us-west-2"
          }
        }
      }
    },
    "root_module": {
      "outputs": {
        "bucket_id": {
          "expression": {
            "references": [
              "var.region"
            ]
          },
          "description": "out"
        }
      },
      "module_calls": {
        "net": {
          "source": "./net",
          "expressions": {
            "cidr": {
              "constant_value": "10.0.0.0/16"
            }
          }
        }
      },
      "variables": {
        "region": {
          "default": "us-east-1",
          "description": "Region"
        }
      }
    }
  }
}`
	doc := parseRawPlan(t, raw)
	line := func(path ...interface{}) interface{} {
		var v interface{} = doc
		for _, p := range path {
			switch k := p.(type) {
			case string:
				if d, ok := v.(model.Document); ok {
					v = map[string]interface{}(d)
				}
				v = v.(map[string]interface{})[k]
			case int:
				v = v.([]interface{})[k]
			}
		}
		return v
	}
	at := func(text string) float64 { return float64(lineOf(t, raw, text)) }

	require.Equal(t, at(`"bucket_id": {`), line("output", "_dd_lines", "_dd_bucket_id", "_dd_line"))
	require.Equal(t, at(`"expression": {`), line("output", "bucket_id", "_dd_lines", "_dd_value", "_dd_line"))
	require.Equal(t, at(`"description": "out"`), line("output", "bucket_id", "_dd_lines", "_dd_description", "_dd_line"))

	require.Equal(t, at(`"net": {`), line("module", "_dd_lines", "_dd_net", "_dd_line"))
	require.Equal(t, at(`"cidr": {`), line("module", "net", "_dd_lines", "_dd_cidr", "_dd_line"))
	require.Equal(t, at(`"source": "./net"`), line("module", "net", "_dd_lines", "_dd_source", "_dd_line"))

	require.Equal(t, at(`"variables": {`)+1, line("variable", "_dd_lines", "_dd_region", "_dd_line"))
	require.Equal(t, at(`"description": "Region"`), line("variable", "region", "_dd_lines", "_dd_description", "_dd_line"))

	require.Equal(t, at(`"aws": {`), line("provider", "_dd_lines", "_dd_aws", "_dd_line"))
	require.Equal(t, at(`"aws.west": {`), line("provider", "_dd_lines", "_dd_aws", "_dd_arr", 1, "_dd__default", "_dd_line"))
	require.Equal(t, at(`"alias": "west"`), line("provider", "aws", 1, "_dd_lines", "_dd_alias", "_dd_line"))
	require.Equal(t, at(`"default_tags": [`), line("provider", "aws", 0, "_dd_lines", "_dd_default_tags", "_dd_line"))
}

func parseRawPlan(t *testing.T, raw string) model.Document {
	t.Helper()
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), []byte(raw), "plan.json", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	return docs[0]
}

// lineOf is the 1-based line of the first line of raw containing text.
func lineOf(t *testing.T, raw, text string) int {
	t.Helper()
	for i, l := range strings.Split(raw, "\n") {
		if strings.Contains(l, text) {
			return i + 1
		}
	}
	require.Failf(t, "text not found", "%q", text)
	return -1
}

// A module call's arguments are evaluated in the calling module, an output's
// value in the module declaring it.
func TestPlanConfigReferencesResolveInEvaluatingModule(t *testing.T) {
	doc := parsePlanJSON(t, `{
		"format_version":"1.2","terraform_version":"1.9.0",
		"planned_values":{"root_module":{
			"resources":[{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","values":{}}],
			"child_modules":[{"address":"module.w","resources":[
				{"address":"module.w.aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","values":{}}]}]}},
		"configuration":{"root_module":{
			"resources":[{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","expressions":{}}],
			"module_calls":{"w":{"source":"./w",
				"expressions":{"x":{"references":["aws_s3_bucket.b.id","aws_s3_bucket.b"]}},
				"module":{
					"resources":[{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","expressions":{}}],
					"outputs":{"o":{"expression":{"references":["aws_s3_bucket.b.id","aws_s3_bucket.b"]}}},
					"module_calls":{"child":{"source":"./child",
						"expressions":{"name":{"references":["aws_s3_bucket.b.id","aws_s3_bucket.b"]}},
						"module":{}}}}}}}}}`)
	refsOf := func(section, key, attr string) any {
		block, _ := doc[section].(map[string]any)[key].(map[string]any)
		require.NotNil(t, block, section+"."+key)
		refs, _ := block["_dd_meta"].(map[string]any)["references"].(map[string]any)
		return refs[attr]
	}
	require.Equal(t, []any{"aws_s3_bucket.b"}, refsOf("module", "w", "x"))
	require.Equal(t, []any{"module.w.aws_s3_bucket.b"}, refsOf("module", "module.w.module.child", "name"))
	require.Equal(t, []any{"module.w.aws_s3_bucket.b"}, refsOf("output", "module.w.o", "value"))
}

// A planned set does not keep the configuration's order, so a constant is
// restored over after_unknown only when every sibling block writes it.

// A module under count evaluates each instance's expressions in that
// instance; references from the shared configuration resolve to every
// planned instance of the named resource.
func TestPlanConfigReferencesResolveAcrossCountedModule(t *testing.T) {
	doc := parsePlanJSON(t, `{
		"format_version":"1.2","terraform_version":"1.9.0",
		"planned_values":{"root_module":{"child_modules":[
			{"address":"module.w[0]","resources":[
				{"address":"module.w[0].aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","values":{}}]},
			{"address":"module.w[1]","resources":[
				{"address":"module.w[1].aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","values":{}}]}]}},
		"configuration":{"root_module":{
			"module_calls":{"w":{"source":"./w","count_expression":{"constant_value":2},
				"module":{
					"resources":[{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","expressions":{}}],
					"outputs":{"o":{"expression":{"references":["aws_s3_bucket.b.id","aws_s3_bucket.b"]}}}}}}}}}`)
	block, _ := doc["output"].(map[string]any)["module.w.o"].(map[string]any)
	require.NotNil(t, block)
	refs, _ := block["_dd_meta"].(map[string]any)["references"].(map[string]any)
	require.ElementsMatch(t, []any{"module.w[0].aws_s3_bucket.b", "module.w[1].aws_s3_bucket.b"}, refs["value"])
}

func TestPlanValuesSiblingConstantNeedsAgreement(t *testing.T) {
	_, meta := plannedWeb(t, valuesPlanDoc(t,
		`{"ebs":[{"type":""},{"type":""}]}`,
		`{"ebs":[{"type":true},{"type":true}]}`,
		`{"ebs":[{"type":{"constant_value":"gp3"}},{"type":{"constant_value":""}}]}`))
	require.Equal(t, map[string]any{"ebs": []any{map[string]any{"type": true}, map[string]any{"type": true}}}, meta["unknown"])

	_, meta = plannedWeb(t, valuesPlanDoc(t,
		`{"ebs":[{"type":""},{"type":""}]}`,
		`{"ebs":[{"type":true},{"type":true}]}`,
		`{"ebs":[{"type":{"constant_value":""}},{}]}`))
	require.Equal(t, map[string]any{"ebs": []any{map[string]any{"type": true}, map[string]any{"type": true}}}, meta["unknown"])

	values, meta := plannedWeb(t, valuesPlanDoc(t,
		`{"ebs":[{"type":""},{"type":""}]}`,
		`{"ebs":[{"type":true},{"type":true}]}`,
		`{"ebs":[{"type":{"constant_value":""}},{"type":{"constant_value":""}}]}`))
	require.NotContains(t, meta, "unknown")
	require.Equal(t, []any{map[string]any{"type": ""}, map[string]any{"type": ""}}, values["ebs"])
}

// A constant count of zero creates no instance: leave no child sections under it.
func TestPlanZeroCountModuleHasNoChildSections(t *testing.T) {
	doc := parsePlanJSON(t, `{
		"format_version":"1.2","terraform_version":"1.9.0",
		"planned_values":{"root_module":{"resources":[]}},
		"configuration":{"root_module":{
			"module_calls":{
				"zero":{"source":"./zero","count_expression":{"constant_value":0},"module":{
					"outputs":{"zo":{"expression":{"constant_value":1}}},
					"variables":{"zx":{}},
					"module_calls":{"inner":{"source":"./inner","module":{
						"outputs":{"io":{"expression":{"constant_value":2}}}
					}}}
				}},
				"one":{"source":"./one","module":{
					"outputs":{"oo":{"expression":{"constant_value":3}}}
				}}
			}
		}}}`)
	out, _ := doc["output"].(map[string]any)
	require.NotContains(t, out, "module.zero.zo")
	require.NotContains(t, out, "module.zero.module.inner.io")
	require.Contains(t, out, "module.one.oo")
	vars, _ := doc["variable"].(map[string]any)
	require.NotContains(t, vars, "module.zero.zx")
	mods, _ := doc["module"].(map[string]any)
	require.NotContains(t, mods, "zero")
	require.NotContains(t, mods, "module.zero.module.inner")
	require.Contains(t, mods, "one")
}
