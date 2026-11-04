package engine

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
)

func TestTerraformIndexSpansEveryRoot(t *testing.T) {
	docs := []map[string]interface{}{
		{"id": "a", "resource": map[string]interface{}{
			"aws_s3_bucket": map[string]interface{}{"b": map[string]interface{}{"bucket": "shared"}},
		}},
		{"id": "b", "resource": map[string]interface{}{
			"aws_s3_bucket_logging": map[string]interface{}{
				"l": map[string]interface{}{
					"bucket":        "shared",
					"target_bucket": "${var.logs}",
					"target_prefix": "pending",
					"tags":          map[string]interface{}{"k": "v"},
					ddMetaKey: map[string]interface{}{
						"unknown":    map[string]interface{}{"target_prefix": true},
						"references": map[string]interface{}{"bucket": []interface{}{}},
					},
				},
				"module.m.aws_s3_bucket_logging.l[0]": map[string]interface{}{"bucket": "from-module"},
			},
		}, "data": map[string]interface{}{
			"aws_iam_policy": map[string]interface{}{"p": []interface{}{
				map[string]interface{}{"name": "first"},
				map[string]interface{}{"name": "second"},
			}},
		}, "ephemeral": map[string]interface{}{
			"random_password": map[string]interface{}{"p": map[string]interface{}{"special": "yes"}},
		}},
	}
	terms := make([]*ast.Term, len(docs))
	buckets := make([][]string, len(docs))
	for i, doc := range docs {
		v, err := ast.InterfaceToValue(doc)
		require.NoError(t, err)
		terms[i] = ast.NewTerm(v)
		buckets[i] = []string{platformTerraform}
	}
	payloads := assemblePlatformPayloads(terms, buckets, nil, map[string]bool{platformTerraform: true}, false,
		map[string][]string{"a": {"rootA"}, "b": {"rootB"}}, true, true)

	rootA := rootPayloads(payloads)["rootA"]
	require.True(t, evalBool(t, rootA, `input._dd_tf_index.aws_s3_bucket_logging.bucket["shared"].rootB == true`))
	require.True(t, evalBool(t, rootA, `input._dd_root == "rootA"`))
	require.True(t, evalBool(t, payloads.byPlatform[platformTerraform], `not input._dd_root`), "a payload of several roots stands for none")
	require.Len(t, termsByID(t, rootA), 1)

	want := ast.MustParseTerm(`{
		"aws_s3_bucket": {"bucket": {"shared": {"rootA": true}}},
		"aws_s3_bucket_logging": {"bucket": {"shared": {"rootB": true}, "from-module": {"rootB": true}}},
		"data.aws_iam_policy": {"name": {"first": {"rootB": true}, "second": {"rootB": true}}},
		"ephemeral.random_password": {"special": {"yes": {"rootB": true}}}
	}`)
	for _, payload := range []ast.Value{rootA, rootPayloads(payloads)["rootB"], payloads.byPlatform[platformTerraform]} {
		got := payload.(ast.Object).Get(ast.StringTerm(tfIndexKey))
		require.NotNil(t, got)
		require.Equal(t, 0, want.Value.Compare(got.Value), "got %v", got)
	}
}

func TestTerraformIndexOnlyIndexesValuesTracedToNothing(t *testing.T) {
	doc := map[string]interface{}{"resource": map[string]interface{}{
		"aws_s3_bucket_logging": map[string]interface{}{
			"traced": map[string]interface{}{
				"bucket":        "literal",
				"target_bucket": "resolved-from-reference",
				"target_prefix": "untraced",
				ddMetaKey: map[string]interface{}{"references": map[string]interface{}{
					"bucket":        []interface{}{},
					"target_bucket": []interface{}{"aws_s3_bucket.logs"},
				}},
			},
			"as_written": map[string]interface{}{"bucket": "as-written"},
			"planned": map[string]interface{}{
				"bucket":  "from-plan",
				ddMetaKey: map[string]interface{}{"references": map[string]interface{}{}},
			},
		},
	}}
	v, err := ast.InterfaceToValue(doc)
	require.NoError(t, err)

	got := buildTerraformIndex([]*ast.Term{ast.NewTerm(v)}, nil)
	want := ast.MustParseTerm(`{"aws_s3_bucket_logging": {"bucket": {"literal": {"": true}, "as-written": {"": true}}}}`)
	require.Equal(t, 0, want.Value.Compare(got), "got %v", got)
}

func TestTerraformIndexNeeded(t *testing.T) {
	require.False(t, terraformIndexNeeded(nil))
	require.False(t, terraformIndexNeeded([]model.QueryMetadata{{
		Platform: "Terraform", Content: `DatadogPolicy contains result if { true }`,
	}}))
	require.True(t, terraformIndexNeeded([]model.QueryMetadata{{
		Platform: "Terraform", Content: `tf_lib.literal_seen("aws_s3_bucket", "bucket", name)`,
	}}))
	require.True(t, terraformIndexNeeded(
		[]model.QueryMetadata{{Platform: "Terraform", Content: `true`}},
		`literal_seen(type, attr, value) if { input._dd_tf_index[type][attr][value] }`,
	))
	require.False(t, terraformIndexNeeded([]model.QueryMetadata{{
		Platform: "kubernetes", Content: `literal_seen("x", "y", "z")`,
	}}), "only Terraform rules trigger the index")
	require.True(t, terraformIndexNeeded([]model.QueryMetadata{{
		Platform: "Terraform", Content: `input._dd_tf_index`,
	}}), "platform names are matched case-insensitively")
}

func TestAssemblePlatformPayloadsSkipsIndexWhenUnneeded(t *testing.T) {
	doc := map[string]interface{}{
		"id": "a",
		"resource": map[string]interface{}{
			"aws_s3_bucket": map[string]interface{}{"b": map[string]interface{}{"bucket": "shared"}},
		},
	}
	v, err := ast.InterfaceToValue(doc)
	require.NoError(t, err)
	terms := []*ast.Term{ast.NewTerm(v)}
	buckets := [][]string{{platformTerraform}}

	without := assemblePlatformPayloads(terms, buckets, nil, map[string]bool{platformTerraform: true}, false,
		map[string][]string{"a": {"root"}}, true, false)
	require.Nil(t, without.byPlatform[platformTerraform].(ast.Object).Get(ast.StringTerm(tfIndexKey)))
	require.Nil(t, rootPayloads(without)["root"].(ast.Object).Get(ast.StringTerm(tfIndexKey)))

	with := assemblePlatformPayloads(terms, buckets, nil, map[string]bool{platformTerraform: true}, false,
		map[string][]string{"a": {"root"}}, true, true)
	require.NotNil(t, with.byPlatform[platformTerraform].(ast.Object).Get(ast.StringTerm(tfIndexKey)))
}

func TestAddDocumentMatchesTransformedIndex(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{"id": "a", "resource": map[string]interface{}{
			"aws_s3_bucket": map[string]interface{}{"b": map[string]interface{}{"bucket": "shared"}},
		}},
		map[string]interface{}{"id": "b", "resource": map[string]interface{}{
			"aws_s3_bucket_logging": map[string]interface{}{
				"l": map[string]interface{}{
					"bucket":        "shared",
					"target_bucket": "${var.logs}",
					"target_prefix": "pending",
					"tags":          map[string]interface{}{"k": "v"},
					ddMetaKey: map[string]interface{}{
						"unknown":    map[string]interface{}{"target_prefix": true},
						"references": map[string]interface{}{"bucket": []interface{}{}},
					},
				},
				"module.m.aws_s3_bucket_logging.l[0]": map[string]interface{}{"bucket": "from-module"},
			},
		}, "data": map[string]interface{}{
			"aws_iam_policy": map[string]interface{}{"p": []interface{}{
				map[string]interface{}{"name": "first"},
				map[string]interface{}{"name": "second"},
			}},
		}, "ephemeral": map[string]interface{}{
			"random_password": map[string]interface{}{"p": map[string]interface{}{"special": "yes"}},
		}},
		map[string]interface{}{"resource": map[string]interface{}{
			"aws_s3_bucket_logging": map[string]interface{}{
				"traced": map[string]interface{}{
					"bucket":        "literal",
					"target_bucket": "resolved-from-reference",
					"target_prefix": "untraced",
					ddMetaKey: map[string]interface{}{"references": map[string]interface{}{
						"bucket":        []interface{}{},
						"target_bucket": []interface{}{"aws_s3_bucket.logs"},
					}},
				},
				"as_written": map[string]interface{}{"bucket": "as-written"},
				"encoded": map[string]interface{}{
					"bucket":  `jsonencode("kept")`,
					"policy":  `jsonencode({ statement = "no" })`,
					"wrapped": `${jsonencode("also")}`,
				},
			},
		}},
	}
	idx := make(literalIndex)
	for _, doc := range docs {
		idx.addDocument(doc, nil)
	}
	require.Equal(t, 0, transformedIndex(t, docs).Compare(idx.object()))
}

func transformedIndex(t *testing.T, docs []interface{}) ast.Value {
	t.Helper()
	ins := &Inspector{}
	terms := make([]*ast.Term, len(docs))
	for i, doc := range docs {
		v, err := ast.InterfaceToValue(doc)
		require.NoError(t, err)
		terms[i] = ast.NewTerm(ins.TransformJsonencodeInPayload(context.Background(), v))
	}
	return buildTerraformIndex(terms, nil)
}

func evalBool(t *testing.T, input ast.Value, query string) bool {
	t.Helper()
	rs, err := rego.New(rego.Query(query), rego.ParsedInput(input)).Eval(context.Background())
	require.NoError(t, err)
	return len(rs) == 1 && len(rs[0].Expressions) == 1 && rs[0].Expressions[0].Value == true
}

func TestTerraformIndexSkipsBlocksWithMetaButNoReferences(t *testing.T) {
	doc := map[string]interface{}{"resource": map[string]interface{}{
		"aws_s3_bucket_logging": map[string]interface{}{
			"untraced": map[string]interface{}{
				"bucket":  "planned-untraced",
				ddMetaKey: map[string]interface{}{"address": "aws_s3_bucket_logging.untraced"},
			},
			"traced_empty": map[string]interface{}{
				"bucket":  "traced-empty",
				ddMetaKey: map[string]interface{}{"references": map[string]interface{}{"bucket": []interface{}{}}},
			},
			"as_written": map[string]interface{}{"bucket": "as-written"},
		},
	}}
	v, err := ast.InterfaceToValue(doc)
	require.NoError(t, err)
	want := ast.MustParseTerm(`{"aws_s3_bucket_logging": {"bucket": {"traced-empty": {"": true}, "as-written": {"": true}}}}`)
	require.Equal(t, 0, want.Value.Compare(buildTerraformIndex([]*ast.Term{ast.NewTerm(v)}, nil)))

	idx := make(literalIndex)
	idx.addDocument(doc, nil)
	require.Equal(t, 0, want.Value.Compare(idx.object()))
}
