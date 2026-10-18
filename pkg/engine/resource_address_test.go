/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// Instances of a block that read their instance context but convert
// identically fold into one document keyed by the first of their addresses
// (counted[1]); a finding on it must be reported once per address that value
// stands for, so counted[2] is not lost.
func TestResourceAddressesFor_FoldedIdenticalInstances(t *testing.T) {
	file := &model.FileMetadata{
		Platform: "Terraform",
		Expansions: []model.ResourceExpansion{{
			Path: "resource.aws_s3_bucket.counted",
			Type: "aws_s3_bucket", Name: "counted",
			Addresses: []string{"aws_s3_bucket.counted[0]", "aws_s3_bucket.counted[1]", "aws_s3_bucket.counted[2]"},
			Positions: [][]int{{0}, {1, 2}},
		}},
	}

	for _, searchKey := range []string{
		"aws_s3_bucket.counted[1].acl",  // type.name[key] shape
		`aws_s3_bucket[counted[1]].acl`, // type[name] shape
	} {
		require.Equal(t,
			[]string{"aws_s3_bucket.counted[1]", "aws_s3_bucket.counted[2]"},
			resourceAddressesFor(file, searchKey),
			"search key %s", searchKey)
	}

	// The first distinct instance keeps the block's own name and covers only
	// its own address.
	require.Equal(t, []string{"aws_s3_bucket.counted[0]"},
		resourceAddressesFor(file, "aws_s3_bucket.counted.acl"))
}

// A for_each instance key matches the expansion record's formatted address,
// not just count indexes.
func TestResourceAddressesFor_FoldedForEachInstances(t *testing.T) {
	file := &model.FileMetadata{
		Platform: "Terraform",
		Expansions: []model.ResourceExpansion{{
			Path: "resource.aws_s3_bucket.keyed",
			Type: "aws_s3_bucket", Name: "keyed",
			Addresses: []string{`aws_s3_bucket.keyed["a"]`, `aws_s3_bucket.keyed["b"]`},
			Positions: [][]int{{0}, {1, 0}},
		}},
	}

	require.Equal(t, []string{`aws_s3_bucket.keyed["b"]`, `aws_s3_bucket.keyed["a"]`},
		resourceAddressesFor(file, `aws_s3_bucket.keyed["b"].acl`))
}

// An instance key no planned instance address carries (unknown or
// unformattable) falls back to the search key's own address spelling.
func TestResourceAddressesFor_InstanceKeyWithoutAddress(t *testing.T) {
	file := &model.FileMetadata{
		Platform: "Terraform",
		Expansions: []model.ResourceExpansion{{
			Path: "resource.aws_s3_bucket.counted",
			Type: "aws_s3_bucket", Name: "counted",
			Addresses: []string{"aws_s3_bucket.counted[0]"},
			Positions: [][]int{{0}},
		}},
	}

	require.Equal(t, []string{"aws_s3_bucket.counted[3]"},
		resourceAddressesFor(file, "aws_s3_bucket.counted[3].acl"))
}

// A truncated expansion keeps the block as written alongside its capped
// instances: the as-written conversion stands for the block itself, so a
// finding on the plain block name keeps the unindexed address instead of
// being misattributed to instance [0].
func TestResourceAddressesFor_TruncatedExpansionAsWritten(t *testing.T) {
	file := &model.FileMetadata{
		Platform: "Terraform",
		Expansions: []model.ResourceExpansion{{
			Path: "resource.aws_s3_bucket.counted",
			Type: "aws_s3_bucket", Name: "counted",
			Truncated: true,
			Addresses: []string{"aws_s3_bucket.counted[0]", "aws_s3_bucket.counted[1]"},
			Positions: [][]int{{0}, {1}, {}},
		}},
	}

	// The as-written finding names the block without an instance suffix.
	require.Equal(t, []string{"aws_s3_bucket.counted"},
		resourceAddressesFor(file, "aws_s3_bucket.counted.acl"))

	// The capped instances keep their own addresses.
	require.Equal(t, []string{"aws_s3_bucket.counted[1]"},
		resourceAddressesFor(file, "aws_s3_bucket.counted[1].acl"))
}

// Some rules emit the search key with Terraform's resource. prefix spelled
// out (resource.<type>[<name>].attr); a plain file carries no such prefix in
// its documents, so the identity parse must strip it like the data. one and
// the finding must resolve to the unindexed address spelling — or fan out
// through the expansion record when the block expands.
func TestResourceAddressesFor_ResourcePrefixedSearchKey(t *testing.T) {
	plain := &model.FileMetadata{Platform: "Terraform"}

	for _, searchKey := range []string{
		"resource.aws_elasticache_cluster[c5].engine", // type[name] shape
		"resource.aws_elasticache_cluster.c5.engine",  // type.name shape
	} {
		require.Equal(t, []string{"aws_elasticache_cluster.c5"},
			resourceAddressesFor(plain, searchKey), "search key %s", searchKey)
	}

	expanded := &model.FileMetadata{
		Platform: "Terraform",
		Expansions: []model.ResourceExpansion{{
			Path: "resource.aws_s3_bucket.counted",
			Type: "aws_s3_bucket", Name: "counted",
			Addresses: []string{"aws_s3_bucket.counted[0]", "aws_s3_bucket.counted[1]"},
			Positions: [][]int{{0}, {1}},
		}},
	}
	require.Equal(t, []string{"aws_s3_bucket.counted[0]"},
		resourceAddressesFor(expanded, `resource.aws_s3_bucket[counted[0]].acl`))
}

// tfplan flattens child modules into Resource[type][moduleAddress.name], so a
// module-nested finding's search key splits into more segments than the
// document key has: the key is everything after the resource type.
func TestTfplanAddress_ModuleNestedPlanResource(t *testing.T) {
	file := &model.FileMetadata{
		Platform: "Terraform",
		Document: model.Document{
			"_dd_tfplan_meta": map[string]interface{}{
				"aws_instance": map[string]interface{}{
					"module.m.b[0]": map[string]interface{}{
						"address": "module.m.aws_instance.b[0]",
					},
				},
			},
		},
	}

	require.Equal(t, "module.m.aws_instance.b[0]",
		tfplanAddress(file, "resource.aws_instance.module.m.b[0].tags"))
	require.Equal(t, []string{"module.m.aws_instance.b[0]"},
		resourceAddressesFor(file, "resource.aws_instance.module.m.b[0].tags"))
}

// A root-level plan resource keeps its single-segment document key.
func TestTfplanAddress_RootPlanResource(t *testing.T) {
	file := &model.FileMetadata{
		Platform: "Terraform",
		TfplanResourceAddresses: map[string]map[string]string{
			"aws_instance": {"web": "aws_instance.web"},
		},
	}

	require.Equal(t, "aws_instance.web",
		tfplanAddress(file, "resource.aws_instance.web.tags"))
}

// The resource path a module-addressed document names: the shape handling the
// expandModuleFindings clone path and the ModuleAddress lookup share.
func TestModuleDocResourcePath(t *testing.T) {
	for _, tc := range [...]struct {
		searchKey, want string
	}{
		{"aws_s3_bucket[bucket].acl", "aws_s3_bucket.bucket"},
		{"aws_s3_bucket.bucket.acl", "aws_s3_bucket.bucket"},
		{"resource.aws_s3_bucket.bucket.acl", "aws_s3_bucket.bucket"},
		{"data.aws_ami.ubuntu.id", "aws_ami.ubuntu"},
		{`aws_s3_bucket[b[counted[1]]].acl`, "aws_s3_bucket.b[counted[1]]"},
	} {
		require.Equal(t, tc.want, moduleDocResourcePath(tc.searchKey), "search key %s", tc.searchKey)
	}
	// A type[name] key with nothing after it cannot be told apart from a bare
	// name, matching the ModuleAddress branch's handling.
	require.Empty(t, moduleDocResourcePath("aws_s3_bucket[bucket]"))
	require.Empty(t, moduleDocResourcePath("aws_s3_bucket"))
}
