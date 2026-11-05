/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// Empty chain adds no segment; a chain changes the hash for Terraform and is ignored elsewhere.
func TestGetDatadogFingerprintHash_ModuleCallChain(t *testing.T) {
	sci := SCIInfo{RepositoryCommitInfo: RepositoryCommitInfo{RepositoryUrl: "repo"}}

	// An empty chain appends nothing, so Terraform matches the plain base hash (no fingerprint churn).
	base := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", "Kubernetes", "aws_s3_bucket", "this", "rule-1", "", "")
	tfEmpty := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", TerraformPlatform, "aws_s3_bucket", "this", "rule-1", "", "")
	require.Equal(t, base, tfEmpty, "empty call chain must not change the fingerprint")

	fromA := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", TerraformPlatform, "aws_s3_bucket", "this", "rule-1", "", "stack-a/main.tf|module.bucket")
	fromB := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", TerraformPlatform, "aws_s3_bucket", "this", "rule-1", "", "stack-b/main.tf|module.bucket")

	require.NotEqual(t, tfEmpty, fromA, "a non-empty call chain must change the fingerprint")
	require.NotEqual(t, fromA, fromB, "distinct callers must produce distinct fingerprints")

	fromAAgain := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", TerraformPlatform, "aws_s3_bucket", "this", "rule-1", "", "stack-a/main.tf|module.bucket")
	require.Equal(t, fromA, fromAAgain, "the same caller must produce a stable fingerprint")

	// Non-Terraform platforms must ignore the module call chain.
	k8sWithChain := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", "Kubernetes", "aws_s3_bucket", "this", "rule-1", "", "stack-a/main.tf|module.bucket")
	require.Equal(t, base, k8sWithChain, "non-Terraform platforms must ignore the module call chain")
}

// FindingIdentity (storage's grouping) and CreateSummary (the report's
// persisted fingerprint) must group findings on exactly the same fields (see
// fingerprintFields), or a finding storage reduced to one copy could still be
// fingerprinted as two distinct findings in the report, or the reverse.
func TestFindingIdentity_EqualIdentityMeansEqualCreateSummaryFingerprint(t *testing.T) {
	a := Vulnerability{
		FileName: "/repo/stack/main.tf", Platform: TerraformPlatform, QueryID: "rule-1",
		ResourceType: "aws_security_group", ResourceName: "sg", ModuleCallChain: "stack/main.tf|module.sg",
		Line: 4, LineWithVulnerability: "cidr_blocks = [\"0.0.0.0/0\"] # ingress[0]",
		Severity: SeverityHigh, SearchKey: "aws_security_group[sg].ingress[0].cidr_blocks",
	}
	// b differs only on fields FindingIdentity does not use for a Terraform
	// finding: the line and the exact text detected there. This is exactly the
	// shape of two ingress blocks violating one rule on one resource.
	b := a
	b.Line = 9
	b.LineWithVulnerability = "cidr_blocks = [\"0.0.0.0/0\"] # ingress[1]"
	b.SearchKey = "aws_security_group[sg].ingress[1].cidr_blocks"

	require.Equal(t, FindingIdentity(&a), FindingIdentity(&b), "precondition: the two findings share an identity")

	summary := CreateSummary(context.Background(), Counters{}, []Vulnerability{a, b}, "scan", nil, "/repo", SCIInfo{})
	require.Len(t, summary.Queries, 1)
	files := summary.Queries[0].Files
	require.Len(t, files, 2, "CreateSummary keeps every finding it is given; identity reduction is storage's job")
	require.Equal(t, files[0].Fingerprint, files[1].Fingerprint,
		"equal FindingIdentity must mean equal CreateSummary fingerprints")
}

func TestIdentityBeforeLine_IsFindingIdentityUnderEveryChain(t *testing.T) {
	for _, platform := range []string{"Terraform", "CloudFormation", "Kubernetes", ""} {
		for _, chain := range []string{"", "module.a", "module.a.module.b[\"k\"]"} {
			v := &Vulnerability{
				FileName: "modules/app/main.tf", Platform: platform, ResourceType: "aws_s3_bucket",
				ResourceName: "logs", QueryID: "q", LegacyQueryID: "legacy",
				LineWithVulnerability: "line text", ModuleCallChain: chain,
			}
			id, ok := IdentityBeforeLine(v)
			require.True(t, ok, platform)
			want := fingerprintInput(SCIInfo{}, v.FileName, platform, v.ResourceType, v.ResourceName, "legacy", "line text", chain)
			require.Equal(t, want, FindingIdentity(v), platform)
			require.Equal(t, want, id.WithChain(chain), platform)
			require.Equal(t, want, string(id.AppendWithChain(nil, chain)), platform)
		}
	}

	_, ok := IdentityBeforeLine(&Vulnerability{Platform: "Dockerfile"})
	require.False(t, ok, "a Dockerfile identity includes the line")
}

// A Terraform finding identified by its root module and address keys on them
// alone: two instances sharing everything else must not collapse, and the same
// address under another root module is another instance.
func TestFindingIdentity_TerraformIdentity(t *testing.T) {
	base := Vulnerability{
		FileName: "/repo/stack/main.tf", Platform: TerraformPlatform, QueryID: "rule-1",
		ResourceType: "aws_s3_bucket", ResourceName: "this", ModuleCallChain: "stack/main.tf|module.a",
		Severity: SeverityHigh, SearchKey: "aws_s3_bucket[this]",
	}
	first, second, otherRoot := base, base, base
	first.RootModule, first.ResourceID, first.Line = "stack", "aws_s3_bucket.this[0]", 2
	second.RootModule, second.ResourceID, second.Line = "stack", "aws_s3_bucket.this[1]", 9
	otherRoot.RootModule, otherRoot.ResourceID = "other", "aws_s3_bucket.this[0]"

	require.NotEqual(t, FindingIdentity(&first), FindingIdentity(&second))
	require.NotEqual(t, FindingIdentity(&first), FindingIdentity(&otherRoot))
	require.Equal(t, "|stack|aws_s3_bucket.this[0]|rule-1", FindingIdentity(&first))
	require.Equal(t, FindingIdentity(&first),
		string(AppendTerraformIdentity(nil, "rule-1", TerraformIdentity{RootModule: "stack", ResourceID: "aws_s3_bucket.this[0]"})))

	// Half an identity, or one on another platform, is not used.
	half := base
	half.RootModule = "stack"
	require.Equal(t, FindingIdentity(&base), FindingIdentity(&half))
	k8s := first
	k8s.Platform = "Kubernetes"
	_, ok := TerraformIdentityOf(&k8s)
	require.False(t, ok)

	summary := CreateSummary(context.Background(), Counters{}, []Vulnerability{first, second}, "scan", nil, "/repo",
		SCIInfo{RepositoryCommitInfo: RepositoryCommitInfo{RepositoryUrl: "repo"}})
	files := summary.Queries[0].Files
	require.Len(t, files, 2)
	require.Equal(t, stringToHash("repo|stack|aws_s3_bucket.this[0]|rule-1"), files[0].Fingerprint)
	require.Equal(t, stringToHash("repo|stack|aws_s3_bucket.this[1]|rule-1"), files[1].Fingerprint)
	require.Equal(t, "aws_s3_bucket.this[0]", files[0].ResourceID)
	require.Equal(t, "stack", files[0].RootModule)
}
