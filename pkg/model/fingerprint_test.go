/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/stretchr/testify/require"
)

// A resolved Terraform instance identity replaces resource
// name in the fingerprint: two instances sharing everything else but a
// distinct address must not collapse to one finding, and the fingerprint must
// agree with that distinction.
func TestGetDatadogFingerprintHash_ResolvedTerraformIdentity(t *testing.T) {
	sci := SCIInfo{RepositoryCommitInfo: RepositoryCommitInfo{RepositoryUrl: "repo"}}

	hash := func(id TerraformIdentity) string {
		return GetDatadogFingerprintHash(sci, "stack/main.tf", terraformPlatform, "aws_s3_bucket", "this", "rule-1", "", id)
	}

	a := hash(TerraformIdentity{RootModule: "stack", ResourceID: "aws_s3_bucket.this[0]"})
	b := hash(TerraformIdentity{RootModule: "stack", ResourceID: "aws_s3_bucket.this[1]"})
	require.NotEqual(t, a, b, "distinct resolved addresses must produce distinct fingerprints")

	aAgain := hash(TerraformIdentity{RootModule: "stack", ResourceID: "aws_s3_bucket.this[0]"})
	require.Equal(t, a, aAgain, "the same address must produce a stable fingerprint")

	// Same address, different root module: the same module path called from two
	// different root stacks must not collapse.
	c := hash(TerraformIdentity{RootModule: "other-stack", ResourceID: "aws_s3_bucket.this[0]"})
	require.NotEqual(t, a, c, "the same address under a different root must produce a distinct fingerprint")
}

// A Terraform finding without a resolved identity keeps the legacy fingerprint.
// The module call chain is part of that fingerprint; a resolved address replaces it.
func TestGetDatadogFingerprintHash_LegacyTerraformFallback(t *testing.T) {
	sci := SCIInfo{RepositoryCommitInfo: RepositoryCommitInfo{RepositoryUrl: "repo"}}

	tf := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", terraformPlatform, "aws_s3_bucket", "this", "rule-1", "")
	// Only one of RootModule/ResourceID set: falls back to the legacy formula.
	half := GetDatadogFingerprintHash(
		sci, "modules/bucket/main.tf", terraformPlatform, "aws_s3_bucket", "this", "rule-1", "",
		TerraformIdentity{RootModule: "stack"},
	)
	require.Equal(t, tf, half, "a half-resolved identity must not be used; fall back to the legacy formula")

	chain := GetDatadogFingerprintHash(
		sci, "modules/bucket/main.tf", terraformPlatform, "aws_s3_bucket", "this", "rule-1", "",
		TerraformIdentity{CallChain: "stack/main.tf|module.bucket"},
	)
	require.Equal(t, stringToHash("repo|modules/bucket/main.tf|aws_s3_bucket|this|rule-1|stack/main.tf|module.bucket"), chain)
	require.NotEqual(t, tf, chain)

	resolved := GetDatadogFingerprintHash(
		sci, "modules/bucket/main.tf", terraformPlatform, "aws_s3_bucket", "this", "rule-1", "",
		TerraformIdentity{RootModule: "stack", ResourceID: "aws_s3_bucket.this", CallChain: "stack/main.tf|module.bucket"},
	)
	require.Equal(t, stringToHash("repo|stack|aws_s3_bucket.this|rule-1"), resolved)

	// A non-Terraform platform hashes the same way (minus Terraform-specific fields).
	other := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", "Kubernetes", "aws_s3_bucket", "this", "rule-1", "")
	require.Equal(t, tf, other)
}

func TestOmitTerraformInstanceIdentity_KeepsCallChainFingerprint(t *testing.T) {
	sci := SCIInfo{RepositoryCommitInfo: RepositoryCommitInfo{RepositoryUrl: "repo"}}
	v := Vulnerability{
		FileName: "modules/bucket/main.tf", Platform: terraformPlatform, QueryID: "rule-1",
		ResourceType: "aws_s3_bucket", ResourceName: "this", Severity: SeverityHigh,
		RootModule: "stack", ResourceID: "module.bucket.aws_s3_bucket.this",
		ModuleCallChain: "stack/main.tf|module.bucket", Line: 1, SearchKey: "k",
	}
	vulns := []Vulnerability{v}
	OmitTerraformInstanceIdentity(vulns)
	require.Empty(t, vulns[0].ResourceID)
	require.Empty(t, vulns[0].RootModule)
	require.Equal(t, "stack/main.tf|module.bucket", vulns[0].ModuleCallChain)

	summary := CreateSummary(context.Background(), Counters{}, vulns, "scan", nil, "", sci)
	require.Empty(t, summary.Queries[0].Files[0].ResourceID)
	file := filepath.FromSlash("modules/bucket/main.tf")
	require.Equal(t, stringToHash("repo|"+file+"|aws_s3_bucket|this|rule-1|stack/main.tf|module.bucket"), summary.Queries[0].Files[0].Fingerprint)
}

// The fingerprint of a resolved identity is exactly root + address + rule.
func TestGetDatadogFingerprintHash_ResolvedInput(t *testing.T) {
	sci := SCIInfo{RepositoryCommitInfo: RepositoryCommitInfo{RepositoryUrl: "repo"}}
	got := GetDatadogFingerprintHash(
		sci, "stack/main.tf", terraformPlatform, "aws_s3_bucket", "this", "rule-1", "3",
		TerraformIdentity{RootModule: "stack", ResourceID: `module.a["x"].aws_s3_bucket.this[0]`},
	)
	want := stringToHash("repo|stack|module.a[\"x\"].aws_s3_bucket.this[0]|rule-1")
	require.Equal(t, want, got, "a resolved identity hashes repo|root|address|rule")
}

func TestFindingIdentity_ResolvedTerraformIdentityUncollapsesInstances(t *testing.T) {
	base := Vulnerability{
		FileName: "/repo/stack/main.tf", Platform: terraformPlatform, QueryID: "rule-1",
		ResourceType: "aws_s3_bucket", ResourceName: "this", RootModule: "stack",
		Severity: SeverityHigh, SearchKey: "aws_s3_bucket[this]",
	}
	first, second := base, base
	first.ResourceID, first.Line = "aws_s3_bucket.this[0]", 2
	second.ResourceID, second.Line = "aws_s3_bucket.this[1]", 9

	require.NotEqual(t, FindingIdentity(&first), FindingIdentity(&second),
		"distinct resolved addresses must not share a finding identity")

	summary := CreateSummary(context.Background(), Counters{}, []Vulnerability{first, second}, "scan", nil, "/repo", sciInfoForTest)
	require.Len(t, summary.Queries, 1)
	files := summary.Queries[0].Files
	require.Len(t, files, 2)
	require.NotEqual(t, files[0].Fingerprint, files[1].Fingerprint,
		"distinct FindingIdentity must mean distinct CreateSummary fingerprints")
}

var sciInfoForTest = SCIInfo{RepositoryCommitInfo: RepositoryCommitInfo{RepositoryUrl: "repo"}}

// FindingIdentity (storage's grouping) and CreateSummary (the report's
// persisted fingerprint) must group findings on exactly the same fields (see
// fingerprintFields), or a finding storage reduced to one copy could still be
// fingerprinted as two distinct findings in the report, or the reverse.
func TestFindingIdentity_EqualIdentityMeansEqualCreateSummaryFingerprint(t *testing.T) {
	a := Vulnerability{
		FileName: "/repo/stack/main.tf", Platform: terraformPlatform, QueryID: "rule-1",
		ResourceType: "aws_security_group", ResourceName: "sg",
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

// The identity input is the finding's identity less its line, whatever the
// platform; a Dockerfile identity includes the line, so it is not knowable
// before detection.
func TestIdentityInput_IsFindingIdentityLessLine(t *testing.T) {
	for _, platform := range []string{"Terraform", "CloudFormation", "Kubernetes", ""} {
		v := &Vulnerability{
			FileName: "modules/app/main.tf", Platform: platform, ResourceType: "aws_s3_bucket",
			ResourceName: "logs", QueryID: "q", LegacyQueryID: "legacy",
			LineWithVulnerability: "line text",
		}
		id, ok := IdentityInput(v.FileName, platform, v.ResourceType, v.ResourceName, utils.ChooseQueryID("q", "legacy"))
		require.True(t, ok, platform)
		want := fingerprintInput(SCIInfo{}, v.FileName, platform, v.ResourceType, v.ResourceName, "legacy", "line text")
		require.Equal(t, want, FindingIdentity(v), platform)
		require.Equal(t, want, id, platform)
	}

	_, ok := IdentityInput("modules/app/main.tf", "Dockerfile", "", "", "q")
	require.False(t, ok, "a Dockerfile identity includes the line")

	// A resolved Terraform identity replaces file, type and name.
	v := &Vulnerability{
		FileName: "modules/app/main.tf", Platform: terraformPlatform, ResourceType: "aws_s3_bucket",
		ResourceName: "logs", QueryID: "q", ResourceID: "aws_s3_bucket.logs[0]", RootModule: "stack",
	}
	id, ok := IdentityInput(v.FileName, terraformPlatform, v.ResourceType, v.ResourceName, "q",
		TerraformIdentity{RootModule: "stack", ResourceID: "aws_s3_bucket.logs[0]"})
	require.True(t, ok)
	require.Equal(t, FindingIdentity(v), id)
}
