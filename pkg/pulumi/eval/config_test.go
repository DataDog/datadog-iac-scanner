/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/capture"
	"github.com/stretchr/testify/assert"
)

func TestCandidatesFor(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"__main__.py": `cfg = pulumi.Config()
subnets = cfg.require_object("subnets")
cidrs = cfg.require_object('subnet_cidrs')
retries = cfg.get_int("retries")
ratio = cfg.require_float("ratio")
`,
		"main.go": `count := config.RequireInt(ctx, "count")
debug := cfg.GetBool("debug")
`,
		"venv/lib/site.py": `cfg.require_int("dataDir")`,
	})
	src := newSourceIndex(dir)
	first := func(key string) string { return candidatesFor(key, src)[0] }

	assert.Equal(t, "[]", first("app:subnets"))
	assert.Equal(t, `["10.0.0.0/24","10.0.1.0/24","10.0.2.0/24"]`, first("app:subnet_cidrs"))
	assert.Equal(t, "1", first("app:retries"))
	assert.Equal(t, "1.5", first("app:ratio"))
	assert.Equal(t, "1", first("app:count"))
	assert.Equal(t, "false", first("app:debug"))
	assert.Equal(t, ".", first("app:dataDir"), "virtual environments are not the program")
	assert.Equal(t, "10.0.0.0/16", first("app:vpcCidr"))
	assert.Equal(t, "us-east-1", first("app:region"))
	assert.Equal(t, "dd-placeholder.example.com", first("app:domainName"))
	assert.Equal(t, "ddph", first("app:name"))

	all := candidatesFor("app:retries", src)
	assert.Equal(t, []string{"1", "dd-placeholder", "true", "[]", "{}"}, all, "no duplicate candidates")
}

func TestStackConfig(t *testing.T) {
	p := &Project{Name: "app", Config: map[string]any{
		"plain":         "x",
		"withDefault":   map[string]any{"type": "string", "default": "d"},
		"emptyValue":    map[string]any{"value": "", "default": "fallback"},
		"declaredInt":   map[string]any{"type": "integer"},
		"declaredBool":  map[string]any{"type": "boolean"},
		"undeclared":    map[string]any{"description": "no value"},
		"secretDecl":    map[string]any{"secret": true, "default": "s"},
		"aws:region":    "eu-west-3",
		"other:setting": map[string]any{"value": []any{"a", "b"}},
	}}
	st := &Stack{Name: "prod", Config: map[string]any{
		"undeclared": "now set",
		"password":   map[string]any{"secure": "v1:abc"},
		"db":         map[string]any{"host": "h", "password": map[string]any{"secure": "v1:def"}},
		"tokens":     []any{"plain", map[string]any{"secure": "v1:ghi"}},
		"cookie":     map[string]any{"opts": map[string]any{"secure": true, "sameSite": "lax"}},
		"flags":      map[string]any{"secure": "yes", "other": "x"},
		"count":      3,
		"enabled":    true,
	}}
	c := newStackConfig(p, st, nil)

	assert.Equal(t, "x", c.values["app:plain"])
	assert.Equal(t, "d", c.values["app:withDefault"])
	assert.Equal(t, "fallback", c.values["app:emptyValue"], "an empty declared value is missing")
	assert.Equal(t, "1", c.values["app:declaredInt"])
	assert.Equal(t, "false", c.values["app:declaredBool"])
	assert.Equal(t, "now set", c.values["app:undeclared"], "the stack overrides the project")
	assert.Equal(t, secretPlaceholder, c.values["app:password"])
	assert.Equal(t, `{"host":"h","password":"`+secretPlaceholder+`"}`, c.values["app:db"], "nested secure values are redacted")
	assert.Equal(t, `["plain","`+secretPlaceholder+`"]`, c.values["app:tokens"])
	assert.Equal(t, `{"opts":{"sameSite":"lax","secure":true}}`, c.values["app:cookie"], "a secure setting that is not a string")
	assert.Equal(t, `{"other":"x","secure":"yes"}`, c.values["app:flags"], "an object with keys other than secure")
	assert.Equal(t, "3", c.values["app:count"])
	assert.Equal(t, "true", c.values["app:enabled"])
	assert.Equal(t, "eu-west-3", c.values["aws:region"])
	assert.Equal(t, `["a","b"]`, c.values["other:setting"])

	assert.Equal(t, []string{"app:declaredBool", "app:declaredInt"}, sortedKeys(c.placeholders))
	assert.Equal(t, []string{"app:db", "app:password", "app:secretDecl", "app:tokens"}, sortedKeys(c.secrets))
	assert.NotContains(t, sortedKeys(c.providerDefaults), "aws:region")
	assert.Contains(t, sortedKeys(c.providerDefaults), "azure:location")
	assert.NotContains(t, c.publicValues(), "app:password")
	assert.NotContains(t, c.publicValues(), "app:db")
	assert.Contains(t, c.publicValues(), "app:cookie")
	assert.Equal(t, `["app:db","app:password","app:secretDecl","app:tokens"]`, c.secretKeysJSON())

	c.addPlaceholder("app:extra", nil)
	assert.Equal(t, "ddph", c.values["app:extra"])
	assert.True(t, c.nextCandidate("app:extra", nil))
	assert.Equal(t, "dd-placeholder", c.values["app:extra"])
	for c.nextCandidate("app:extra", nil) {
	}
	assert.Equal(t, "{}", c.values["app:extra"], "the last candidate stays")
}

func TestClassifyProgram(t *testing.T) {
	cases := []struct {
		output     string
		invokes    bool
		unimpl     []string
		wantReason capture.Reason
		wantDetail string
	}{
		{"error: Missing required configuration variable 'app:name'", false, nil, capture.ReasonConfigMissing, ""},
		{"ModuleNotFoundError: No module named 'pulumi_aws'", false, nil, capture.ReasonDepsMissing, ""},
		{"TypeError: Descriptors cannot be created directly.", false, nil, capture.ReasonDepsMissing, capture.DetailDepsIncompatible},
		{"socket.gaierror: [Errno -3] Temporary failure in name resolution", false, nil, capture.ReasonNetworkAccess, ""},
		{"KeyError: 'GCP_PROJECT_ID'", false, nil, capture.ReasonEnvMissing, ""},
		{"AttributeError: module 'pulumi_aws.ec2' has no attribute 'get_ami_ids'", false, nil,
			capture.ReasonProgramError, capture.DetailSDKAPIMismatch},
		{"error: unable to find main python program `__main__.py` in `/x`", false, nil, capture.ReasonFileMissing, capture.DetailEntrypoint},
		{"FileNotFoundError: [Errno 2] No such file or directory: 'config/dev.yaml'", false, nil, capture.ReasonFileMissing, ""},
		{"TypeError: Missing required property 'assume_role_policy'", false, nil, capture.ReasonProgramError, capture.DetailRequiredInput},
		{"grpc: Unimplemented", false, []string{"/pulumirpc.ResourceMonitor/Call"},
			capture.ReasonEngineUnsupportedRPC, "/pulumirpc.ResourceMonitor/Call"},
		{"IndexError: list index out of range", true, nil, capture.ReasonProgramError, capture.DetailAfterInvoke},
		{"IndexError: list index out of range", false, nil, capture.ReasonProgramError, ""},
	}
	for _, c := range cases {
		reason, detail := classifyProgram(c.output, c.invokes, c.unimpl)
		assert.Equal(t, c.wantReason, reason, c.output)
		assert.Equal(t, c.wantDetail, detail, c.output)
	}
	assert.Equal(t, capture.ReasonDepsMissing, classifyBuild("go: module lookup disabled by GOPROXY=off"))
	assert.Equal(t, capture.ReasonBuildFailed, classifyBuild("./main.go:3:2: undefined: foo"))
}

func TestExcerpt(t *testing.T) {
	out := "Traceback (most recent call last):\n  File \"__main__.py\", line 3\n    zones[0]\nIndexError: list index out of range\n\n"
	assert.Equal(t, "IndexError: list index out of range", excerpt(out))
	assert.Equal(t, "last line", excerpt("first\nlast line\n"))
	assert.Len(t, excerpt(string(make([]byte, 1000))), maxMessage)
}
