/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package gitlab

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/yamlnode"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func parseRootNode(t *testing.T, content string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(content), &doc))
	if len(doc.Content) == 0 {
		return nil
	}
	return doc.Content[0]
}

func TestGitLabGlobRubyReference(t *testing.T) {
	// Expected matches come from File.fnmatch with PATHNAME, DOTMATCH and EXTGLOB.
	paths := []string{"", "a", "b", "c", "ab", "a/a", "a/b", "a/x/b", "x", "x/a", "x/y/a", "xa", "x/xa", "a*", "*", "a,b", "[", "]", "t]", ":]", "d]", "1", "-", ".", ".hidden", "ci/", "ci/build.rb", "ci/nested/", "ci/nested/build.rb", "ci/nested/build.py", "ci/nested/deep/", "ci/nested/deep/build.rb", "ci/other/build.py", "ci/.hidden/x.rb", "ci/nested/xx.rb", "ci/nested/xy.py", "ci/x", "ci/xyz", "ci/.rb", "{a", "a}", "\u00e9", "ci/\u00e9.rb"}
	for _, tc := range []struct {
		pattern string
		matches []string
	}{
		{"*", []string{"", "a", "b", "c", "ab", "x", "xa", "a*", "*", "a,b", "[", "]", "t]", ":]", "d]", "1", "-", ".", ".hidden", "{a", "a}", "\u00e9"}},
		{"**", []string{"", "a", "b", "c", "ab", "x", "xa", "a*", "*", "a,b", "[", "]", "t]", ":]", "d]", "1", "-", ".", ".hidden", "{a", "a}", "\u00e9"}},
		{"**/*", []string{"", "a", "b", "c", "ab", "a/a", "a/b", "a/x/b", "x", "x/a", "x/y/a", "xa", "x/xa", "a*", "*", "a,b", "[", "]", "t]", ":]", "d]", "1", "-", ".", ".hidden", "ci/", "ci/build.rb", "ci/nested/", "ci/nested/build.rb", "ci/nested/build.py", "ci/nested/deep/", "ci/nested/deep/build.rb", "ci/other/build.py", "ci/.hidden/x.rb", "ci/nested/xx.rb", "ci/nested/xy.py", "ci/x", "ci/xyz", "ci/.rb", "{a", "a}", "\u00e9", "ci/\u00e9.rb"}},
		{"**/a", []string{"a", "a/a", "x/a", "x/y/a"}},
		{"ci/**", []string{"ci/", "ci/build.rb", "ci/x", "ci/xyz", "ci/.rb", "ci/\u00e9.rb"}},
		{"ci/**/", []string{"ci/", "ci/nested/", "ci/nested/deep/"}},
		{"ci/**/*.rb", []string{"ci/build.rb", "ci/nested/build.rb", "ci/nested/deep/build.rb", "ci/.hidden/x.rb", "ci/nested/xx.rb", "ci/.rb", "ci/\u00e9.rb"}},
		{"ci/**/*.{rb,py}", []string{"ci/build.rb", "ci/nested/build.rb", "ci/nested/build.py", "ci/nested/deep/build.rb", "ci/other/build.py", "ci/.hidden/x.rb", "ci/nested/xx.rb", "ci/nested/xy.py", "ci/.rb", "ci/\u00e9.rb"}},
		{"ci/{build.rb,nested/*.py}", []string{"ci/build.rb", "ci/nested/build.py", "ci/nested/xy.py"}},
		{"ci/{nested/deep,other}/*.{rb,py}", []string{"ci/nested/deep/build.rb", "ci/other/build.py"}},
		{"{a}", []string{"a"}},
		{"{a,b}", []string{"a", "b"}},
		{"{{a,b},c}", []string{"a", "b", "c"}},
		{"{,a}b", []string{"b", "ab"}},
		{"*{**,x}/a", []string{"a/a", "x/a"}},
		{"{**,x}/a", []string{"a", "a/a", "x/a", "x/y/a"}},
		{"**{/,x}a", []string{"a", "a/a", "x/a", "x/y/a", "xa"}},
		{"{**,**}/a", []string{"a", "a/a", "x/a", "x/y/a"}},
		{"a**/b", []string{"a/b"}},
		{"***/a", []string{"a/a", "x/a"}},
		{"a?", []string{"ab", "a*", "a}"}},
		{"a[bc]", []string{"ab"}},
		{"[!a]", []string{"b", "c", "x", "*", "[", "]", "1", "-", ".", "\u00e9"}},
		{"[^a]", []string{"b", "c", "x", "*", "[", "]", "1", "-", ".", "\u00e9"}},
		{"[z-a]", []string{"a"}},
		{"[[:digit:]]", []string{"t]", ":]", "d]"}},
		{"[[]", []string{"["}},
		{"[]a]", []string{}},
		{"[!]", []string{"a", "b", "c", "x", "*", "[", "]", "1", "-", ".", "\u00e9"}},
		{"[\\]]", []string{"]"}},
		{"[abc", []string{}},
		{"{a", []string{}},
		{"a}", []string{"a}"}},
		{"a\\*", []string{"a*"}},
		{"{a\\,b,c}", []string{"c", "a,b"}},
		{"\\*", []string{"*"}},
		{"ci/**/**/build.rb", []string{"ci/build.rb", "ci/nested/build.rb", "ci/nested/deep/build.rb"}},
		{"ci/.*/?.rb", []string{"ci/.hidden/x.rb"}},
		{"ci/[^x]*", []string{"ci/build.rb", "ci/.rb", "ci/\u00e9.rb"}},
		{"ci/{,nested/}build.rb", []string{"ci/build.rb", "ci/nested/build.rb"}},
		{"{**,x}/{a,b}", []string{"a", "b", "a/a", "a/b", "a/x/b", "x/a", "x/y/a"}},
		{"{*,}**/a", []string{"a", "a/a", "x/a", "x/y/a"}},
		{"{[,a}", []string{"a"}},
		{"{a,[}", []string{"a"}},
		{"{[a,b],c}", []string{"c"}},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			ctx, cancel := WithLimits(t.Context())
			defer cancel()
			program := compileGitLabGlob(ctx, tc.pattern)
			wanted := make(map[string]bool)
			for _, path := range tc.matches {
				wanted[path] = true
			}
			machine := program.machine()
			for _, path := range paths {
				matched := false
				if machine != nil {
					matched = machine.accepts(machine.advance(machine.start(), path))
				}
				require.Equal(t, wanted[path], matched, "pattern=%q path=%q", tc.pattern, path)
			}
			require.NoError(t, context.Cause(ctx))
		})
	}
	pattern := "ci/" + strings.Repeat("{a,b}", 100) + "/**/{build,test}.{rb,py}"
	ctx, cancel := WithLimits(t.Context())
	defer cancel()
	program := compileGitLabGlob(ctx, pattern)
	require.Less(t, len(program.code), len(pattern)*3, "brace alternatives retain a linear representation")
	machine := program.machine()
	require.NotNil(t, machine)
	require.True(t, machine.accepts(machine.advance(machine.start(), "ci/"+strings.Repeat("a", 100)+"/nested/build.rb")))
	require.NoError(t, context.Cause(ctx))
}

func TestPathHelpers(t *testing.T) {
	for _, p := range []string{
		".gitlab-ci.yml",
		".gitlab-ci.yaml",
		"sub/.gitlab-ci.yml",
		"ci/deploy.gitlab-ci.yml",
		"ci/Deploy.GitLab-CI.YAML",
	} {
		require.True(t, IsConfigFileName(p), p)
	}
	for _, p := range []string{
		"gitlab-ci.yml",
		".gitlab/ci/build.yml",
		".github/workflows/ci.yml",
	} {
		require.False(t, IsConfigFileName(p), p)
	}

	for _, p := range []string{
		".gitlab/ci/build.yml",
		"repo/.gitlab/ci/sub/deploy.yaml",
		".GITLAB/CI/Test.YML",
	} {
		require.True(t, IsCIDirPath(p), p)
	}
	for _, p := range []string{
		".gitlab/route-map.yml",
		".gitlab/ci/readme.md",
		"ci/build.yml",
	} {
		require.False(t, IsCIDirPath(p), p)
	}
}

func TestKeywordAndJobClassification(t *testing.T) {
	for _, needs := range []string{"{pipeline: group/project}", "{pipeline: group/project, job: build}"} {
		body := "upstream_status: {needs: " + needs + "}\n"
		root := parseRootNode(t, body)
		var document map[string]interface{}
		require.NoError(t, yaml.Unmarshal([]byte(body), &document))
		require.True(t, isJobNode("upstream_status", root.Content[1]))
		require.True(t, IsExecutableJob("upstream_status", document["upstream_status"]))
		require.True(t, IsDocumentNode(root))
		require.True(t, IsDocument(document))
		for _, file := range []string{".gitlab-ci.yml", ".gitlab/ci/status.yml", "status.yml"} {
			require.True(t, ShouldParse([]byte(body), file), file)
		}
	}
	// True global keywords are reserved; job-level keywords remain valid job names.
	for _, kw := range []string{
		"stages", "variables", "default", "include", "workflow",
		"image", "services", "before_script", "after_script", "cache", "spec", "types",
	} {
		require.True(t, IsReservedTopLevelKeyword(kw), kw)
	}
	for _, validJob := range []string{"release", "artifacts", "hooks", "pages", "build", ".template"} {
		require.False(t, IsReservedTopLevelKeyword(validJob), validJob)
	}

	jobVal := map[string]interface{}{"stage": "release", "script": []interface{}{"./release.sh"}}
	require.True(t, IsExecutableJob("release", jobVal))
	require.True(t, IsExecutableJob("steps", map[string]interface{}{"run": []interface{}{map[string]interface{}{"name": "execute", "script": "echo ok"}}}))
	require.True(t, IsExecutableJob("artifacts", map[string]interface{}{"script": "echo ok"}))
	require.True(t, IsExecutableJob("hooks", map[string]interface{}{"extends": ".base"}))
	require.True(t, IsExecutableJob("stage_only_plus_rules", map[string]interface{}{"stage": "test", "rules": []interface{}{}}))
	require.False(t, IsExecutableJob(".template", jobVal))
	require.True(t, isJobMapping(".template", jobVal))
	require.False(t, isJobMapping("stages", jobVal))
	for _, name := range []string{"_dd_lines", "_path", "_parsed_before_script", "_parsed_after_script", "gitlab_scripts"} {
		require.True(t, isJobMapping(name, jobVal), name)
		require.True(t, IsExecutableJob(name, jobVal), name)
	}
}

func TestDialectDetection(t *testing.T) {
	// GitHub workflows (even mentioning !reference in a string), action manifests,
	// and Dependabot configs are rejected as GitLab CI.
	githubWorkflow := parseRootNode(t, `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "!reference [.a, b]"
`)
	require.True(t, isGitHubCICDNode(githubWorkflow))
	require.False(t, IsDocumentNode(githubWorkflow))

	actionManifest := parseRootNode(t, `name: My Action
runs:
  using: composite
  steps:
    - run: echo hi
`)
	require.True(t, isGitHubCICDNode(actionManifest))
	require.False(t, IsDocumentNode(actionManifest))

	dependabotCfg := parseRootNode(t, `version: 2
updates:
  - package-ecosystem: gomod
    directory: /
`)
	require.True(t, isGitHubCICDNode(dependabotCfg))
	require.False(t, IsDocumentNode(dependabotCfg))

	// A GitLab CI pipeline with jobs named "version" and "updates" is NOT Dependabot.
	gitlabVersionUpdates := parseRootNode(t, `version:
  script:
    - echo v1
updates:
  script:
    - echo updating
`)
	require.False(t, isGitHubCICDNode(gitlabVersionUpdates))
	require.True(t, IsDocumentNode(gitlabVersionUpdates))

	// Kubernetes and CloudFormation manifests are not claimed as GitLab CI.
	k8s := parseRootNode(t, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n")
	require.False(t, IsDocumentNode(k8s))
	cfn := parseRootNode(t, "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n")
	require.False(t, IsDocumentNode(cfn))
	compose := "include: [shared.yml]\nservices: {web: {image: alpine:latest}}\n"
	require.False(t, IsDocumentNode(parseRootNode(t, compose)))
	require.False(t, ShouldParse([]byte(compose), ".gitlab/ci/compose.yml"))
	var composeDocument map[string]interface{}
	require.NoError(t, yaml.Unmarshal([]byte(compose), &composeDocument))
	require.False(t, IsDocument(composeDocument))
	for _, fields := range []string{
		"services: {web: {image: alpine}}",
		"apiVersion: v1, kind: ConfigMap",
		"Resources: {Bucket: {Type: 'AWS::S3::Bucket'}}",
		"on: [push], jobs: {build: {steps: [{run: echo ok}]}}",
		"runs: {using: composite, steps: [{run: echo ok}]}",
		"version: 2, updates: [{directory: '/', 'package-ecosystem': npm}]",
	} {
		for _, merge := range []string{"*base", "[*base]", "[*base, *base]"} {
			content := "x-base: &base {" + fields + "}\n<<: " + merge + "\nx-helper: {script: echo setup}\n"
			require.False(t, IsDocumentNode(parseRootNode(t, content)), content)
			require.False(t, ShouldParse([]byte(content), ".gitlab/ci/other.yml"), content)
		}
	}
	cycle := parseRootNode(t, "x-base: &base {<<: *base, services: {web: {image: alpine}}}\n<<: *base\nx-helper: {script: echo setup}\n")
	require.False(t, IsDocumentNode(cycle))
	override := parseRootNode(t, "x-base: &base {services: {web: {image: alpine}}}\n<<: *base\nservices: [docker:dind]\njob: {script: echo ok}\n")
	require.True(t, IsDocumentNode(override), "explicit keys override merged keys")
	for _, content := range []string{
		"Resources: {script: echo job}\n",
		"Resources: {variables: {Type: value}, script: echo job}\n",
		"apiVersion: {script: echo version}\nkind: {script: echo kind}\n",
		"on: {script: echo on}\njobs: {script: echo jobs}\n",
		"variables: {NAME: &name build}\n*name: {script: echo job}\n",
	} {
		root := parseRootNode(t, content)
		require.True(t, IsDocumentNode(root))
		var document map[string]interface{}
		require.NoError(t, yaml.Unmarshal([]byte(content), &document))
		require.True(t, IsDocument(document))
	}
	require.False(t, IsDocumentNode(parseRootNode(t, "Resources: {script: {Type: 'AWS::S3::Bucket'}}\n")))
	for _, content := range []string{
		"Resources:\n  Shared: &resource {Type: 'AWS::S3::Bucket'}\n  script: *resource\n",
		"Resources:\n  Shared: &resource {Type: 'AWS::S3::Bucket'}\n  script: {<<: *resource}\n",
		"Metadata: &resources {script: {Type: 'AWS::S3::Bucket'}}\nResources: *resources\n",
		"Resources:\n  script: {Type: 'AWS::S3::Bucket'}\n  Fn::ForEach::Buckets: [Name, [One], {'${Name}': {Type: 'AWS::S3::Bucket'}}]\n",
	} {
		require.False(t, IsDocumentNode(parseRootNode(t, content)), "CloudFormation resource reuse remains CloudFormation")
		var document map[string]interface{}
		require.NoError(t, yaml.Unmarshal([]byte(content), &document))
		require.False(t, IsDocument(document))
	}

	// Spec header + pipeline multi-doc and top-level-only GitLab configs are detected.
	spec := parseRootNode(t, "spec:\n  inputs:\n    env:\n      default: prod\n")
	require.True(t, IsSpecHeaderNode(spec))
	pipe := parseRootNode(t, "include:\n  - local: .gitlab/ci/base.yml\n")
	require.True(t, isDocumentNodes([]*yaml.Node{spec, pipe}))

	// Parsed-map helpers agree with YAML-node helpers.
	require.True(t, isGitHubCICDDocument(map[string]interface{}{"version": float64(2), "updates": []interface{}{}}))
	require.False(t, isGitHubCICDDocument(map[string]interface{}{
		"version": map[string]interface{}{"script": "echo v1"},
		"updates": map[string]interface{}{"script": "echo u"},
	}))
	require.True(t, IsDocument(map[string]interface{}{"workflow": map[string]interface{}{"rules": []interface{}{}}}))
	require.True(t, IsDocument(map[string]interface{}{"default": map[string]interface{}{"image": "alpine:3"}}))
	require.True(t, IsDocument(map[string]interface{}{"before_script": []interface{}{"echo hi"}}))
	require.False(t, IsDocument(map[string]interface{}{"spec": map[string]interface{}{"inputs": map[string]interface{}{}}}))
}

func TestInputExpansionLimits(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		src := strings.Repeat("x", maxScalarBytes-60)
		if reverse {
			src += "$[[ inputs.empty ]]$[[ inputs.grow ]]"
		} else {
			src += "$[[ inputs.grow ]]$[[ inputs.empty ]]"
		}
		ctx, cancel := WithLimits(context.Background())
		out, changed := applyStreamingInputExpansion(ctx, src, map[string]*yaml.Node{
			"grow":  {Kind: yaml.ScalarNode, Value: strings.Repeat("g", 50)},
			"empty": {Kind: yaml.ScalarNode, Value: ""},
		})
		require.True(t, changed)
		require.Len(t, out, maxScalarBytes-10)
		require.NoError(t, context.Cause(ctx))
		cancel()
	}
}

func BenchmarkSharedListNormalization(b *testing.B) {
	for _, jobs := range []int{100, 1000} {
		b.Run(fmt.Sprint(jobs), func(b *testing.B) {
			commands := &yaml.Node{Kind: yaml.SequenceNode, Tag: yamlnode.SeqTag}
			for range 9000 {
				commands.Content = append(commands.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: yamlnode.StrTag, Value: "echo ok"})
			}
			root := &yaml.Node{Kind: yaml.MappingNode, Tag: yamlnode.MapTag}
			for index := range jobs {
				key := &yaml.Node{Kind: yaml.ScalarNode, Tag: yamlnode.StrTag, Value: fmt.Sprintf("job%d", index)}
				field := &yaml.Node{Kind: yaml.ScalarNode, Tag: yamlnode.StrTag, Value: "script"}
				job := &yaml.Node{Kind: yaml.MappingNode, Tag: yamlnode.MapTag, Content: []*yaml.Node{field, commands}}
				root.Content = append(root.Content, key, job)
			}
			b.ResetTimer()
			for range b.N {
				state := NewFileState(b.Context(), nil, "", ".gitlab-ci.yml")
				if normalized := state.flattenLists(root); len(normalized.Content) != 2*jobs {
					b.Fatal("normalization lost jobs")
				}
			}
		})
	}
}

func TestInputVariantIdentities(t *testing.T) {
	root := parseRootNode(t, "items: '$[[ inputs.value ]]'\n")
	state := NewFileState(t.Context(), nil, "", ".gitlab-ci.yml")
	state.RegisterSource(root, ".gitlab-ci.yml", "items: '$[[ inputs.value ]]'\n", 0)
	originalKey := root.Content[0]
	for _, value := range []string{"[one]", "[two, three]"} {
		input := parseRootNode(t, value)
		variant := state.interpolateInputs(root, map[string]*yaml.Node{"value": input}, nil)
		require.NotSame(t, originalKey, variant.Content[0], "contextual positions belong to the input variant")
		require.Nil(t, state.keyOverlays[originalKey], "the cached source key stays immutable")
		require.Equal(t, "$[[ inputs.value ]]", root.Content[1].Value)
	}
	shared := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: strings.Repeat("x", 512*1024)}
	digests := make(map[*yaml.Node][sha256.Size]byte)
	identities := make(map[string]bool)
	for _, kind := range []string{"!!str", "!!int", "!!bool"} {
		for _, value := range []string{"1", "true", "plain"} {
			inputs := map[string]*yaml.Node{"shared": shared, "value": {Kind: yaml.ScalarNode, Tag: kind, Value: value}}
			signature := inputsSignature(inputs, digests)
			require.Len(t, signature, sha256.Size*2)
			require.False(t, identities[signature])
			identities[signature] = true
			reordered := map[string]*yaml.Node{"value": inputs["value"], "shared": shared}
			require.Equal(t, signature, inputsSignature(reordered, digests))
		}
	}
	// Shared content is hashed once regardless of the number of distinct variants.
	require.Len(t, digests, 10)
}

func TestInputVariantAllocationsAreReserved(t *testing.T) {
	for _, extra := range []int{-1, math.MaxInt, math.MaxInt / pointerAllocationBytes} {
		ctx, cancel := WithLimits(t.Context())
		state := NewFileState(ctx, nil, "", ".gitlab-ci.yml")
		require.Nil(t, state.cloneJobForDefaults(parseRootNode(t, "script: echo job\n"), extra))
		require.ErrorIs(t, context.Cause(ctx), ErrLimitExceeded, "capacity arithmetic fails before allocation")
		cancel()
	}
	for _, kind := range []yaml.Kind{yaml.MappingNode, yaml.SequenceNode} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			ctx, cancel := WithLimits(context.Background())
			defer cancel()
			node := &yaml.Node{Kind: kind, Tag: yamlnode.MapTag}
			if kind == yaml.SequenceNode {
				node.Tag = yamlnode.SeqTag
			}
			for i := range 4096 {
				if kind == yaml.MappingNode {
					node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: fmt.Sprint(i)})
				}
				value := "unchanged"
				if i == 0 {
					value = "$[[ inputs.value ]]"
				}
				node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: yamlnode.StrTag, Value: value})
			}
			state := NewFileState(ctx, nil, "", ".gitlab-ci.yml")
			// Only one scalar changes: its substitution fits, but copying the wide
			// container does not. Scalar work alone must not exhaust this allowance.
			limits := ctx.Value(limitsKey{}).(*parseLimits)
			limits.bytes = 1024
			result := state.interpolateInputs(node, map[string]*yaml.Node{"value": {Kind: yaml.ScalarNode, Tag: yamlnode.StrTag, Value: "v"}}, nil)
			require.Same(t, node, result, "exhaustion must not publish a partial container")
			require.ErrorIs(t, context.Cause(ctx), ErrLimitExceeded)
		})
	}
}

func TestOverlayCombinationSharesAndAccountsForDAGs(t *testing.T) {
	allocations := func(depth int) float64 {
		base, own := &model.LineOverlay{Line: 1}, &model.LineOverlay{Line: 2}
		for range depth {
			base = &model.LineOverlay{Line: 1, Children: map[string]*model.LineOverlay{"left": base, "right": base}}
			own = &model.LineOverlay{Children: map[string]*model.LineOverlay{"left": own, "right": own}}
		}
		return testing.AllocsPerRun(3, func() {
			ctx, cancel := WithLimits(t.Context())
			defer cancel()
			state := NewFileState(ctx, nil, "", "")
			result := state.combineLineOverlays(base, own)
			require.NoError(t, context.Cause(ctx))
			for range depth {
				require.Same(t, result.Children["left"], result.Children["right"])
				result = result.Children["left"]
			}
			require.Equal(t, 2, result.Line)
		})
	}
	small, large := allocations(10), allocations(14)
	require.Less(t, large/small, 2.0, "overlay work follows distinct pairs, not logical paths")
	ctx, cancel := WithLimits(t.Context())
	defer cancel()
	state := NewFileState(ctx, nil, "", "")
	ctx.Value(limitsKey{}).(*parseLimits).bytes = 1
	state.combineLineOverlays(&model.LineOverlay{Line: 1}, &model.LineOverlay{Line: 2})
	require.ErrorIs(t, context.Cause(ctx), ErrLimitExceeded)
}
