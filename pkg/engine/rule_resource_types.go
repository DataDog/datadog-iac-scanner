/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"regexp"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/cespare/xxhash/v2"
)

// A rule names the resource and data types it can match, either by reading
// them off a document (`input.document[i].resource.aws_s3_bucket[name]`,
// `input.document[i].data.aws_ami[name]`) or by passing
// them to a library helper (`has_target_resource(bucket,
// "aws_s3_bucket_lifecycle_configuration")`). Both forms are picked up here.
var (
	resourceFieldPattern = regexp.MustCompile(`resource\.([a-z][a-z0-9_]*)`)
	resourceIndexPattern = regexp.MustCompile(`resource\[\s*"([^"\s]+)"\s*\]`)
	// Rego imports and data documents (`data.generic.terraform`) share the
	// data. prefix; Terraform type names always hold an underscore.
	dataFieldPattern = regexp.MustCompile(`\bdata\.([a-z][a-z0-9]*_[a-z0-9_]*)`)
	dataIndexPattern = regexp.MustCompile(`\bdata\[\s*"([a-z][a-z0-9]*_[a-z0-9_]*)"\s*\]`)
	// Ephemeral resources are read through their namespace
	// (`input.document[i].ephemeral.random_password[name]`) and named with it
	// in literals (`"ephemeral.random_password"`). The namespace makes both
	// patterns specific enough to skip the underscore requirement; the quoted
	// form records the namespaced type whole, the way findings name it.
	ephemeralFieldPattern  = regexp.MustCompile(`\bephemeral\.([a-z][a-z0-9_]*)`)
	ephemeralQuotedPattern = regexp.MustCompile(`"(ephemeral\.[a-z][a-z0-9_]*)"`)
	typeLiteralPattern     = regexp.MustCompile(`"([a-z][a-z0-9]*(?:_[a-z0-9]+)+)"`)
	// Rules that apply to a whole provider select it by prefix, as in
	// `startswith(resource_type, "aws_")`.
	typePrefixPattern = regexp.MustCompile(`startswith\([^,]+,\s*"([a-z][a-z0-9]*_)"\s*\)`)
)

// ruleTargets decides whether a resource type can be matched by name by any of
// the loaded rules.
type ruleTargets struct {
	types    map[string]bool
	prefixes []string
}

// matches reports whether some rule names this resource type, directly or
// through the provider prefix it belongs to.
func (t *ruleTargets) matches(resourceType string) bool {
	if t == nil {
		return true
	}
	if t.types[resourceType] {
		return true
	}
	for _, prefix := range t.prefixes {
		if strings.HasPrefix(resourceType, prefix) {
			return true
		}
	}
	return false
}

// ruleTargetedResourceTypes collects every Terraform resource type the given
// rules can match by name, either individually or by provider prefix.
//
// Resolving a module's variables only changes a finding if some rule reads the
// resource whose values were resolved, so this is what decides which resources
// are worth instantiating. Skipping a resource never removes it from the scan:
// it keeps being read where it is written, with the same unresolved values it
// has today. The cost of missing a type is therefore a finding this feature
// could have improved, not one the scanner used to report — but the collection
// still errs towards including too much, since a wrongly included type only
// costs a little work. Most of what it over-collects (helper names, attribute
// names) never matches a resource type anyway.
//
// Returns nil when nothing could be collected, which turns the filter off
// rather than silently narrowing a scan.
func ruleTargetedResourceTypes(queries []model.QueryMetadata, libraries ...string) *ruleTargets {
	targets := ruleTargets{types: make(map[string]bool)}
	prefixes := make(map[string]bool)
	collect := func(source string) {
		for _, pattern := range []*regexp.Regexp{
			resourceFieldPattern, resourceIndexPattern, dataFieldPattern, dataIndexPattern,
			ephemeralFieldPattern, ephemeralQuotedPattern, typeLiteralPattern,
		} {
			for _, m := range pattern.FindAllStringSubmatch(source, -1) {
				targets.types[m[1]] = true
			}
		}
		for _, m := range typePrefixPattern.FindAllStringSubmatch(source, -1) {
			prefixes[m[1]] = true
		}
	}
	for i := range queries {
		collect(queries[i].Content)
		collect(queries[i].InputData)
	}
	for _, library := range libraries {
		collect(library)
	}
	if len(targets.types) == 0 {
		return nil
	}
	for prefix := range prefixes {
		targets.prefixes = append(targets.prefixes, prefix)
	}
	sort.Strings(targets.prefixes)
	return &targets
}

// terraformCrossDocumentQueries classifies the loaded Terraform rules against
// the same libraries their resource types are collected from. The result is
// cached on the inspector for the ruleset that produced it: classifying every
// rule recompiles them.
func (c *Inspector) terraformCrossDocumentQueries(queries []model.QueryMetadata) map[string]bool {
	terraform := make([]model.QueryMetadata, 0, len(queries))
	for i := range queries {
		if queries[i].Platform == platformTerraform {
			terraform = append(terraform, queries[i])
		}
	}
	if len(terraform) == 0 {
		return nil
	}
	libraries := c.terraformRuleLibraries()
	key := classificationKey(terraform, libraries)
	c.crossDocMu.Lock()
	defer c.crossDocMu.Unlock()
	if c.crossDocReady && c.crossDocKey == key {
		return c.crossDoc
	}
	c.crossDoc = crossDocumentQueries(terraform, libraries...)
	c.crossDocKey = key
	c.crossDocReady = true
	return c.crossDoc
}

func classificationKey(queries []model.QueryMetadata, libraries []string) uint64 {
	h := xxhash.New()
	for i := range queries {
		_, _ = h.WriteString(queries[i].Query)
		_, _ = h.WriteString("\x00")
		_, _ = h.WriteString(queries[i].Content)
		_, _ = h.WriteString("\x00")
	}
	for _, library := range libraries {
		_, _ = h.WriteString(library)
		_, _ = h.WriteString("\x00")
	}
	return h.Sum64()
}

// terraformByRoot reports whether this scan builds one Terraform input per root.
func terraformByRoot(rootCount int, cross map[string]bool) bool {
	if rootCount < 2 {
		return false
	}
	for _, isCross := range cross {
		if isCross {
			return true
		}
	}
	return false
}

func countRoots(docRoots map[string][]string) int {
	roots := map[string]bool{}
	for _, rs := range docRoots {
		for _, r := range rs {
			roots[r] = true
		}
	}
	return len(roots)
}

// terraformRuleLibraries returns the Rego libraries that Terraform rules are
// compiled against, so type names spelled only in shared helpers are seen too.
func (c *Inspector) terraformRuleLibraries() []string {
	libraries := []string{c.QueryLoader.commonLibrary.LibraryCode}
	if platform, ok := c.QueryLoader.platformLibraries[platformTerraform]; ok {
		libraries = append(libraries, platform.LibraryCode)
	}
	return libraries
}
