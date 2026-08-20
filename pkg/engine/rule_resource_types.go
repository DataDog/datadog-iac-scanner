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
)

// A rule names the resource types it can match, either by reading them off a
// document (`input.document[i].resource.aws_s3_bucket[name]`) or by passing
// them to a library helper (`module_equivalent_key("aws", source,
// "aws_s3_bucket", key)`). Both forms are picked up here.
var (
	resourceFieldPattern = regexp.MustCompile(`resource\.([a-z][a-z0-9_]*)`)
	resourceIndexPattern = regexp.MustCompile(`resource\[\s*"([^"\s]+)"\s*\]`)
	typeLiteralPattern   = regexp.MustCompile(`"([a-z][a-z0-9]*(?:_[a-z0-9]+)+)"`)
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
			resourceFieldPattern, resourceIndexPattern, typeLiteralPattern,
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

// terraformRuleLibraries returns the Rego libraries that Terraform rules are
// compiled against, so type names spelled only in shared helpers are seen too.
func (c *Inspector) terraformRuleLibraries() []string {
	libraries := []string{c.QueryLoader.commonLibrary.LibraryCode}
	if platform, ok := c.QueryLoader.platformLibraries["terraform"]; ok {
		libraries = append(libraries, platform.LibraryCode)
	}
	return libraries
}
