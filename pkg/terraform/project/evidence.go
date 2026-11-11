/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
)

// EvidenceRoot reports whether r may supply cross-root companion evidence: a
// source root that is not an example, a test or a vendored module, and that
// no other root calls as a module. called maps cleaned module directories;
// nil skips the called-module check (the planner may apply it after a full pass).
func EvidenceRoot(r *model.Root, called map[string]bool) bool {
	if r.Plan {
		return false
	}
	for _, seg := range strings.Split(filepath.ToSlash(r.ID), "/") {
		switch seg {
		case "examples", "test", "tests", "testdata", "fixtures", ".terraform":
			return false
		}
	}
	if called[filepath.Clean(r.Dir)] {
		return false
	}
	tests, _ := filepath.Glob(filepath.Join(r.Dir, "*.tftest.hcl"))
	return len(tests) == 0
}

// HoldsCompanion reports whether r declares a resource type that can write a
// literal companion keyed in keys.
func HoldsCompanion(r *model.Root, keys LiteralKeys) bool {
	for _, m := range r.Modules {
		for _, b := range m.Blocks {
			if _, ok := keys[b.Type]; ok && b.Kind == address.KindResource {
				return true
			}
		}
	}
	return false
}
