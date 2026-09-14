/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"reflect"
	"testing"
)

// NOTE: ParsedSearchKey and ParseSearchKey are now implemented in search_key_parser.go
// These tests validate that implementation

// TestParseSearchKey_FailingPatterns tests various search key formats including
// previously problematic patterns that are now fully supported.
func TestParseSearchKey_FailingPatterns(t *testing.T) {
	tests := []struct {
		name        string
		searchKey   string
		expected    *ParsedSearchKey
		description string
	}{
		// ====== CRITICAL FAILING PATTERNS FROM PRODUCTION ======
		{
			name:      "mixed notation with module as apparent resource key",
			searchKey: "aws_instance.module.app_servers[0].app",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_instance",
				ResourceName:     "app", // NOT "module"
				ModulePath:       []string{"module", "app_servers", "0"},
				FullResourceAddr: "module.app_servers[0].aws_instance.app",
				NormalizedAddr:   "module.app_servers.aws_instance.app",
				AttributePath:    nil,
				HasAttribute:     false,
				IsResourceLevel:  true,
				IsModuleResource: true,
			},
			description: "Mixed notation with module path in middle",
		},
		{
			name:      "bracket notation with full module path",
			searchKey: "aws_instance[module.app_servers[0].app]",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_instance",
				ResourceName:     "app",
				ModulePath:       []string{"module", "app_servers", "0"},
				FullResourceAddr: "module.app_servers[0].aws_instance.app",
				NormalizedAddr:   "module.app_servers.aws_instance.app",
				AttributePath:    nil,
				HasAttribute:     false,
				IsResourceLevel:  true,
				IsModuleResource: true,
			},
			description: "Bracket notation containing full module path",
		},
		{
			name:      "template syntax with module path",
			searchKey: "aws_instance.{{module.app_servers[0].app}}",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_instance",
				ResourceName:     "app",
				ModulePath:       []string{"module", "app_servers", "0"},
				FullResourceAddr: "module.app_servers[0].aws_instance.app",
				NormalizedAddr:   "module.app_servers.aws_instance.app",
				AttributePath:    nil,
				HasAttribute:     false,
				IsResourceLevel:  true,
				IsModuleResource: true,
			},
			description: "Template syntax containing module path",
		},
		{
			// Regression: template unwrapping used to discard the closing "]" suffix
			// and insert a spurious "." right after "[", producing an unmatched-bracket
			// error for this exact shape (see pkg/detector/default_detect_test.go's
			// "curly_brace_wrapped_name" case for the equivalent terraformPlanPath test).
			name:      "template syntax wrapped in bracket notation",
			searchKey: "aws_s3_bucket_object[{{this[0]}}]",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_s3_bucket_object",
				ResourceName:     "this",
				ModulePath:       nil,
				FullResourceAddr: "aws_s3_bucket_object.this[0]",
				NormalizedAddr:   "aws_s3_bucket_object.this",
				AttributePath:    nil,
				HasAttribute:     false,
				IsResourceLevel:  true,
				IsModuleResource: false,
			},
			description: "Template syntax wrapped in bracket notation must keep the closing bracket suffix",
		},
		{
			// Same shape as above, but the template content itself is a module path.
			name:      "template syntax wrapped in bracket notation with module path",
			searchKey: "aws_s3_bucket_object[{{module.s3_object.this[0]}}]",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_s3_bucket_object",
				ResourceName:     "this",
				ModulePath:       []string{"module", "s3_object"},
				FullResourceAddr: "module.s3_object.aws_s3_bucket_object.this[0]",
				NormalizedAddr:   "module.s3_object.aws_s3_bucket_object.this",
				AttributePath:    nil,
				HasAttribute:     false,
				IsResourceLevel:  true,
				IsModuleResource: true,
			},
			description: "Template syntax wrapped in bracket notation with a module-prefixed name",
		},
		{
			name:      "resource name that looks like module path",
			searchKey: "aws_vpc[module.vpc.main]",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_vpc",
				ResourceName:     "main",
				ModulePath:       []string{"module", "vpc"},
				FullResourceAddr: "module.vpc.aws_vpc.main",
				NormalizedAddr:   "module.vpc.aws_vpc.main",
				AttributePath:    nil,
				HasAttribute:     false,
				IsResourceLevel:  true,
				IsModuleResource: true,
			},
			description: "Bracket notation with simple module path",
		},
		{
			name:      "indexed module with attribute path",
			searchKey: "module.app_servers[0].aws_instance.app.tags",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_instance",
				ResourceName:     "app",
				ModulePath:       []string{"module", "app_servers", "0"},
				FullResourceAddr: "module.app_servers[0].aws_instance.app",
				NormalizedAddr:   "module.app_servers.aws_instance.app",
				AttributePath:    []string{"tags"},
				HasAttribute:     true,
				IsResourceLevel:  false,
				IsModuleResource: true,
			},
			description: "Indexed module resource with attribute - needs proper module path extraction",
		},
		{
			name:      "indexed module resource-level finding",
			searchKey: "module.app_servers[0].aws_instance.app",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_instance",
				ResourceName:     "app",
				ModulePath:       []string{"module", "app_servers", "0"},
				FullResourceAddr: "module.app_servers[0].aws_instance.app",
				NormalizedAddr:   "module.app_servers.aws_instance.app",
				AttributePath:    nil,
				HasAttribute:     false,
				IsResourceLevel:  true,
				IsModuleResource: true,
			},
			description: "Resource-level finding (no attribute) - should NOT treat 'app' as an attribute",
		},

		// ====== ATTRIBUTE VS RESOURCE LEVEL DISTINCTION ======
		{
			name:      "simple resource with attribute",
			searchKey: "aws_instance.web.tags",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_instance",
				ResourceName:     "web",
				ModulePath:       nil,
				FullResourceAddr: "aws_instance.web",
				NormalizedAddr:   "aws_instance.web",
				AttributePath:    []string{"tags"},
				HasAttribute:     true,
				IsResourceLevel:  false,
				IsModuleResource: false,
			},
			description: "Attribute-level finding - should map to tags attribute",
		},
		{
			name:      "simple resource without attribute",
			searchKey: "aws_instance.web",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_instance",
				ResourceName:     "web",
				ModulePath:       nil,
				FullResourceAddr: "aws_instance.web",
				NormalizedAddr:   "aws_instance.web",
				AttributePath:    nil,
				HasAttribute:     false,
				IsResourceLevel:  true,
				IsModuleResource: false,
			},
			description: "Resource-level finding - should map to resource block, not attribute",
		},
		{
			name:      "nested attribute path",
			searchKey: "aws_instance.web.root_block_device.volume_size",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_instance",
				ResourceName:     "web",
				ModulePath:       nil,
				FullResourceAddr: "aws_instance.web",
				NormalizedAddr:   "aws_instance.web",
				AttributePath:    []string{"root_block_device", "volume_size"},
				HasAttribute:     true,
				IsResourceLevel:  false,
				IsModuleResource: false,
			},
			description: "Multi-level attribute path",
		},

		// ====== PREFIX AND SYNTAX VARIATIONS ======
		{
			name:      "resource prefix with simple resource",
			searchKey: "resource.aws_instance.web.ami",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_instance",
				ResourceName:     "web",
				ModulePath:       nil,
				FullResourceAddr: "aws_instance.web",
				NormalizedAddr:   "aws_instance.web",
				AttributePath:    []string{"ami"},
				HasAttribute:     true,
				IsResourceLevel:  false,
				IsModuleResource: false,
			},
			description: "Should strip 'resource.' prefix",
		},
		{
			name:      "resource prefix with module resource",
			searchKey: "resource.module.vpc.aws_vpc.main.cidr_block",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_vpc",
				ResourceName:     "main",
				ModulePath:       []string{"module", "vpc"},
				FullResourceAddr: "module.vpc.aws_vpc.main",
				NormalizedAddr:   "module.vpc.aws_vpc.main",
				AttributePath:    []string{"cidr_block"},
				HasAttribute:     true,
				IsResourceLevel:  false,
				IsModuleResource: true,
			},
			description: "Should strip 'resource.' and parse module path",
		},

		// ====== NESTED MODULES ======
		{
			name:      "double nested module",
			searchKey: "module.network.module.subnet.aws_subnet.private.cidr_block",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_subnet",
				ResourceName:     "private",
				ModulePath:       []string{"module", "network", "module", "subnet"},
				FullResourceAddr: "module.network.module.subnet.aws_subnet.private",
				NormalizedAddr:   "module.network.module.subnet.aws_subnet.private",
				AttributePath:    []string{"cidr_block"},
				HasAttribute:     true,
				IsResourceLevel:  false,
				IsModuleResource: true,
			},
			description: "Nested module (module within module) with attribute",
		},
		{
			name:      "triple nested module resource-level",
			searchKey: "aws_subnet[module.network.module.subnet.private]",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_subnet",
				ResourceName:     "private",
				ModulePath:       []string{"module", "network", "module", "subnet"},
				FullResourceAddr: "module.network.module.subnet.aws_subnet.private",
				NormalizedAddr:   "module.network.module.subnet.aws_subnet.private",
				AttributePath:    nil,
				HasAttribute:     false,
				IsResourceLevel:  true,
				IsModuleResource: true,
			},
			description: "Nested module in bracket notation - resource-level finding",
		},

		// ====== EDGE CASES ======
		{
			name:      "module resource with index in brackets",
			searchKey: "aws_instance[module.app[0].web]",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_instance",
				ResourceName:     "web",
				ModulePath:       []string{"module", "app", "0"},
				FullResourceAddr: "module.app[0].aws_instance.web",
				NormalizedAddr:   "module.app.aws_instance.web",
				AttributePath:    nil,
				HasAttribute:     false,
				IsResourceLevel:  true,
				IsModuleResource: true,
			},
			description: "Module index inside bracket notation",
		},
		{
			// FullResourceAddr keeps the raw quoted key, matching parseModulePath's
			// convention of retaining a for_each/count selector as-is.
			name:      "bracket notation with string key",
			searchKey: `aws_instance["example"].tags`,
			expected: &ParsedSearchKey{
				ResourceType:     "aws_instance",
				ResourceName:     "example",
				FullResourceAddr: `aws_instance."example"`,
				NormalizedAddr:   "aws_instance.example",
				AttributePath:    []string{"tags"},
				HasAttribute:     true,
				IsResourceLevel:  false,
				IsModuleResource: false,
			},
			description: "Bracket notation with quoted string key",
		},
		{
			// Regression: FullResourceAddr must retain the count/for_each index
			// inside the bracket selector itself (a module resource instance key
			// like "this[0]"), not just indices outside the brackets. See
			// pkg/detector/default_detect_test.go's "module_resource_with_count_index"
			// case for the equivalent terraformPlanPath test.
			name:      "bracket notation with nested instance index",
			searchKey: "aws_dynamodb_table[this[0]].server_side_encryption",
			expected: &ParsedSearchKey{
				ResourceType:     "aws_dynamodb_table",
				ResourceName:     "this",
				FullResourceAddr: "aws_dynamodb_table.this[0]",
				NormalizedAddr:   "aws_dynamodb_table.this",
				AttributePath:    []string{"server_side_encryption"},
				HasAttribute:     true,
				IsResourceLevel:  false,
				IsModuleResource: false,
			},
			description: "Bracket notation must keep the nested instance index in FullResourceAddr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSearchKey(tt.searchKey)

			if err != nil {
				t.Errorf("ParseSearchKey returned error: %v", err)
				return
			}

			if result == nil {
				t.Errorf("ParseSearchKey returned nil (expected implementation missing)")
				t.Logf("Description: %s", tt.description)
				t.Logf("SearchKey: %s", tt.searchKey)
				t.Logf("Expected: %+v", tt.expected)
				return
			}

			// Detailed field-by-field comparison
			if result.ResourceType != tt.expected.ResourceType {
				t.Errorf("ResourceType = %q, want %q", result.ResourceType, tt.expected.ResourceType)
			}
			if result.ResourceName != tt.expected.ResourceName {
				t.Errorf("ResourceName = %q, want %q", result.ResourceName, tt.expected.ResourceName)
			}
			if !reflect.DeepEqual(result.ModulePath, tt.expected.ModulePath) {
				t.Errorf("ModulePath = %v, want %v", result.ModulePath, tt.expected.ModulePath)
			}
			if result.FullResourceAddr != tt.expected.FullResourceAddr {
				t.Errorf("FullResourceAddr = %q, want %q", result.FullResourceAddr, tt.expected.FullResourceAddr)
			}
			if result.NormalizedAddr != tt.expected.NormalizedAddr {
				t.Errorf("NormalizedAddr = %q, want %q", result.NormalizedAddr, tt.expected.NormalizedAddr)
			}
			if !reflect.DeepEqual(result.AttributePath, tt.expected.AttributePath) {
				t.Errorf("AttributePath = %v, want %v", result.AttributePath, tt.expected.AttributePath)
			}
			if result.HasAttribute != tt.expected.HasAttribute {
				t.Errorf("HasAttribute = %v, want %v", result.HasAttribute, tt.expected.HasAttribute)
			}
			if result.IsResourceLevel != tt.expected.IsResourceLevel {
				t.Errorf("IsResourceLevel = %v, want %v", result.IsResourceLevel, tt.expected.IsResourceLevel)
			}
			if result.IsModuleResource != tt.expected.IsModuleResource {
				t.Errorf("IsModuleResource = %v, want %v", result.IsModuleResource, tt.expected.IsModuleResource)
			}

			t.Logf("✓ Description: %s", tt.description)
		})
	}
}

// TestParseSearchKey_InvalidFormats tests that the parser handles invalid inputs gracefully
func TestParseSearchKey_InvalidFormats(t *testing.T) {
	tests := []struct {
		name      string
		searchKey string
		wantErr   bool
	}{
		{
			name:      "empty string",
			searchKey: "",
			wantErr:   true,
		},
		{
			name:      "single component",
			searchKey: "aws_instance",
			wantErr:   true,
		},
		{
			name:      "unmatched opening bracket",
			searchKey: "aws_instance[web.tags",
			wantErr:   true,
		},
		{
			name:      "unmatched closing bracket",
			searchKey: "aws_instance.web].tags",
			wantErr:   true,
		},
		{
			name:      "unmatched template braces",
			searchKey: "aws_instance.{{web.tags",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSearchKey(tt.searchKey)

			if tt.wantErr {
				if err == nil && result != nil {
					t.Errorf("ParseSearchKey() expected error for invalid input %q, got result: %+v", tt.searchKey, result)
				}
			}
		})
	}
}

// TestFindMatchingBracketSimple_QuotedForEachKey verifies bracket matching is quote-aware,
// since a for_each string key can itself contain a literal "]" or "[".
func TestFindMatchingBracketSimple_QuotedForEachKey(t *testing.T) {
	tests := []struct {
		name      string
		s         string
		startIdx  int
		wantClose int
	}{
		{
			name:      "plain count index",
			s:         `web[0].ami`,
			startIdx:  3,
			wantClose: 5,
		},
		{
			name:      "quoted key with literal closing bracket",
			s:         `module.secrets["prod]eu"].aws_instance.web`,
			startIdx:  14,
			wantClose: 24,
		},
		{
			name:      "quoted key with literal opening bracket",
			s:         `module.secrets["prod[eu"].aws_instance.web`,
			startIdx:  14,
			wantClose: 24,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findMatchingBracketSimple(tt.s, tt.startIdx)
			if got != tt.wantClose {
				t.Errorf("findMatchingBracketSimple(%q, %d) = %d, want %d", tt.s, tt.startIdx, got, tt.wantClose)
			}
		})
	}
}

// TestSplitPreservingBrackets_QuotedForEachKey verifies dot-splitting is quote-aware,
// since a for_each string key can itself contain a literal "]", "[", or ".".
func TestSplitPreservingBrackets_QuotedForEachKey(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want []string
	}{
		{
			name: "plain module path with count index",
			s:    "module.app[0].aws_instance.web",
			want: []string{"module", "app[0]", "aws_instance", "web"},
		},
		{
			name: "for_each key containing both a bracket and a dot",
			s:    `module.secrets["prod].eu"].aws_instance.web`,
			want: []string{"module", `secrets["prod].eu"]`, "aws_instance", "web"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitPreservingBrackets(tt.s)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitPreservingBrackets(%q) = %#v, want %#v", tt.s, got, tt.want)
			}
		})
	}
}
