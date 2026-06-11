# Test assets/libraries/terraform.rego
# Make sure you have OPA version 0.49.2 installed
# Run from repo root using `opa test assets/libraries/ -v`
package generic.terraform

import rego.v1

import data.generic.common as common_lib

# Test check_cidr with open access (0.0.0.0/0)
test_check_cidr_with_cidr_blocks_open if {
	rule := {"cidr_blocks": ["0.0.0.0/0"]}
	check_cidr(rule)
}

test_check_cidr_with_cidr_block_open if {
	rule := {"cidr_block": "0.0.0.0/0"}
	check_cidr(rule)
}

test_check_cidr_with_restricted_access if {
	rule := {"cidr_blocks": ["10.0.0.0/16"]}
	not check_cidr(rule)
}

# Test portOpenToInternet function
test_port_open_to_internet_allow if {
	rule := {
		"action": "allow",
		"cidr_blocks": ["0.0.0.0/0"],
		"protocol": "tcp",
		"from_port": 22,
		"to_port": 22,
	}
	portOpenToInternet(rule, 22)
}

test_port_open_to_internet_no_action if {
	rule := {
		"cidr_blocks": ["0.0.0.0/0"],
		"protocol": "tcp",
		"from_port": 22,
		"to_port": 22,
	}
	portOpenToInternet(rule, 22)
}

test_port_not_open_when_denied if {
	rule := {
		"action": "deny",
		"cidr_blocks": ["0.0.0.0/0"],
		"protocol": "tcp",
		"from_port": 22,
		"to_port": 22,
	}
	not portOpenToInternet(rule, 22)
}

test_port_not_open_with_restricted_cidr if {
	rule := {
		"action": "allow",
		"cidr_blocks": ["10.0.0.0/16"],
		"protocol": "tcp",
		"from_port": 22,
		"to_port": 22,
	}
	not portOpenToInternet(rule, 22)
}

# Test containsPort function
test_contains_port_in_range if {
	rule := {
		"from_port": 20,
		"to_port": 25,
	}
	containsPort(rule, 22)
}

test_contains_port_all_ports if {
	rule := {
		"from_port": 0,
		"to_port": 0,
	}
	containsPort(rule, 80)
}

test_contains_port_outside_range if {
	rule := {
		"from_port": 443,
		"to_port": 443,
	}
	not containsPort(rule, 80)
}

# Test getProtocolList function
test_get_protocol_list_wildcard_dash if {
	protocols := getProtocolList("-1")
	count(protocols) == 3
	protocols[_] == "TCP"
	protocols[_] == "UDP"
	protocols[_] == "ICMP"
}

test_get_protocol_list_wildcard_asterisk if {
	protocols := getProtocolList("*")
	count(protocols) == 3
}

test_get_protocol_list_tcp if {
	protocols := getProtocolList("tcp")
	count(protocols) == 1
	protocols[0] == "TCP"
}

test_get_protocol_list_udp if {
	protocols := getProtocolList("UDP")
	count(protocols) == 1
	protocols[0] == "UDP"
}

# Test anyPrincipal function
test_any_principal_string if {
	statement := {"Principal": "*"}
	anyPrincipal(statement)
}

test_any_principal_aws_string if {
	statement := {"Principal": {"AWS": "*"}}
	anyPrincipal(statement)
}

test_any_principal_aws_array if {
	statement := {"Principal": {"AWS": ["*"]}}
	anyPrincipal(statement)
}

test_any_principal_service_string if {
	statement := {"Principal": {"Service": "*"}}
	anyPrincipal(statement)
}

test_any_principal_service_array if {
	statement := {"Principal": {"Service": ["*"]}}
	anyPrincipal(statement)
}

test_any_principal_specific_account if {
	statement := {"Principal": {"AWS": "arn:aws:iam::123456789012:root"}}
	not anyPrincipal(statement)
}

# Test getSpecInfo function
test_get_spec_info_job_template if {
	resource := {"spec": {"job_template": {"spec": {"template": {"spec": {"containers": [{"name": "test"}]}}}}}}
	result := getSpecInfo(resource)
	result.path == "spec.job_template.spec.template.spec"
	result.spec.containers[0].name == "test"
}

test_get_spec_info_template if {
	resource := {"spec": {"template": {"spec": {"containers": [{"name": "test"}]}}}}
	result := getSpecInfo(resource)
	result.path == "spec.template.spec"
	result.spec.containers[0].name == "test"
}

test_get_spec_info_direct if {
	resource := {"spec": {"containers": [{"name": "test"}]}}
	result := getSpecInfo(resource)
	result.path == "spec"
	result.spec.containers[0].name == "test"
}

# Test empty_array function
test_empty_array_with_empty_array if {
	empty_array([])
}

test_empty_array_with_null if {
	empty_array(null)
}

test_empty_array_with_non_empty_array if {
	not empty_array([1, 2, 3])
}

# Test has_key function
test_has_key_exists if {
	obj := {"key1": "value1", "key2": "value2"}
	has_key(obj, "key1")
}

test_has_key_not_exists if {
	obj := {"key1": "value1"}
	not has_key(obj, "key2")
}

# Test getStatement function
test_get_statement_array if {
	policy := {"Statement": [
		{"Effect": "Allow", "Action": "*"},
		{"Effect": "Deny", "Action": "s3:*"},
	]}
	statements := getStatement(policy)
	count(statements) == 2
	statements[0].Effect == "Allow"
}

test_get_statement_single if {
	policy := {"Statement": {"Effect": "Allow", "Action": "*"}}
	statements := getStatement(policy)
	count(statements) == 1
	statements[0].Effect == "Allow"
}

# Test is_publicly_accessible function
test_is_publicly_accessible_with_wildcard_principal if {
	policy := {"Statement": [{
		"Effect": "Allow",
		"Principal": "*",
		"Action": "s3:GetObject",
	}]}
	is_publicly_accessible(policy)
}

test_is_publicly_accessible_with_aws_wildcard if {
	policy := {"Statement": {
		"Effect": "Allow",
		"Principal": {"AWS": "*"},
		"Action": "s3:*",
	}}
	is_publicly_accessible(policy)
}

test_not_publicly_accessible_with_deny if {
	policy := {"Statement": [{
		"Effect": "Deny",
		"Principal": "*",
		"Action": "s3:*",
	}]}
	not is_publicly_accessible(policy)
}

test_not_publicly_accessible_with_specific_principal if {
	policy := {"Statement": [{
		"Effect": "Allow",
		"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
		"Action": "s3:*",
	}]}
	not is_publicly_accessible(policy)
}

# Test is_default_password function
test_is_default_password_with_common_password if {
	is_default_password("password")
}

test_is_default_password_with_repetition if {
	is_default_password("user1111")
}

test_is_default_password_with_zeros if {
	is_default_password("test000")
}

test_not_default_password_valid if {
	not is_default_password("MyStr0ng!Pass")
}

# Test matches function
test_matches_with_dot_notation if {
	matches("aws_s3_bucket.my_bucket", "my_bucket")
}

test_matches_with_exact_match if {
	matches("my_bucket", "my_bucket")
}

test_not_matches_different_name if {
	not matches("aws_s3_bucket.other_bucket", "my_bucket")
}

# Test check_member function
test_check_member_with_members_array if {
	attribute := {"members": ["allUsers", "user:test@example.com"]}
	check_member(attribute, "allUsers")
}

test_check_member_with_member_string if {
	attribute := {"member": "allAuthenticatedUsers"}
	check_member(attribute, "allAuthenticated")
}

test_not_check_member_no_match if {
	attribute := {"members": ["user:test@example.com"]}
	not check_member(attribute, "allUsers")
}

# Test check_aws_resource_supports_tags function
test_check_aws_resource_supports_tags_s3 if {
	check_aws_resource_supports_tags("aws_s3_bucket")
}

test_check_aws_resource_supports_tags_ec2 if {
	check_aws_resource_supports_tags("aws_instance")
}

test_check_aws_resource_not_supports_tags if {
	not check_aws_resource_supports_tags("aws_unsupported_resource")
}

# Test check_gcp_resource_supports_labels function
test_check_gcp_resource_supports_labels_storage if {
	check_gcp_resource_supports_labels("google_storage_bucket")
}

test_check_gcp_resource_supports_labels_compute if {
	check_gcp_resource_supports_labels("google_compute_instance")
}

test_check_gcp_resource_not_supports_labels if {
	not check_gcp_resource_supports_labels("google_unsupported_resource")
}

# Test check_azure_resource_supports_tags function
test_check_azure_resource_supports_tags_storage if {
	check_azure_resource_supports_tags("azurerm_storage_account")
}

test_check_azure_resource_supports_tags_vm if {
	check_azure_resource_supports_tags("azurerm_linux_virtual_machine")
}

test_check_azure_resource_not_supports_tags if {
	not check_azure_resource_supports_tags("azurerm_unsupported_resource")
}

# Test portOpenToInternet with arrays
test_port_open_to_internet_array_allow if {
	rules := [{
		"action": "allow",
		"cidr_blocks": ["0.0.0.0/0"],
		"protocol": "tcp",
		"from_port": 22,
		"to_port": 22,
	}]
	portOpenToInternet(rules, 22)
}

test_port_open_to_internet_array_no_action if {
	rules := [{
		"cidr_blocks": ["0.0.0.0/0"],
		"protocol": "tcp",
		"from_port": 80,
		"to_port": 80,
	}]
	portOpenToInternet(rules, 80)
}

test_port_not_open_to_internet_array_deny if {
	rules := [{
		"action": "deny",
		"cidr_blocks": ["0.0.0.0/0"],
		"protocol": "tcp",
		"from_port": 22,
		"to_port": 22,
	}]
	not portOpenToInternet(rules, 22)
}

# Test portOpenToInternet with rule_action (aws_network_acl_rule)
test_port_open_to_internet_rule_action_allow if {
	rule := {
		"rule_action": "allow",
		"cidr_block": "0.0.0.0/0",
		"protocol": "tcp",
		"from_port": 3389,
		"to_port": 3389,
	}
	portOpenToInternet(rule, 3389)
}

test_port_not_open_to_internet_rule_action_deny if {
	rule := {
		"rule_action": "deny",
		"cidr_block": "0.0.0.0/0",
		"protocol": "tcp",
		"from_port": 3389,
		"to_port": 3389,
	}
	not portOpenToInternet(rule, 3389)
}

test_port_not_open_to_internet_rule_action_deny_with_cidr_blocks if {
	rule := {
		"rule_action": "deny",
		"cidr_blocks": ["0.0.0.0/0"],
		"protocol": "tcp",
		"from_port": 22,
		"to_port": 22,
	}
	not portOpenToInternet(rule, 22)
}

test_port_open_to_internet_rule_action_allow_with_port_range if {
	rule := {
		"rule_action": "allow",
		"cidr_block": "0.0.0.0/0",
		"protocol": "tcp",
		"from_port": 3300,
		"to_port": 3400,
	}
	portOpenToInternet(rule, 3389)
}

test_port_not_open_to_internet_rule_action_with_restricted_cidr if {
	rule := {
		"rule_action": "allow",
		"cidr_block": "10.0.0.0/16",
		"protocol": "tcp",
		"from_port": 3389,
		"to_port": 3389,
	}
	not portOpenToInternet(rule, 3389)
}

test_port_not_open_to_internet_rule_action_with_different_protocol if {
	rule := {
		"rule_action": "allow",
		"cidr_block": "0.0.0.0/0",
		"protocol": "udp",
		"from_port": 3389,
		"to_port": 3389,
	}
	not portOpenToInternet(rule, 3389)
}

# Test containsPort with destination_port_range
test_contains_port_destination_range_exact if {
	rule := {"destination_port_range": "22"}
	containsPort(rule, 22)
}

test_contains_port_destination_range_list if {
	rule := {"destination_port_range": "80,443,8080"}
	containsPort(rule, 443)
}

test_contains_port_destination_range_with_dash if {
	rule := {"destination_port_range": "8000-8100"}
	containsPort(rule, 8050)
}

# Test get_resource_name function
test_get_resource_name if {
	resource := {"name": "test-resource"}
	name := get_resource_name(resource, "my_resource")
	name == "my_resource"
}

# Test get_specific_resource_name function
test_get_specific_resource_name_s3 if {
	resource := {"bucket": "my-s3-bucket"}
	name := get_specific_resource_name(resource, "aws_s3_bucket", "resource_def")
	name == "my-s3-bucket"
}

test_get_specific_resource_name_fallback if {
	resource := {"name": "test"}
	name := get_specific_resource_name(resource, "aws_instance", "my_instance")
	name == "my_instance"
}

test_get_specific_resource_name_rejects_interpolation if {
	resource := {"bucket": "${aws_s3_bucket.foo.id}"}
	name := get_specific_resource_name(resource, "aws_s3_bucket", "my_bucket")
	name == "my_bucket"
}

test_get_specific_resource_name_rejects_composite_interpolation if {
	resource := {"bucket": "prefix-${var.env}-suffix"}
	name := get_specific_resource_name(resource, "aws_s3_bucket", "my_bucket")
	name == "my_bucket"
}

# Test resolve_reference_name function
test_resolve_reference_name_literal if {
	resource := {"bucket": "my-bucket"}
	name := resolve_reference_name(resource, "bucket", "aws_s3_bucket", "fallback_logical")
	name == "my-bucket"
}

test_resolve_reference_name_composite_interpolation_falls_back if {
	resource := {"bucket": "prefix-${var.env}-suffix"}
	name := resolve_reference_name(resource, "bucket", "aws_s3_bucket", "fallback_logical")
	name == "fallback_logical"
}

test_resolve_reference_name_unknown_reference_falls_back if {
	resource := {"bucket": "${module.x.bucket_id}"}
	name := resolve_reference_name(resource, "bucket", "aws_s3_bucket", "fallback_logical")
	name == "fallback_logical"
}

test_resolve_reference_name_missing_attribute_falls_back if {
	resource := {"other": "value"}
	name := resolve_reference_name(resource, "bucket", "aws_s3_bucket", "fallback_logical")
	name == "fallback_logical"
}

test_resolve_reference_name_var_without_default_falls_back if {
	resource := {"bucket": "${var.bucket_name}"}
	name := resolve_reference_name(resource, "bucket", "aws_s3_bucket", "fallback_logical")
	name == "fallback_logical"
}

# Test resolve_s3_bucket_name function against mock input.document shape
test_resolve_s3_bucket_name_literal if {
	resource := {"bucket": "my-literal-bucket"}
	name := resolve_s3_bucket_name(resource, "policy_logical_name") with input as {}
	name == "my-literal-bucket"
}

test_resolve_s3_bucket_name_same_document_reference if {
	mock_input := {"document": [{"resource": {
		"aws_s3_bucket": {"my_bucket": {"bucket": "shopist-prod"}},
		"aws_s3_bucket_policy": {"my_policy": {"bucket": "${aws_s3_bucket.my_bucket.id}"}},
	}}]}
	policy := mock_input.document[0].resource.aws_s3_bucket_policy.my_policy
	name := resolve_s3_bucket_name(policy, "my_policy") with input as mock_input
	name == "shopist-prod"
}

test_resolve_s3_bucket_name_cross_document_reference if {
	mock_input := {"document": [
		{"resource": {"aws_s3_bucket": {"my_bucket": {"bucket": "shopist-cross-file"}}}},
		{"resource": {"aws_s3_bucket_policy": {"my_policy": {"bucket": "${aws_s3_bucket.my_bucket.id}"}}}},
	]}
	policy := mock_input.document[1].resource.aws_s3_bucket_policy.my_policy
	name := resolve_s3_bucket_name(policy, "my_policy") with input as mock_input
	name == "shopist-cross-file"
}

test_resolve_s3_bucket_name_reference_to_missing_bucket_falls_back if {
	mock_input := {"document": [{"resource": {"aws_s3_bucket_policy": {"orphan_policy": {"bucket": "${aws_s3_bucket.not_there.id}"}}}}]}
	policy := mock_input.document[0].resource.aws_s3_bucket_policy.orphan_policy
	name := resolve_s3_bucket_name(policy, "orphan_policy") with input as mock_input
	name == "orphan_policy"
}

test_resolve_s3_bucket_name_reference_to_bucket_without_literal_name_returns_target_logical_name if {
	# When the referenced aws_s3_bucket exists in the scan but its `bucket`
	# attribute is itself unresolvable (e.g. "${var.bucket_name}" with no
	# default), prefer the target bucket's Terraform logical name over the
	# companion resource's own logical name -- it is one step closer to the
	# runtime asset and still jump-to-code-friendly.
	mock_input := {"document": [{"resource": {
		"aws_s3_bucket": {"dynamic": {"bucket": "${var.bucket_name}"}},
		"aws_s3_bucket_policy": {"its_policy": {"bucket": "${aws_s3_bucket.dynamic.id}"}},
	}}]}
	policy := mock_input.document[0].resource.aws_s3_bucket_policy.its_policy
	name := resolve_s3_bucket_name(policy, "its_policy") with input as mock_input
	name == "dynamic"
}

test_resolve_s3_bucket_name_module_reference_falls_back if {
	mock_input := {"document": [{"resource": {"aws_s3_bucket_policy": {"modular_policy": {"bucket": "${module.shopist.bucket_id}"}}}}]}
	policy := mock_input.document[0].resource.aws_s3_bucket_policy.modular_policy
	name := resolve_s3_bucket_name(policy, "modular_policy") with input as mock_input
	name == "modular_policy"
}
