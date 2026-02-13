# Test assets/libraries/terraform.rego
# Make sure you have OPA version 0.49.2 installed
# Run from repo root using `opa test assets/libraries/ -v`
package generic.terraform

import data.generic.common as common_lib

# Test check_cidr with open access (0.0.0.0/0)
test_check_cidr_with_cidr_blocks_open {
    rule := {"cidr_blocks": ["0.0.0.0/0"]}
    check_cidr(rule)
}

test_check_cidr_with_cidr_block_open {
    rule := {"cidr_block": "0.0.0.0/0"}
    check_cidr(rule)
}

test_check_cidr_with_restricted_access {
    rule := {"cidr_blocks": ["10.0.0.0/16"]}
    not check_cidr(rule)
}

# Test portOpenToInternet function
test_port_open_to_internet_allow {
    rule := {
        "action": "allow",
        "cidr_blocks": ["0.0.0.0/0"],
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22
    }
    portOpenToInternet(rule, 22)
}

test_port_open_to_internet_no_action {
    rule := {
        "cidr_blocks": ["0.0.0.0/0"],
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22
    }
    portOpenToInternet(rule, 22)
}

test_port_not_open_when_denied {
    rule := {
        "action": "deny",
        "cidr_blocks": ["0.0.0.0/0"],
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22
    }
    not portOpenToInternet(rule, 22)
}

test_port_not_open_with_restricted_cidr {
    rule := {
        "action": "allow",
        "cidr_blocks": ["10.0.0.0/16"],
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22
    }
    not portOpenToInternet(rule, 22)
}

# Test containsPort function
test_contains_port_in_range {
    rule := {
        "from_port": 20,
        "to_port": 25
    }
    containsPort(rule, 22)
}

test_contains_port_all_ports {
    rule := {
        "from_port": 0,
        "to_port": 0
    }
    containsPort(rule, 80)
}

test_contains_port_outside_range {
    rule := {
        "from_port": 443,
        "to_port": 443
    }
    not containsPort(rule, 80)
}

# Test getProtocolList function
test_get_protocol_list_wildcard_dash {
    protocols := getProtocolList("-1")
    count(protocols) == 3
    protocols[_] == "TCP"
    protocols[_] == "UDP"
    protocols[_] == "ICMP"
}

test_get_protocol_list_wildcard_asterisk {
    protocols := getProtocolList("*")
    count(protocols) == 3
}

test_get_protocol_list_tcp {
    protocols := getProtocolList("tcp")
    count(protocols) == 1
    protocols[0] == "TCP"
}

test_get_protocol_list_udp {
    protocols := getProtocolList("UDP")
    count(protocols) == 1
    protocols[0] == "UDP"
}

# Test anyPrincipal function
test_any_principal_string {
    statement := {"Principal": "*"}
    anyPrincipal(statement)
}

test_any_principal_aws_string {
    statement := {"Principal": {"AWS": "*"}}
    anyPrincipal(statement)
}

test_any_principal_aws_array {
    statement := {"Principal": {"AWS": ["*"]}}
    anyPrincipal(statement)
}

test_any_principal_service_string {
    statement := {"Principal": {"Service": "*"}}
    anyPrincipal(statement)
}

test_any_principal_service_array {
    statement := {"Principal": {"Service": ["*"]}}
    anyPrincipal(statement)
}

test_any_principal_specific_account {
    statement := {"Principal": {"AWS": "arn:aws:iam::123456789012:root"}}
    not anyPrincipal(statement)
}

# Test getSpecInfo function
test_get_spec_info_job_template {
    resource := {
        "spec": {
            "job_template": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [{"name": "test"}]
                        }
                    }
                }
            }
        }
    }
    result := getSpecInfo(resource)
    result.path == "spec.job_template.spec.template.spec"
    result.spec.containers[0].name == "test"
}

test_get_spec_info_template {
    resource := {
        "spec": {
            "template": {
                "spec": {
                    "containers": [{"name": "test"}]
                }
            }
        }
    }
    result := getSpecInfo(resource)
    result.path == "spec.template.spec"
    result.spec.containers[0].name == "test"
}

test_get_spec_info_direct {
    resource := {
        "spec": {
            "containers": [{"name": "test"}]
        }
    }
    result := getSpecInfo(resource)
    result.path == "spec"
    result.spec.containers[0].name == "test"
}

# Test empty_array function
test_empty_array_with_empty_array {
    empty_array([])
}

test_empty_array_with_null {
    empty_array(null)
}

test_empty_array_with_non_empty_array {
    not empty_array([1, 2, 3])
}

# Test has_key function
test_has_key_exists {
    obj := {"key1": "value1", "key2": "value2"}
    has_key(obj, "key1")
}

test_has_key_not_exists {
    obj := {"key1": "value1"}
    not has_key(obj, "key2")
}

# Test getStatement function
test_get_statement_array {
    policy := {
        "Statement": [
            {"Effect": "Allow", "Action": "*"},
            {"Effect": "Deny", "Action": "s3:*"}
        ]
    }
    statements := getStatement(policy)
    count(statements) == 2
    statements[0].Effect == "Allow"
}

test_get_statement_single {
    policy := {
        "Statement": {"Effect": "Allow", "Action": "*"}
    }
    statements := getStatement(policy)
    count(statements) == 1
    statements[0].Effect == "Allow"
}

# Test is_publicly_accessible function
test_is_publicly_accessible_with_wildcard_principal {
    policy := {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject"
            }
        ]
    }
    is_publicly_accessible(policy)
}

test_is_publicly_accessible_with_aws_wildcard {
    policy := {
        "Statement": {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "s3:*"
        }
    }
    is_publicly_accessible(policy)
}

test_not_publicly_accessible_with_deny {
    policy := {
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*"
            }
        ]
    }
    not is_publicly_accessible(policy)
}

test_not_publicly_accessible_with_specific_principal {
    policy := {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "s3:*"
            }
        ]
    }
    not is_publicly_accessible(policy)
}

# Test is_default_password function
test_is_default_password_with_common_password {
    is_default_password("password")
}

test_is_default_password_with_repetition {
    is_default_password("user1111")
}

test_is_default_password_with_zeros {
    is_default_password("test000")
}

test_not_default_password_valid {
    not is_default_password("MyStr0ng!Pass")
}

# Test matches function
test_matches_with_dot_notation {
    matches("aws_s3_bucket.my_bucket", "my_bucket")
}

test_matches_with_exact_match {
    matches("my_bucket", "my_bucket")
}

test_not_matches_different_name {
    not matches("aws_s3_bucket.other_bucket", "my_bucket")
}

# Test check_member function
test_check_member_with_members_array {
    attribute := {"members": ["allUsers", "user:test@example.com"]}
    check_member(attribute, "allUsers")
}

test_check_member_with_member_string {
    attribute := {"member": "allAuthenticatedUsers"}
    check_member(attribute, "allAuthenticated")
}

test_not_check_member_no_match {
    attribute := {"members": ["user:test@example.com"]}
    not check_member(attribute, "allUsers")
}

# Test check_aws_resource_supports_tags function
test_check_aws_resource_supports_tags_s3 {
    check_aws_resource_supports_tags("aws_s3_bucket")
}

test_check_aws_resource_supports_tags_ec2 {
    check_aws_resource_supports_tags("aws_instance")
}

test_check_aws_resource_not_supports_tags {
    not check_aws_resource_supports_tags("aws_unsupported_resource")
}

# Test check_gcp_resource_supports_labels function
test_check_gcp_resource_supports_labels_storage {
    check_gcp_resource_supports_labels("google_storage_bucket")
}

test_check_gcp_resource_supports_labels_compute {
    check_gcp_resource_supports_labels("google_compute_instance")
}

test_check_gcp_resource_not_supports_labels {
    not check_gcp_resource_supports_labels("google_unsupported_resource")
}

# Test check_azure_resource_supports_tags function
test_check_azure_resource_supports_tags_storage {
    check_azure_resource_supports_tags("azurerm_storage_account")
}

test_check_azure_resource_supports_tags_vm {
    check_azure_resource_supports_tags("azurerm_linux_virtual_machine")
}

test_check_azure_resource_not_supports_tags {
    not check_azure_resource_supports_tags("azurerm_unsupported_resource")
}

# Test portOpenToInternet with arrays
test_port_open_to_internet_array_allow {
    rules := [
        {
            "action": "allow",
            "cidr_blocks": ["0.0.0.0/0"],
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22
        }
    ]
    portOpenToInternet(rules, 22)
}

test_port_open_to_internet_array_no_action {
    rules := [
        {
            "cidr_blocks": ["0.0.0.0/0"],
            "protocol": "tcp",
            "from_port": 80,
            "to_port": 80
        }
    ]
    portOpenToInternet(rules, 80)
}

test_port_not_open_to_internet_array_deny {
    rules := [
        {
            "action": "deny",
            "cidr_blocks": ["0.0.0.0/0"],
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22
        }
    ]
    not portOpenToInternet(rules, 22)
}

# Test portOpenToInternet with rule_action (aws_network_acl_rule)
test_port_open_to_internet_rule_action_allow {
    rule := {
        "rule_action": "allow",
        "cidr_block": "0.0.0.0/0",
        "protocol": "tcp",
        "from_port": 3389,
        "to_port": 3389
    }
    portOpenToInternet(rule, 3389)
}

test_port_not_open_to_internet_rule_action_deny {
    rule := {
        "rule_action": "deny",
        "cidr_block": "0.0.0.0/0",
        "protocol": "tcp",
        "from_port": 3389,
        "to_port": 3389
    }
    not portOpenToInternet(rule, 3389)
}

test_port_not_open_to_internet_rule_action_deny_with_cidr_blocks {
    rule := {
        "rule_action": "deny",
        "cidr_blocks": ["0.0.0.0/0"],
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22
    }
    not portOpenToInternet(rule, 22)
}

test_port_open_to_internet_rule_action_allow_with_port_range {
    rule := {
        "rule_action": "allow",
        "cidr_block": "0.0.0.0/0",
        "protocol": "tcp",
        "from_port": 3300,
        "to_port": 3400
    }
    portOpenToInternet(rule, 3389)
}

test_port_not_open_to_internet_rule_action_with_restricted_cidr {
    rule := {
        "rule_action": "allow",
        "cidr_block": "10.0.0.0/16",
        "protocol": "tcp",
        "from_port": 3389,
        "to_port": 3389
    }
    not portOpenToInternet(rule, 3389)
}

test_port_not_open_to_internet_rule_action_with_different_protocol {
    rule := {
        "rule_action": "allow",
        "cidr_block": "0.0.0.0/0",
        "protocol": "udp",
        "from_port": 3389,
        "to_port": 3389
    }
    not portOpenToInternet(rule, 3389)
}

# Test containsPort with destination_port_range
test_contains_port_destination_range_exact {
    rule := {
        "destination_port_range": "22"
    }
    containsPort(rule, 22)
}

test_contains_port_destination_range_list {
    rule := {
        "destination_port_range": "80,443,8080"
    }
    containsPort(rule, 443)
}

test_contains_port_destination_range_with_dash {
    rule := {
        "destination_port_range": "8000-8100"
    }
    containsPort(rule, 8050)
}

# Test get_resource_name function
test_get_resource_name {
    resource := {"name": "test-resource"}
    name := get_resource_name(resource, "my_resource")
    name == "my_resource"
}

# Test get_specific_resource_name function
test_get_specific_resource_name_s3 {
    resource := {"bucket": "my-s3-bucket"}
    name := get_specific_resource_name(resource, "aws_s3_bucket", "resource_def")
    name == "my-s3-bucket"
}

test_get_specific_resource_name_fallback {
    resource := {"name": "test"}
    name := get_specific_resource_name(resource, "aws_instance", "my_instance")
    name == "my_instance"
}
