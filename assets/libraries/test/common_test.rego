# Test assets/libraries/common.rego
# Make sure you have OPA version 0.49.2 installed
# Run from repo root using `opa test assets/libraries/ -v`
package generic.common

import rego.v1

# Test build_search_line function
test_build_search_line_with_path_only if {
	result := build_search_line(["father", "son", "grandson"], [])
	count(result) == 3
	result[0] == "father"
	result[1] == "son"
	result[2] == "grandson"
}

test_build_search_line_with_path_and_obj if {
	result := build_search_line(["father", "son"], ["grandson"])
	count(result) == 3
	result[0] == "father"
	result[1] == "son"
	result[2] == "grandson"
}

test_build_search_line_with_numbers if {
	result := build_search_line(["array", 0, "field"], [])
	count(result) == 3
	result[0] == "array"
	result[1] == "0"
	result[2] == "field"
}

# Test concat_path function
test_concat_path_simple if {
	result := concat_path(["Resources", "MyBucket", "Properties"])
	result == "Resources.MyBucket.Properties"
}

test_concat_path_with_numbers if {
	result := concat_path(["items", 0, "name"])
	result == "items.name"
}

test_concat_path_with_special_chars if {
	result := concat_path(["field.with.dot", "another=field"])
	result == "{{field.with.dot}}.{{another=field}}"
}

# Test calc_IP_value function
test_calc_IP_value_basic if {
	result := calc_IP_value("192.168.1.1")
	result == 3232235777
}

test_calc_IP_value_zero if {
	result := calc_IP_value("0.0.0.0")
	result == 0
}

test_calc_IP_value_max if {
	result := calc_IP_value("255.255.255.255")
	result == 4294967295
}

# Test between function
test_between_true if {
	between(5, 1, 10)
}

test_between_boundaries if {
	between(10, 10, 10)
}

test_between_false if {
	not between(15, 1, 10)
}

# Test inArray function
test_in_array_found if {
	list := ["a", "b", "c"]
	inArray(list, "b")
}

test_in_array_not_found if {
	list := ["a", "b", "c"]
	not inArray(list, "d")
}

test_in_array_numbers if {
	list := [1, 2, 3]
	inArray(list, 2)
}

# Test emptyOrNull function
test_empty_or_null_with_empty_string if {
	emptyOrNull("")
}

test_empty_or_null_with_null if {
	emptyOrNull(null)
}

test_empty_or_null_with_value if {
	not emptyOrNull("value")
}

# Test isPrivateIP function
test_is_private_ip_class_a if {
	isPrivateIP("10.0.0.1")
}

test_is_private_ip_class_b if {
	isPrivateIP("172.16.0.1")
}

test_is_private_ip_class_c if {
	isPrivateIP("192.168.1.1")
}

test_is_not_private_ip if {
	not isPrivateIP("8.8.8.8")
}

# Test equalsOrInArray function
test_equals_or_in_array_string_match if {
	equalsOrInArray("allow", "allow")
}

test_equals_or_in_array_string_case_insensitive if {
	equalsOrInArray("Allow", "allow")
}

test_equals_or_in_array_array_match if {
	equalsOrInArray(["Allow", "Deny"], "allow")
}

test_equals_or_in_array_no_match if {
	not equalsOrInArray("Deny", "allow")
}

# Test containsOrInArrayContains function
test_contains_or_in_array_contains_string if {
	containsOrInArrayContains("allow-all", "allow")
}

test_contains_or_in_array_contains_array if {
	containsOrInArrayContains(["allow-all", "deny-some"], "allow")
}

test_contains_or_in_array_contains_no_match if {
	not containsOrInArrayContains("deny", "allow")
}

# Test get_statement function
test_get_statement_array if {
	policy := {"Statement": [
		{"Effect": "Allow"},
		{"Effect": "Deny"},
	]}
	result := get_statement(policy)
	count(result) == 2
	result[0].Effect == "Allow"
}

test_get_statement_object if {
	policy := {"Statement": {"Effect": "Allow"}}
	result := get_statement(policy)
	count(result) == 1
	result[0].Effect == "Allow"
}

# Test is_allow_effect function
test_is_allow_effect_with_allow if {
	statement := {"Effect": "Allow"}
	is_allow_effect(statement)
}

test_is_allow_effect_lowercase if {
	statement := {"effect": "Allow"}
	is_allow_effect(statement)
}

test_is_allow_effect_no_effect_field if {
	statement := {"Action": "*"}
	is_allow_effect(statement)
}

test_is_not_allow_effect if {
	statement := {"Effect": "Deny"}
	not is_allow_effect(statement)
}

# Test is_cross_account function
test_is_cross_account_string if {
	statement := {"Principal": {"AWS": "arn:aws:iam::123456789012:root"}}
	is_cross_account(statement)
}

test_is_cross_account_array if {
	statement := {"Principal": {"AWS": ["arn:aws:sts::123456789012:assumed-role/test"]}}
	is_cross_account(statement)
}

test_is_cross_account_account_id if {
	statement := {"Principal": {"AWS": "123456789012"}}
	is_cross_account(statement)
}

test_is_not_cross_account if {
	statement := {"Principal": {"AWS": "arn:aws:ec2::123456789012:instance/i-123"}}
	not is_cross_account(statement)
}

# Test is_assume_role function
test_is_assume_role_string if {
	statement := {"Action": "sts:AssumeRole"}
	is_assume_role(statement)
}

test_is_assume_role_array if {
	statement := {"Action": ["sts:AssumeRole", "sts:GetSessionToken"]}
	is_assume_role(statement)
}

test_is_not_assume_role if {
	statement := {"Action": "s3:GetObject"}
	not is_assume_role(statement)
}

# Test has_external_id function
test_has_external_id_present if {
	statement := {"Condition": {"StringEquals": {"sts:ExternalId": "external123"}}}
	has_external_id(statement)
}

test_has_external_id_absent if {
	statement := {"Condition": {"StringEquals": {}}}
	not has_external_id(statement)
}

# Test has_mfa function
test_has_mfa_bool_if_exists if {
	statement := {"Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "true"}}}
	has_mfa(statement)
}

test_has_mfa_bool if {
	statement := {"Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}
	has_mfa(statement)
}

test_has_mfa_absent if {
	statement := {"Condition": {}}
	not has_mfa(statement)
}

# Test any_principal function
test_any_principal_wildcard_string if {
	statement := {"Principal": "*"}
	any_principal(statement)
}

test_any_principal_aws_wildcard_string if {
	statement := {"Principal": {"AWS": "*"}}
	any_principal(statement)
}

test_any_principal_aws_wildcard_array if {
	statement := {"Principal": {"AWS": ["*"]}}
	any_principal(statement)
}

test_any_principal_no_principal if {
	statement := {"Effect": "Allow"}
	any_principal(statement)
}

test_not_any_principal if {
	statement := {"Principal": {"AWS": "arn:aws:iam::123456789012:root"}}
	not any_principal(statement)
}

# Test valid_key function
test_valid_key_exists if {
	obj := {"key1": "value1", "key2": "value2"}
	valid_key(obj, "key1")
}

test_valid_key_not_exists if {
	obj := {"key1": "value1"}
	not valid_key(obj, "key2")
}

test_valid_key_null_value if {
	obj := {"key1": null}
	not valid_key(obj, "key1")
}

# Test expired function
test_expired_past_date if {
	# Date in the past: January 1, 2000
	expired([2000, 1, 1])
}

test_not_expired_future_date if {
	# Date in the future: January 1, 2030
	not expired([2030, 1, 1])
}

# Test unsecured_cors_rule function
test_unsecured_cors_all_methods if {
	methods := ["GET", "PUT", "POST", "DELETE", "HEAD"]
	headers := ["Content-Type"]
	origins := ["https://example.com"]
	unsecured_cors_rule(methods, headers, origins)
}

test_unsecured_cors_wildcard_headers if {
	methods := ["GET"]
	headers := ["*"]
	origins := ["https://example.com"]
	unsecured_cors_rule(methods, headers, origins)
}

test_unsecured_cors_wildcard_origins if {
	methods := ["GET"]
	headers := ["Content-Type"]
	origins := ["*"]
	unsecured_cors_rule(methods, headers, origins)
}

test_secured_cors_rule if {
	methods := ["GET", "POST"]
	headers := ["Content-Type"]
	origins := ["https://example.com"]
	not unsecured_cors_rule(methods, headers, origins)
}

# Test is_ingress function
test_is_ingress_no_direction if {
	firewall := {"protocol": "tcp"}
	is_ingress(firewall)
}

test_is_ingress_explicit if {
	firewall := {"direction": "INGRESS"}
	is_ingress(firewall)
}

test_is_not_ingress if {
	firewall := {"direction": "EGRESS"}
	not is_ingress(firewall)
}

# Test is_recommended_tls function
test_is_recommended_tls_2018 if {
	is_recommended_tls("TLSv1.2_2018")
}

test_is_recommended_tls_2019 if {
	is_recommended_tls("TLSv1.2_2019")
}

test_is_recommended_tls_2021 if {
	is_recommended_tls("TLSv1.2_2021")
}

test_is_not_recommended_tls if {
	not is_recommended_tls("TLSv1.0")
}

# Test is_unrestricted function
test_is_unrestricted_ipv4 if {
	is_unrestricted("0.0.0.0/0")
}

test_is_unrestricted_ipv6 if {
	is_unrestricted("::/0")
}

test_is_not_unrestricted if {
	not is_unrestricted("10.0.0.0/16")
}

# Test check_principals function
test_check_principals_identifiers if {
	statement := {"principals": {
		"identifiers": ["*"],
		"type": "AWS",
	}}
	check_principals(statement)
}

test_check_principals_object if {
	statement := {"Principal": {"AWS": "*"}}
	check_principals(statement)
}

test_check_principals_string if {
	statement := {"Principal": "*"}
	check_principals(statement)
}

test_check_principals_no_wildcard if {
	statement := {"Principal": {"AWS": "arn:aws:iam::123456789012:root"}}
	not check_principals(statement)
}

# Test check_actions function
test_check_actions_lowercase_array if {
	statement := {"actions": ["s3:GetObject", "s3:PutObject"]}
	check_actions(statement, "s3:GetObject")
}

test_check_actions_uppercase_array if {
	statement := {"Actions": ["s3:GetObject"]}
	check_actions(statement, "s3:GetObject")
}

test_check_actions_wildcard if {
	statement := {"Action": "*"}
	check_actions(statement, "s3:GetObject")
}

test_check_actions_no_match if {
	statement := {"Action": ["s3:GetObject"]}
	not check_actions(statement, "s3:PutObject")
}

# Test has_wildcard function
test_has_wildcard_principals if {
	statement := {"Principal": "*", "Action": "s3:GetObject"}
	has_wildcard(statement, "s3:GetObject")
}

test_has_wildcard_actions if {
	statement := {
		"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
		"Action": "*",
	}
	has_wildcard(statement, "s3:GetObject")
}

# Test isOSDir function
test_is_os_dir_root if {
	isOSDir("/")
}

test_is_os_dir_bin if {
	isOSDir("/bin")
}

test_is_os_dir_etc if {
	isOSDir("/etc")
}

test_is_os_dir_nested if {
	isOSDir("/etc/config")
}

test_is_not_os_dir if {
	not isOSDir("/app")
}

# Test compareArrays function
test_compare_arrays_match if {
	arrayOne := ["Allow", "Deny"]
	arrayTwo := ["allow", "deny"]
	compareArrays(arrayOne, arrayTwo)
}

test_compare_arrays_no_match if {
	arrayOne := ["Allow"]
	arrayTwo := ["Deny"]
	not compareArrays(arrayOne, arrayTwo)
}

# Test weakCipher function with IANA format
test_weak_cipher_iana_null if {
	weakCipher("TLS_NULL_WITH_NULL_NULL")
}

test_weak_cipher_iana_rc4 if {
	weakCipher("TLS_RSA_WITH_RC4_128_MD5")
}

test_weak_cipher_iana_des if {
	weakCipher("TLS_RSA_WITH_DES_CBC_SHA")
}

# Test weakCipher function with OpenSSL format
test_weak_cipher_openssl_null if {
	weakCipher("NULL-MD5")
}

test_weak_cipher_openssl_des if {
	weakCipher("DES-CBC3-SHA")
}

test_weak_cipher_openssl_rc4 if {
	weakCipher("AES128-SHA")
}

# Test weakCipher function with GnuTLS format
test_weak_cipher_gnutls_null if {
	weakCipher("TLS_RSA_NULL_MD5")
}

test_weak_cipher_gnutls_arcfour if {
	weakCipher("TLS_RSA_ARCFOUR_128_MD5")
}

test_weak_cipher_gnutls_des if {
	weakCipher("TLS_RSA_3DES_EDE_CBC_SHA1")
}

# Test as_array function
test_as_array_with_array if {
	arr := ["a", "b", "c"]
	result := as_array(arr)
	count(result) == 3
	result[0] == "a"
}

test_as_array_with_single_value if {
	result := as_array("value")
	count(result) == 1
	result[0] == "value"
}

test_as_array_with_number if {
	result := as_array(42)
	count(result) == 1
	result[0] == 42
}

# Test contains_element function
test_contains_element_found if {
	arr := ["a", "b", "c"]
	contains_element(arr, "b")
}

test_contains_element_not_found if {
	arr := ["a", "b", "c"]
	not contains_element(arr, "d")
}

# Test contains_with_size function
test_contains_with_size_found if {
	arr := ["allow-all", "deny-some"]
	contains_with_size(arr, "allow")
}

test_contains_with_size_not_found if {
	arr := ["deny-all", "deny-some"]
	not contains_with_size(arr, "allow")
}

test_contains_with_size_empty_array if {
	arr := []
	not contains_with_size(arr, "allow")
}

# Test get_tag_name_if_exists function
test_get_tag_name_tags_field if {
	resource := {"tags": {"Name": "my-resource"}}
	result := get_tag_name_if_exists(resource)
	result == "my-resource"
}

test_get_tag_name_properties_tags_array if {
	resource := {"Properties": {"Tags": [
		{"Key": "Environment", "Value": "prod"},
		{"Key": "Name", "Value": "my-bucket"},
	]}}
	result := get_tag_name_if_exists(resource)
	result == "my-bucket"
}

test_get_tag_name_properties_tags_object if {
	resource := {"Properties": {"Tags": {
		"Environment": "prod",
		"Name": "my-resource",
	}}}
	result := get_tag_name_if_exists(resource)
	result == "my-resource"
}

# Test json_unmarshal function
test_json_unmarshal_object if {
	obj := {"key": "value"}
	result := json_unmarshal(obj)
	result.key == "value"
}

test_json_unmarshal_array if {
	arr := ["a", "b", "c"]
	result := json_unmarshal(arr)
	count(result) == 3
}

test_json_unmarshal_null if {
	result := json_unmarshal(null)
	is_object(result)
}

test_json_unmarshal_json_string if {
	str := "{\"key\":\"value\"}"
	result := json_unmarshal(str)
	result.key == "value"
}

# Test get_encryption_if_exists function
test_get_encryption_encrypted_true if {
	resource := {"encrypted": true}
	result := get_encryption_if_exists(resource)
	result == "encrypted"
}

test_get_encryption_with_key if {
	resource := {"kms_master_key_id": "arn:aws:kms:..."}
	result := get_encryption_if_exists(resource)
	result == "encrypted"
}

test_get_encryption_unencrypted if {
	resource := {"name": "my-resource"}
	result := get_encryption_if_exists(resource)
	result == "unencrypted"
}

# Test is_iam_policy_principal_scoped_by_condition function
test_is_iam_policy_principal_scoped_source_arn if {
	statement := {
		"Effect": "Allow",
		"Principal": "*",
		"Action": "sns:Publish",
		"Condition": {"ArnLike": {"aws:SourceArn": "arn:aws:s3:::my-bucket"}},
	}
	is_iam_policy_principal_scoped_by_condition(statement)
}

test_is_iam_policy_principal_scoped_source_account if {
	statement := {
		"Effect": "Allow",
		"Principal": "*",
		"Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
	}
	is_iam_policy_principal_scoped_by_condition(statement)
}

test_is_iam_policy_principal_scoped_lowercase_key if {
	# condition key matching is case-insensitive
	statement := {
		"Effect": "Allow",
		"Principal": "*",
		"Condition": {"ArnLike": {"AWS:sourcearn": "arn:aws:s3:::my-bucket"}},
	}
	is_iam_policy_principal_scoped_by_condition(statement)
}

test_is_iam_policy_principal_scoped_non_scoping_key if {
	# aws:SecureTransport restricts HOW, not WHO — not scoped
	statement := {
		"Effect": "Allow",
		"Principal": "*",
		"Condition": {"Bool": {"aws:SecureTransport": "true"}},
	}
	not is_iam_policy_principal_scoped_by_condition(statement)
}

test_is_iam_policy_principal_scoped_no_condition if {
	statement := {"Effect": "Allow", "Principal": "*", "Action": "sns:Publish"}
	not is_iam_policy_principal_scoped_by_condition(statement)
}

test_is_iam_policy_principal_scoped_negating_operator if {
	# StringNotEquals means "everyone EXCEPT this account" — still public
	statement := {
		"Effect": "Allow",
		"Principal": "*",
		"Condition": {"StringNotEquals": {"aws:SourceAccount": "123456789012"}},
	}
	not is_iam_policy_principal_scoped_by_condition(statement)
}

test_is_iam_policy_principal_scoped_ifexists_operator if {
	# ArnLikeIfExists passes when the key is absent — does not reliably restrict
	statement := {
		"Effect": "Allow",
		"Principal": "*",
		"Condition": {"ArnLikeIfExists": {"aws:SourceArn": "arn:aws:s3:::my-bucket"}},
	}
	not is_iam_policy_principal_scoped_by_condition(statement)
}

test_is_iam_policy_principal_scoped_wildcard_value if {
	# aws:SourceArn set to "*" restricts nothing
	statement := {
		"Effect": "Allow",
		"Principal": "*",
		"Condition": {"ArnLike": {"aws:SourceArn": "*"}},
	}
	not is_iam_policy_principal_scoped_by_condition(statement)
}

test_is_iam_policy_principal_scoped_array_wildcard_value if {
	# Terraform aws_iam_policy_document emits condition values as arrays; ["*"] is still a wildcard
	statement := {
		"Effect": "Allow",
		"Principal": "*",
		"Condition": {"ArnLike": {"aws:SourceArn": ["*"]}},
	}
	not is_iam_policy_principal_scoped_by_condition(statement)
}

test_is_iam_policy_principal_scoped_unrestricted_cidr if {
	# 0.0.0.0/0 on aws:SourceIp restricts nothing
	statement := {
		"Effect": "Allow",
		"Principal": "*",
		"Condition": {"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}},
	}
	not is_iam_policy_principal_scoped_by_condition(statement)
}

test_is_iam_policy_principal_scoped_unrestricted_ipv6 if {
	statement := {
		"Effect": "Allow",
		"Principal": "*",
		"Condition": {"IpAddress": {"aws:SourceIp": "::/0"}},
	}
	not is_iam_policy_principal_scoped_by_condition(statement)
}

test_is_iam_policy_principal_scoped_specific_cidr if {
	# A specific CIDR is a real restriction
	statement := {
		"Effect": "Allow",
		"Principal": "*",
		"Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
	}
	is_iam_policy_principal_scoped_by_condition(statement)
}
