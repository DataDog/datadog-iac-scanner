# Test assets/libraries/common.rego
# Make sure you have OPA version 0.49.2 installed
# Run from repo root using `opa test assets/libraries/ -v`
package generic.common

# Test build_search_line function
test_build_search_line_with_path_only {
	result := build_search_line(["father", "son", "grandson"], [])
	count(result) == 3
	result[0] == "father"
	result[1] == "son"
	result[2] == "grandson"
}

test_build_search_line_with_path_and_obj {
	result := build_search_line(["father", "son"], ["grandson"])
	count(result) == 3
	result[0] == "father"
	result[1] == "son"
	result[2] == "grandson"
}

test_build_search_line_with_numbers {
	result := build_search_line(["array", 0, "field"], [])
	count(result) == 3
	result[0] == "array"
	result[1] == "0"
	result[2] == "field"
}

# Test concat_path function
test_concat_path_simple {
	result := concat_path(["Resources", "MyBucket", "Properties"])
	result == "Resources.MyBucket.Properties"
}

test_concat_path_with_numbers {
	result := concat_path(["items", 0, "name"])
	result == "items.name"
}

test_concat_path_with_special_chars {
	result := concat_path(["field.with.dot", "another=field"])
	result == "{{field.with.dot}}.{{another=field}}"
}

# Test calc_IP_value function
test_calc_IP_value_basic {
	result := calc_IP_value("192.168.1.1")
	result == 3232235777
}

test_calc_IP_value_zero {
	result := calc_IP_value("0.0.0.0")
	result == 0
}

test_calc_IP_value_max {
	result := calc_IP_value("255.255.255.255")
	result == 4294967295
}

# Test between function
test_between_true {
	between(5, 1, 10)
}

test_between_boundaries {
	between(10, 10, 10)
}

test_between_false {
	not between(15, 1, 10)
}

# Test inArray function
test_in_array_found {
	list := ["a", "b", "c"]
	inArray(list, "b")
}

test_in_array_not_found {
	list := ["a", "b", "c"]
	not inArray(list, "d")
}

test_in_array_numbers {
	list := [1, 2, 3]
	inArray(list, 2)
}

# Test emptyOrNull function
test_empty_or_null_with_empty_string {
	emptyOrNull("")
}

test_empty_or_null_with_null {
	emptyOrNull(null)
}

test_empty_or_null_with_value {
	not emptyOrNull("value")
}

# Test isPrivateIP function
test_is_private_ip_class_a {
	isPrivateIP("10.0.0.1")
}

test_is_private_ip_class_b {
	isPrivateIP("172.16.0.1")
}

test_is_private_ip_class_c {
	isPrivateIP("192.168.1.1")
}

test_is_not_private_ip {
	not isPrivateIP("8.8.8.8")
}

# Test equalsOrInArray function
test_equals_or_in_array_string_match {
	equalsOrInArray("allow", "allow")
}

test_equals_or_in_array_string_case_insensitive {
	equalsOrInArray("Allow", "allow")
}

test_equals_or_in_array_array_match {
	equalsOrInArray(["Allow", "Deny"], "allow")
}

test_equals_or_in_array_no_match {
	not equalsOrInArray("Deny", "allow")
}

# Test containsOrInArrayContains function
test_contains_or_in_array_contains_string {
	containsOrInArrayContains("allow-all", "allow")
}

test_contains_or_in_array_contains_array {
	containsOrInArrayContains(["allow-all", "deny-some"], "allow")
}

test_contains_or_in_array_contains_no_match {
	not containsOrInArrayContains("deny", "allow")
}

# Test get_statement function
test_get_statement_array {
	policy := {
		"Statement": [
			{"Effect": "Allow"},
			{"Effect": "Deny"},
		],
	}
	result := get_statement(policy)
	count(result) == 2
	result[0].Effect == "Allow"
}

test_get_statement_object {
	policy := {"Statement": {"Effect": "Allow"}}
	result := get_statement(policy)
	count(result) == 1
	result[0].Effect == "Allow"
}

# Test is_allow_effect function
test_is_allow_effect_with_allow {
	statement := {"Effect": "Allow"}
	is_allow_effect(statement)
}

test_is_allow_effect_lowercase {
	statement := {"effect": "Allow"}
	is_allow_effect(statement)
}

test_is_allow_effect_no_effect_field {
	statement := {"Action": "*"}
	is_allow_effect(statement)
}

test_is_not_allow_effect {
	statement := {"Effect": "Deny"}
	not is_allow_effect(statement)
}

# Test is_cross_account function
test_is_cross_account_string {
	statement := {"Principal": {"AWS": "arn:aws:iam::123456789012:root"}}
	is_cross_account(statement)
}

test_is_cross_account_array {
	statement := {"Principal": {"AWS": ["arn:aws:sts::123456789012:assumed-role/test"]}}
	is_cross_account(statement)
}

test_is_cross_account_account_id {
	statement := {"Principal": {"AWS": "123456789012"}}
	is_cross_account(statement)
}

test_is_not_cross_account {
	statement := {"Principal": {"AWS": "arn:aws:ec2::123456789012:instance/i-123"}}
	not is_cross_account(statement)
}

# Test is_assume_role function
test_is_assume_role_string {
	statement := {"Action": "sts:AssumeRole"}
	is_assume_role(statement)
}

test_is_assume_role_array {
	statement := {"Action": ["sts:AssumeRole", "sts:GetSessionToken"]}
	is_assume_role(statement)
}

test_is_not_assume_role {
	statement := {"Action": "s3:GetObject"}
	not is_assume_role(statement)
}

# Test has_external_id function
test_has_external_id_present {
	statement := {
		"Condition": {"StringEquals": {"sts:ExternalId": "external123"}},
	}
	has_external_id(statement)
}

test_has_external_id_absent {
	statement := {"Condition": {"StringEquals": {}}}
	not has_external_id(statement)
}

# Test has_mfa function
test_has_mfa_bool_if_exists {
	statement := {
		"Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "true"}},
	}
	has_mfa(statement)
}

test_has_mfa_bool {
	statement := {
		"Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
	}
	has_mfa(statement)
}

test_has_mfa_absent {
	statement := {"Condition": {}}
	not has_mfa(statement)
}

# Test any_principal function
test_any_principal_wildcard_string {
	statement := {"Principal": "*"}
	any_principal(statement)
}

test_any_principal_aws_wildcard_string {
	statement := {"Principal": {"AWS": "*"}}
	any_principal(statement)
}

test_any_principal_aws_wildcard_array {
	statement := {"Principal": {"AWS": ["*"]}}
	any_principal(statement)
}

test_any_principal_no_principal {
	statement := {"Effect": "Allow"}
	any_principal(statement)
}

test_not_any_principal {
	statement := {"Principal": {"AWS": "arn:aws:iam::123456789012:root"}}
	not any_principal(statement)
}

# Test valid_key function
test_valid_key_exists {
	obj := {"key1": "value1", "key2": "value2"}
	valid_key(obj, "key1")
}

test_valid_key_not_exists {
	obj := {"key1": "value1"}
	not valid_key(obj, "key2")
}

test_valid_key_null_value {
	obj := {"key1": null}
	not valid_key(obj, "key1")
}

# Test expired function
test_expired_past_date {
	# Date in the past: January 1, 2000
	expired([2000, 1, 1])
}

test_not_expired_future_date {
	# Date in the future: January 1, 2030
	not expired([2030, 1, 1])
}

# Test unsecured_cors_rule function
test_unsecured_cors_all_methods {
	methods := ["GET", "PUT", "POST", "DELETE", "HEAD"]
	headers := ["Content-Type"]
	origins := ["https://example.com"]
	unsecured_cors_rule(methods, headers, origins)
}

test_unsecured_cors_wildcard_headers {
	methods := ["GET"]
	headers := ["*"]
	origins := ["https://example.com"]
	unsecured_cors_rule(methods, headers, origins)
}

test_unsecured_cors_wildcard_origins {
	methods := ["GET"]
	headers := ["Content-Type"]
	origins := ["*"]
	unsecured_cors_rule(methods, headers, origins)
}

test_secured_cors_rule {
	methods := ["GET", "POST"]
	headers := ["Content-Type"]
	origins := ["https://example.com"]
	not unsecured_cors_rule(methods, headers, origins)
}

# Test is_ingress function
test_is_ingress_no_direction {
	firewall := {"protocol": "tcp"}
	is_ingress(firewall)
}

test_is_ingress_explicit {
	firewall := {"direction": "INGRESS"}
	is_ingress(firewall)
}

test_is_not_ingress {
	firewall := {"direction": "EGRESS"}
	not is_ingress(firewall)
}

# Test is_recommended_tls function
test_is_recommended_tls_2018 {
	is_recommended_tls("TLSv1.2_2018")
}

test_is_recommended_tls_2019 {
	is_recommended_tls("TLSv1.2_2019")
}

test_is_recommended_tls_2021 {
	is_recommended_tls("TLSv1.2_2021")
}

test_is_not_recommended_tls {
	not is_recommended_tls("TLSv1.0")
}

# Test is_unrestricted function
test_is_unrestricted_ipv4 {
	is_unrestricted("0.0.0.0/0")
}

test_is_unrestricted_ipv6 {
	is_unrestricted("::/0")
}

test_is_not_unrestricted {
	not is_unrestricted("10.0.0.0/16")
}

# Test check_principals function
test_check_principals_identifiers {
	statement := {
		"principals": {
			"identifiers": ["*"],
			"type": "AWS",
		},
	}
	check_principals(statement)
}

test_check_principals_object {
	statement := {"Principal": {"AWS": "*"}}
	check_principals(statement)
}

test_check_principals_string {
	statement := {"Principal": "*"}
	check_principals(statement)
}

test_check_principals_no_wildcard {
	statement := {"Principal": {"AWS": "arn:aws:iam::123456789012:root"}}
	not check_principals(statement)
}

# Test check_actions function
test_check_actions_lowercase_array {
	statement := {"actions": ["s3:GetObject", "s3:PutObject"]}
	check_actions(statement, "s3:GetObject")
}

test_check_actions_uppercase_array {
	statement := {"Actions": ["s3:GetObject"]}
	check_actions(statement, "s3:GetObject")
}

test_check_actions_wildcard {
	statement := {"Action": "*"}
	check_actions(statement, "s3:GetObject")
}

test_check_actions_no_match {
	statement := {"Action": ["s3:GetObject"]}
	not check_actions(statement, "s3:PutObject")
}

# Test has_wildcard function
test_has_wildcard_principals {
	statement := {"Principal": "*", "Action": "s3:GetObject"}
	has_wildcard(statement, "s3:GetObject")
}

test_has_wildcard_actions {
	statement := {
		"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
		"Action": "*",
	}
	has_wildcard(statement, "s3:GetObject")
}

# Test isOSDir function
test_is_os_dir_root {
	isOSDir("/")
}

test_is_os_dir_bin {
	isOSDir("/bin")
}

test_is_os_dir_etc {
	isOSDir("/etc")
}

test_is_os_dir_nested {
	isOSDir("/etc/config")
}

test_is_not_os_dir {
	not isOSDir("/app")
}

# Test compareArrays function
test_compare_arrays_match {
	arrayOne := ["Allow", "Deny"]
	arrayTwo := ["allow", "deny"]
	compareArrays(arrayOne, arrayTwo)
}

test_compare_arrays_no_match {
	arrayOne := ["Allow"]
	arrayTwo := ["Deny"]
	not compareArrays(arrayOne, arrayTwo)
}

# Test weakCipher function with IANA format
test_weak_cipher_iana_null {
	weakCipher("TLS_NULL_WITH_NULL_NULL")
}

test_weak_cipher_iana_rc4 {
	weakCipher("TLS_RSA_WITH_RC4_128_MD5")
}

test_weak_cipher_iana_des {
	weakCipher("TLS_RSA_WITH_DES_CBC_SHA")
}

# Test weakCipher function with OpenSSL format
test_weak_cipher_openssl_null {
	weakCipher("NULL-MD5")
}

test_weak_cipher_openssl_des {
	weakCipher("DES-CBC3-SHA")
}

test_weak_cipher_openssl_rc4 {
	weakCipher("AES128-SHA")
}

# Test weakCipher function with GnuTLS format
test_weak_cipher_gnutls_null {
	weakCipher("TLS_RSA_NULL_MD5")
}

test_weak_cipher_gnutls_arcfour {
	weakCipher("TLS_RSA_ARCFOUR_128_MD5")
}

test_weak_cipher_gnutls_des {
	weakCipher("TLS_RSA_3DES_EDE_CBC_SHA1")
}

# Test as_array function
test_as_array_with_array {
	input := ["a", "b", "c"]
	result := as_array(input)
	count(result) == 3
	result[0] == "a"
}

test_as_array_with_single_value {
	result := as_array("value")
	count(result) == 1
	result[0] == "value"
}

test_as_array_with_number {
	result := as_array(42)
	count(result) == 1
	result[0] == 42
}

# Test contains_element function
test_contains_element_found {
	arr := ["a", "b", "c"]
	contains_element(arr, "b")
}

test_contains_element_not_found {
	arr := ["a", "b", "c"]
	not contains_element(arr, "d")
}

# Test contains_with_size function
test_contains_with_size_found {
	arr := ["allow-all", "deny-some"]
	contains_with_size(arr, "allow")
}

test_contains_with_size_not_found {
	arr := ["deny-all", "deny-some"]
	not contains_with_size(arr, "allow")
}

test_contains_with_size_empty_array {
	arr := []
	not contains_with_size(arr, "allow")
}

# Test get_tag_name_if_exists function
test_get_tag_name_tags_field {
	resource := {"tags": {"Name": "my-resource"}}
	result := get_tag_name_if_exists(resource)
	result == "my-resource"
}

test_get_tag_name_properties_tags_array {
	resource := {
		"Properties": {"Tags": [
			{"Key": "Environment", "Value": "prod"},
			{"Key": "Name", "Value": "my-bucket"},
		]},
	}
	result := get_tag_name_if_exists(resource)
	result == "my-bucket"
}

test_get_tag_name_properties_tags_object {
	resource := {
		"Properties": {"Tags": {
			"Environment": "prod",
			"Name": "my-resource",
		}},
	}
	result := get_tag_name_if_exists(resource)
	result == "my-resource"
}

# Test json_unmarshal function
test_json_unmarshal_object {
	obj := {"key": "value"}
	result := json_unmarshal(obj)
	result.key == "value"
}

test_json_unmarshal_array {
	arr := ["a", "b", "c"]
	result := json_unmarshal(arr)
	count(result) == 3
}

test_json_unmarshal_null {
	result := json_unmarshal(null)
	is_object(result)
}

test_json_unmarshal_json_string {
	str := "{\"key\":\"value\"}"
	result := json_unmarshal(str)
	result.key == "value"
}

# Test get_encryption_if_exists function
test_get_encryption_encrypted_true {
	resource := {"encrypted": true}
	result := get_encryption_if_exists(resource)
	result == "encrypted"
}

test_get_encryption_with_key {
	resource := {"kms_master_key_id": "arn:aws:kms:..."}
	result := get_encryption_if_exists(resource)
	result == "encrypted"
}

test_get_encryption_unencrypted {
	resource := {"name": "my-resource"}
	result := get_encryption_if_exists(resource)
	result == "unencrypted"
}
