package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.alicloud_oss_bucket[name]
	policy := resource.policy

	not is_secure_transport(policy)

	policy_doc := common_lib.json_unmarshal(policy)
	st := common_lib.get_statement(policy_doc)
	statement := st[idx]

	statement.Effect == "Allow"
	tf_lib.anyPrincipal(statement)
	is_equal(statement.Condition.Bool["acs:SecureTransport"], "false")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "alicloud_oss_bucket",
		"resourceName": tf_lib.get_specific_resource_name(resource, "alicloud_oss_bucket", name),
		"searchKey": sprintf("alicloud_oss_bucket[%s].policy.Statement[%d].Condition.Bool.acs:SecureTransport", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s[%s].policy should not accept HTTP Requests", [name, name]),
		"keyActualValue": sprintf("%s[%s].policy accepts HTTP Requests", [name, name]),
		"searchLine": common_lib.build_search_line(["resource", "alicloud_oss_bucket", name, "policy", "Statement", idx, "Condition", "Bool", "acs:SecureTransport"], []),
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.alicloud_oss_bucket[name]
	policy := resource.policy

	not is_secure_transport(policy)
	not has_actively_wrong_statement(policy)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "alicloud_oss_bucket",
		"resourceName": tf_lib.get_specific_resource_name(resource, "alicloud_oss_bucket", name),
		"searchKey": sprintf("alicloud_oss_bucket[%s].policy", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("%s[%s].policy should not accept HTTP Requests", [name, name]),
		"keyActualValue": sprintf("%s[%s].policy accepts HTTP Requests", [name, name]),
		"searchLine": common_lib.build_search_line(["resource", "alicloud_oss_bucket", name, "policy"], []),
	}
}

has_actively_wrong_statement(policyValue) {
	policy := common_lib.json_unmarshal(policyValue)
	st := common_lib.get_statement(policy)
	statement := st[_]
	statement.Effect == "Allow"
	tf_lib.anyPrincipal(statement)
	is_equal(statement.Condition.Bool["acs:SecureTransport"], "false")
}

is_equal(secure, target) {
	secure == target
} else {
	secure[_] == target
}

is_secure_transport(policyValue) {
	policy := common_lib.json_unmarshal(policyValue)
	st := common_lib.get_statement(policy)
	statement := st[_]
	statement.Effect == "Deny"
	is_equal(statement.Condition.Bool["acs:SecureTransport"], "false")
	tf_lib.anyPrincipal(statement)
} else {
	policy := common_lib.json_unmarshal(policyValue)
	st := common_lib.get_statement(policy)
	statement := st[_]
	statement.Effect == "Allow"
	is_equal(statement.Condition.Bool["acs:SecureTransport"], "true")
	tf_lib.anyPrincipal(statement)
}
