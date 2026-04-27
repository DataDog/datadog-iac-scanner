package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

resources := {"aws_s3_bucket_policy", "aws_s3_bucket"}

# CxPolicy 1: actively wrong statement (Allow+SecureTransport:false or Deny+SecureTransport:true)
# — pinpoint the specific offending Condition.
CxPolicy[result] {
	resourceType := resources[r]
	resource := input.document[i].resource[resourceType][name]

	policy_unmarshaled := common_lib.json_unmarshal(resource.policy)
	not deny_http_requests(policy_unmarshaled)

	st := common_lib.get_statement(policy_unmarshaled)
	statement := st[idx]
	check_action(statement)
	actively_wrong(statement)

	result := {
		"documentId": input.document[i].id,
		"resourceType": resourceType,
		"resourceName": tf_lib.resolve_s3_bucket_name(resource, name),
		"searchKey": sprintf("%s[%s].policy.Statement[%d].Condition.Bool.aws:SecureTransport", [resourceType, name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s[%s].policy should not accept HTTP Requests", [resourceType, name]),
		"keyActualValue": sprintf("%s[%s].policy accepts HTTP Requests", [resourceType, name]),
		"searchLine": common_lib.build_search_line(["resource", resourceType, name, "policy", "Statement", idx, "Condition", "Bool", "aws:SecureTransport"], []),
	}
}

# CxPolicy 2: policy-level absence of HTTPS enforcement (no actively wrong statement either).
CxPolicy[result] {
	resourceType := resources[r]
	resource := input.document[i].resource[resourceType][name]

	policy_unmarshaled := common_lib.json_unmarshal(resource.policy)
	not deny_http_requests(policy_unmarshaled)
	not has_actively_wrong(policy_unmarshaled)

	result := {
		"documentId": input.document[i].id,
		"resourceType": resourceType,
		"resourceName": tf_lib.resolve_s3_bucket_name(resource, name),
		"searchKey": sprintf("%s[%s].policy", [resourceType, name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s[%s].policy should not accept HTTP Requests", [resourceType, name]),
		"keyActualValue": sprintf("%s[%s].policy accepts HTTP Requests", [resourceType, name]),
		"searchLine": common_lib.build_search_line(["resource", resourceType, name, "policy"], []),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	resourceType := resources[r]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, resourceType, "policy")

	policy := module[keyToCheck]

	policy_unmarshaled := common_lib.json_unmarshal(policy)
	not deny_http_requests(policy_unmarshaled)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'policy' should not accept HTTP Requests",
		"keyActualValue": "'policy' accepts HTTP Requests",
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck], []),
	}
}

any_s3_action(action) {
	any([action == "*", startswith(action, "s3:")])
}
check_action(st) {
	is_string(st.Action)
	any_s3_action(st.Action)
} else {
	any_s3_action(st.Action[a])
} else {
	is_string(st.Actions)
	any_s3_action(st.Actions)
} else {
	any_s3_action(st.Actions[a])
}

is_equal(secure, target)
{
    secure == target
}else {
    secure[_]==target
}

deny_http_requests(policyValue) {
    st := common_lib.get_statement(policyValue)
    statement := st[_]
    check_action(statement)
    statement.Effect == "Deny"
    is_equal(statement.Condition.Bool["aws:SecureTransport"], "false")
} else {
    st := common_lib.get_statement(policyValue)
    statement := st[_]
    check_action(statement)
    statement.Effect == "Allow"
    is_equal(statement.Condition.Bool["aws:SecureTransport"], "true")
}

# An actively wrong statement is one that explicitly permits HTTP or denies HTTPS.
actively_wrong(statement) {
    statement.Effect == "Allow"
    is_equal(statement.Condition.Bool["aws:SecureTransport"], "false")
} else {
    statement.Effect == "Deny"
    is_equal(statement.Condition.Bool["aws:SecureTransport"], "true")
}

has_actively_wrong(policyValue) {
    st := common_lib.get_statement(policyValue)
    statement := st[_]
    check_action(statement)
    actively_wrong(statement)
}
