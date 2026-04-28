package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	document := input.document[i]
	resources := {"aws_sns_topic", "aws_sns_topic_policy"}
	resource := document.resource[resources[r]][name]
	policy := resource.policy

	validate_json(policy)

	pol := common_lib.json_unmarshal(policy)
	st := common_lib.get_statement(pol)
	statement := st[idx]

	common_lib.is_allow_effect(statement)
	statement.NotAction

	result := {
		"documentId": document.id,
		"resourceType": resources[r],
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].policy.Statement[%d].NotAction", [resources[r], name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s[%s].policy shouldn't have 'Effect: Allow' and 'NotAction' simultaneously", [resources[r], name]),
		"keyActualValue": sprintf("%s[%s].policy has 'Effect: Allow' and 'NotAction' simultaneously", [resources[r], name]),
		"searchLine": common_lib.build_search_line(["resource", resources[r], name, "policy", "Statement", idx, "NotAction"], []),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_sns_topic_policy", "policy")

	policy := module[keyToCheck]

	validate_json(policy)

	pol := common_lib.json_unmarshal(policy)
	st := common_lib.get_statement(pol)
	statement := st[idx]

	common_lib.is_allow_effect(statement)
	statement.NotAction

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.Statement[%d].NotAction", [name, keyToCheck, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].policy shouldn't have 'Effect: Allow' and 'NotAction' simultaneously", [name]),
		"keyActualValue": sprintf("module[%s].policy has 'Effect: Allow' and 'NotAction' simultaneously", [name]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck, "Statement", idx, "NotAction"], []),
	}
}

validate_json(string) {
	not startswith(string, "$")
}
