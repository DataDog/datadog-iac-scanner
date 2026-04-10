package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

resource_type := {"aws_sns_topic", "aws_sns_topic_policy"}

CxPolicy[result] {
	res_type := resource_type[_]
	resource := input.document[i].resource[res_type][name]

	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[_]

	common_lib.is_allow_effect(statement)
	tf_lib.anyPrincipal(statement)

	result := {
		"documentId": input.document[i].id,
		"resourceType": res_type,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].policy", [res_type, name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'Statement.Principal.AWS' shouldn't contain '*'",
		"keyActualValue": "'Statement.Principal.AWS' contains '*'",
		"searchLine": common_lib.build_search_line(["resource", res_type, name, "policy"], []),
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_sns_topic", "policy")

	policy := common_lib.json_unmarshal(module[keyToCheck])
	st := common_lib.get_statement(policy)
	statement := st[_]

	common_lib.is_allow_effect(statement)
	tf_lib.anyPrincipal(statement)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'Statement.Principal.AWS' shouldn't contain '*'",
		"keyActualValue": "'Statement.Principal.AWS' contains '*'",
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck], []),
	}
}
