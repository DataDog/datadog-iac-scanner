package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_elasticsearch_domain_policy[name]

	policy := common_lib.json_unmarshal(resource.access_policies)
	st := common_lib.get_statement(policy)
	statement := st[idx]

	common_lib.is_allow_effect(statement)
	not common_lib.valid_key(statement, "Condition")
	common_lib.has_wildcard(statement, "es:*")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_elasticsearch_domain_policy",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_elasticsearch_domain_policy[%s].access_policies.Statement[%d]", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("aws_elasticsearch_domain_policy[%s].access_policies should not have wildcard in 'Action' and 'Principal'", [name]),
		"keyActualValue": sprintf("aws_elasticsearch_domain_policy[%s].access_policies has wildcard in 'Action' or 'Principal'", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_elasticsearch_domain_policy", name, "access_policies", "Statement", idx], []),
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_elasticsearch_domain_policy", "access_policies")

	policy := common_lib.json_unmarshal(module[keyToCheck])
	st := common_lib.get_statement(policy)
	statement := st[idx]

	common_lib.is_allow_effect(statement)
	not common_lib.valid_key(statement, "Condition")
	common_lib.has_wildcard(statement, "es:*")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.Statement[%d]", [name, keyToCheck, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s should not have wildcard in 'Action' and 'Principal'", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s has wildcard in 'Action' or 'Principal'", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck, "Statement", idx], []),
	}
}
