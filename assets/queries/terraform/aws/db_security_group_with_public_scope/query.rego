package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

resource_types := {"aws_db_security_group", "aws_security_group"}

# Single ingress with cidr field (aws_db_security_group)
CxPolicy[result] {
	res_type := resource_types[_]
	resource := input.document[i].resource[res_type][name]
	resource.ingress.cidr == "0.0.0.0/0"

	result := {
		"documentId": input.document[i].id,
		"resourceType": res_type,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].ingress.cidr", [res_type, name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s[%s].ingress.cidr' != 0.0.0.0/0", [res_type, name]),
		"keyActualValue": sprintf("'%s[%s].ingress.cidr' = 0.0.0.0/0", [res_type, name]),
	}
}

# Single ingress with cidr_blocks field (aws_security_group)
CxPolicy[result] {
	res_type := resource_types[_]
	resource := input.document[i].resource[res_type][name]
	contains(resource.ingress.cidr_blocks[j], "0.0.0.0/0")

	result := {
		"documentId": input.document[i].id,
		"resourceType": res_type,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].ingress.cidr_blocks", [res_type, name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s[%s].ingress.cidr_blocks' != 0.0.0.0/0", [res_type, name]),
		"keyActualValue": sprintf("'%s[%s].ingress.cidr_blocks' contains 0.0.0.0/0", [res_type, name]),
		"searchLine": common_lib.build_search_line(["resource", res_type, name, "ingress", "cidr_blocks", j], []),
	}
}

# Array ingress with cidr_blocks field (aws_security_group)
CxPolicy[result] {
	res_type := resource_types[_]
	resource := input.document[i].resource[res_type][name]
	contains(resource.ingress[idx].cidr_blocks[j], "0.0.0.0/0")

	result := {
		"documentId": input.document[i].id,
		"resourceType": res_type,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].ingress[%d].cidr_blocks", [res_type, name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s[%s].ingress[%d].cidr_blocks' != 0.0.0.0/0", [res_type, name, idx]),
		"keyActualValue": sprintf("'%s[%s].ingress[%d].cidr_blocks' contains 0.0.0.0/0", [res_type, name, idx]),
		"searchLine": common_lib.build_search_line(["resource", res_type, name, "ingress", idx, "cidr_blocks", j], []),
	}
}

#######################################################################################################
# Module support
#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_security_group", "ingress")
	module[keyToCheck][j].cidr == "0.0.0.0/0"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s[%s].cidr", [name, keyToCheck, j]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'module[%s].%s.cidr' != 0.0.0.0/0", [name, keyToCheck]),
		"keyActualValue": sprintf("'module[%s].%s.cidr' = 0.0.0.0/0", [name, keyToCheck]),
	}
}
