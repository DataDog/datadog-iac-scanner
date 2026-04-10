package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_db_security_group[name].ingress
	resource.cidr == "0.0.0.0/0"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_db_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_db_security_group[%s].ingress.cidr", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'aws_db_security_group.ingress.cidr' != 0.0.0.0/0",
		"keyActualValue": "'aws_db_security_group.ingress.cidr'= 0.0.0.0/0",
	}
}

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
		"keyActualValue": sprintf("'module[%s].%s.cidr'= 0.0.0.0/0", [name, keyToCheck]),
	}
}

#######################################################################################################
# aws_security_group support (aws_db_security_group is deprecated)
#######################################################################################################

CxPolicy[result] {
	resource := input.document[i].resource.aws_security_group[name]

	contains(resource.ingress.cidr_blocks[j], "0.0.0.0/0")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_security_group[%s].ingress.cidr_blocks", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'aws_security_group.ingress.cidr_blocks' != 0.0.0.0/0",
		"keyActualValue": "'aws_security_group.ingress.cidr_blocks' contains 0.0.0.0/0",
		"searchLine": common_lib.build_search_line(["resource", "aws_security_group", name, "ingress", "cidr_blocks", j], []),
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_security_group[name]

	contains(resource.ingress[idx].cidr_blocks[j], "0.0.0.0/0")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_security_group[%s].ingress[%d].cidr_blocks", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'aws_security_group.ingress.cidr_blocks' != 0.0.0.0/0",
		"keyActualValue": "'aws_security_group.ingress.cidr_blocks' contains 0.0.0.0/0",
		"searchLine": common_lib.build_search_line(["resource", "aws_security_group", name, "ingress", idx, "cidr_blocks", j], []),
	}
}
