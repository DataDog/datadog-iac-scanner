package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_db_security_group[name].ingress
	hosts := split(resource.cidr, "/")
	to_number(hosts[1]) <= 24

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_db_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_db_security_group[%s].ingress.cidr", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'aws_db_security_group.ingress.cidr' > 24",
		"keyActualValue": "'aws_db_security_group.ingress.cidr' <= 24",
	}
}

#######################################################################################################
# aws_security_group support (aws_db_security_group is deprecated)
#######################################################################################################

CxPolicy[result] {
	resource := input.document[i].resource.aws_security_group[name]

	cidr := resource.ingress.cidr_blocks[j]
	hosts := split(cidr, "/")
	to_number(hosts[1]) <= 24

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_security_group[%s].ingress.cidr_blocks", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'aws_security_group.ingress.cidr_blocks' CIDR prefix > 24",
		"keyActualValue": sprintf("'aws_security_group.ingress.cidr_blocks' contains '%s' with prefix <= 24", [cidr]),
		"searchLine": common_lib.build_search_line(["resource", "aws_security_group", name, "ingress", "cidr_blocks", j], []),
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_security_group[name]

	cidr := resource.ingress[idx].cidr_blocks[j]
	hosts := split(cidr, "/")
	to_number(hosts[1]) <= 24

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_security_group[%s].ingress[%d].cidr_blocks", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'aws_security_group.ingress.cidr_blocks' CIDR prefix > 24",
		"keyActualValue": sprintf("'aws_security_group.ingress.cidr_blocks' contains '%s' with prefix <= 24", [cidr]),
		"searchLine": common_lib.build_search_line(["resource", "aws_security_group", name, "ingress", idx, "cidr_blocks", j], []),
	}
}
