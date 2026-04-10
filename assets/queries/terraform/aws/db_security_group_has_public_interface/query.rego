package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_db_security_group[name]

	cidrs := {"0.0.0.0/0", "::/0"}
	cidrValue := cidrs[_]

	resource.ingress.cidr == cidrValue

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_db_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_db_security_group[%s].ingress.cidr", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'aws_db_security_group[%s].ingress.cidr' should not be '0.0.0.0/0' or '::/0'", [name]),
		"keyActualValue": sprintf("'aws_db_security_group[%s].ingress.cidr' is '%s'", [name, resource.ingress.cidr]),
		"searchLine": common_lib.build_search_line(["resource", "aws_db_security_group", name, "ingress", "cidr"], []),
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_db_security_group[name]

	cidrs := {"0.0.0.0/0", "::/0"}
	cidrValue := cidrs[_]

	resource.ingress[idx].cidr == cidrValue

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_db_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_db_security_group[%s].ingress[%d].cidr", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'aws_db_security_group[%s].ingress[%d].cidr' should not be '0.0.0.0/0' or '::/0'", [name, idx]),
		"keyActualValue": sprintf("'aws_db_security_group[%s].ingress[%d].cidr' is '%s'", [name, idx, resource.ingress[idx].cidr]),
		"searchLine": common_lib.build_search_line(["resource", "aws_db_security_group", name, "ingress", idx, "cidr"], []),
	}
}

#######################################################################################################
# aws_security_group support (aws_db_security_group is deprecated)
#######################################################################################################

CxPolicy[result] {
	resource := input.document[i].resource.aws_security_group[name]

	cidrs := {"0.0.0.0/0", "::/0"}
	cidrValue := cidrs[_]

	contains(resource.ingress.cidr_blocks[j], cidrValue)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_security_group[%s].ingress.cidr_blocks", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'aws_security_group[%s].ingress.cidr_blocks' should not contain '0.0.0.0/0' or '::/0'", [name]),
		"keyActualValue": sprintf("'aws_security_group[%s].ingress.cidr_blocks' contains '%s'", [name, cidrValue]),
		"searchLine": common_lib.build_search_line(["resource", "aws_security_group", name, "ingress", "cidr_blocks", j], []),
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_security_group[name]

	cidrs := {"0.0.0.0/0", "::/0"}
	cidrValue := cidrs[_]

	contains(resource.ingress[idx].cidr_blocks[j], cidrValue)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_security_group[%s].ingress[%d].cidr_blocks", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'aws_security_group[%s].ingress[%d].cidr_blocks' should not contain '0.0.0.0/0' or '::/0'", [name, idx]),
		"keyActualValue": sprintf("'aws_security_group[%s].ingress[%d].cidr_blocks' contains '%s'", [name, idx, cidrValue]),
		"searchLine": common_lib.build_search_line(["resource", "aws_security_group", name, "ingress", idx, "cidr_blocks", j], []),
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_security_group[name]

	contains(resource.ingress.ipv6_cidr_blocks[j], "::/0")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_security_group[%s].ingress.ipv6_cidr_blocks", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'aws_security_group[%s].ingress.ipv6_cidr_blocks' should not contain '::/0'", [name]),
		"keyActualValue": sprintf("'aws_security_group[%s].ingress.ipv6_cidr_blocks' contains '::/0'", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_security_group", name, "ingress", "ipv6_cidr_blocks", j], []),
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_security_group[name]

	contains(resource.ingress[idx].ipv6_cidr_blocks[j], "::/0")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_security_group[%s].ingress[%d].ipv6_cidr_blocks", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'aws_security_group[%s].ingress[%d].ipv6_cidr_blocks' should not contain '::/0'", [name, idx]),
		"keyActualValue": sprintf("'aws_security_group[%s].ingress[%d].ipv6_cidr_blocks' contains '::/0'", [name, idx]),
		"searchLine": common_lib.build_search_line(["resource", "aws_security_group", name, "ingress", idx, "ipv6_cidr_blocks", j], []),
	}
}
