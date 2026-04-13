package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Single ingress with cidr field
CxPolicy[result] {
	resource := input.document[i].resource.aws_db_security_group[name]
	hosts := split(resource.ingress.cidr, "/")
	to_number(hosts[1]) <= 24

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_db_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_db_security_group[%s].ingress.cidr", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'aws_db_security_group[%s].ingress.cidr' CIDR prefix > 24", [name]),
		"keyActualValue": sprintf("'aws_db_security_group[%s].ingress.cidr' CIDR prefix <= 24", [name]),
	}
}

# Array ingress with cidr field
CxPolicy[result] {
	resource := input.document[i].resource.aws_db_security_group[name]
	hosts := split(resource.ingress[idx].cidr, "/")
	to_number(hosts[1]) <= 24

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_db_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_db_security_group[%s].ingress[%d].cidr", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'aws_db_security_group[%s].ingress[%d].cidr' CIDR prefix > 24", [name, idx]),
		"keyActualValue": sprintf("'aws_db_security_group[%s].ingress[%d].cidr' CIDR prefix <= 24", [name, idx]),
	}
}
