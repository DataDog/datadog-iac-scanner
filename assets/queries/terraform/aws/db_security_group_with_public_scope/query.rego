package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

public_cidrs := {"0.0.0.0/0", "::/0"}

# Single ingress with cidr field
CxPolicy[result] {
	resource := input.document[i].resource.aws_db_security_group[name]
	cidrValue := public_cidrs[_]
	resource.ingress.cidr == cidrValue

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_db_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_db_security_group[%s].ingress.cidr", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'aws_db_security_group[%s].ingress.cidr' should not be '0.0.0.0/0' or '::/0'", [name]),
		"keyActualValue": sprintf("'aws_db_security_group[%s].ingress.cidr' is '%s'", [name, resource.ingress.cidr]),
	}
}

# Array ingress with cidr field
CxPolicy[result] {
	resource := input.document[i].resource.aws_db_security_group[name]
	cidrValue := public_cidrs[_]
	resource.ingress[idx].cidr == cidrValue

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_db_security_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_db_security_group[%s].ingress[%d].cidr", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'aws_db_security_group[%s].ingress[%d].cidr' should not be '0.0.0.0/0' or '::/0'", [name, idx]),
		"keyActualValue": sprintf("'aws_db_security_group[%s].ingress[%d].cidr' is '%s'", [name, idx, resource.ingress[idx].cidr]),
	}
}

#######################################################################################################
# Module support
#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_security_group", "ingress")
	cidrValue := public_cidrs[_]
	module[keyToCheck][j].cidr == cidrValue

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s[%s].cidr", [name, keyToCheck, j]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'module[%s].%s.cidr' should not be '0.0.0.0/0' or '::/0'", [name, keyToCheck]),
		"keyActualValue": sprintf("'module[%s].%s.cidr' is '%s'", [name, keyToCheck, module[keyToCheck][j].cidr]),
	}
}
