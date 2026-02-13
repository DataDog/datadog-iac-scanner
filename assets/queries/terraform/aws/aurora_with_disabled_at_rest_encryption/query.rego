package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_rds_cluster[name]
	resource.storage_encrypted == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_rds_cluster",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_rds_cluster[{{%s}}].storage_encrypted", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_rds_cluster.storage_encrypted should be set to 'true'",
		"keyActualValue": "aws_rds_cluster.storage_encrypted is set to 'false'",
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_rds_cluster[name]
	not common_lib.valid_key(resource, "storage_encrypted")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_rds_cluster",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_rds_cluster[{{%s}}]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_rds_cluster.storage_encrypted should be defined and set to 'true'",
		"keyActualValue": "aws_rds_cluster.storage_encrypted is undefined",
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_rds_cluster", "storage_encrypted")

	module[keyToCheck] == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s should be set to 'true'", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is set to 'false'", [name, keyToCheck]),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_rds_cluster", "storage_encrypted")

	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s should be defined and set to 'true'", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is undefined", [name, keyToCheck]),
	}
}
