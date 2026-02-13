package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_elasticache_replication_group[name]

	not common_lib.valid_key(resource, "transit_encryption_enabled")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_elasticache_replication_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_elasticache_replication_group[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "The attribute 'transit_encryption_enabled' should be set to true",
		"keyActualValue": "The attribute 'transit_encryption_enabled' is undefined",
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_elasticache_replication_group[name]

	resource.transit_encryption_enabled != true

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_elasticache_replication_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_elasticache_replication_group[%s].transit_encryption_enabled", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "The attribute 'transit_encryption_enabled' should be set to true",
		"keyActualValue": "The attribute 'transit_encryption_enabled' is not set to true",
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_elasticache_replication_group", "transit_encryption_enabled")
	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s should be set to true", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is undefined", [name, keyToCheck]),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_elasticache_replication_group", "transit_encryption_enabled")
	module[keyToCheck] != true

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s should be set to true", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is not set to true", [name, keyToCheck]),
	}
}
