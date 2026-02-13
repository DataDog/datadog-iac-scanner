package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_elasticache_replication_group[name]

	not common_lib.valid_key(resource, "at_rest_encryption_enabled")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_elasticache_replication_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_elasticache_replication_group[%s]", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_elasticache_replication_group", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "The attribute 'at_rest_encryption_enabled' should be set to true",
		"keyActualValue": "The attribute 'at_rest_encryption_enabled' is undefined",
		"remediation": "at_rest_encryption_enabled = true",
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_elasticache_replication_group[name]

	resource.at_rest_encryption_enabled != true

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_elasticache_replication_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_elasticache_replication_group[%s].at_rest_encryption_enabled", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_elasticache_replication_group", name, "at_rest_encryption_enabled"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "The attribute 'at_rest_encryption_enabled' should be set to true",
		"keyActualValue": "The attribute 'at_rest_encryption_enabled' is not set to true",
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_elasticache_replication_group", "at_rest_encryption_enabled")

	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"searchLine": common_lib.build_search_line(["module", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s should be set to true", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is undefined", [name, keyToCheck]),
		"remediation": sprintf("%s = true", [keyToCheck]),
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_elasticache_replication_group", "at_rest_encryption_enabled")

	module[keyToCheck] != true

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s should be set to true", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is not set to true", [name, keyToCheck]),
		"remediation": json.marshal({
			"before": sprintf("%s", [module[keyToCheck]]),
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}
