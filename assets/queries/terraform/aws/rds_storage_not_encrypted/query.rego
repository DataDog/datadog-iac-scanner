package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	cluster := input.document[i].resource.aws_rds_cluster[name]

	not is_serverless(cluster)
	not common_lib.valid_key(cluster, "storage_encrypted")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_rds_cluster",
		"resourceName": tf_lib.get_resource_name(cluster, name),
		"searchKey": sprintf("aws_rds_cluster[%s]", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_rds_cluster", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_rds_cluster.storage_encrypted should be set to true",
		"keyActualValue": "aws_rds_cluster.storage_encrypted is undefined",
		"remediation": "storage_encrypted = true",
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	cluster := input.document[i].resource.aws_rds_cluster[name]

	cluster.storage_encrypted != true

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_rds_cluster",
		"resourceName": tf_lib.get_resource_name(cluster, name),
		"searchKey": sprintf("aws_rds_cluster[%s].storage_encrypted", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_rds_cluster", name, "storage_encrypted"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_rds_cluster.storage_encrypted should be set to true",
		"keyActualValue": "aws_rds_cluster.storage_encrypted is set to false",
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
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_rds_cluster", "storage_encrypted")

	not is_serverless(module)
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
		"remediation": sprintf("module[%s].%s = true", [name, keyToCheck]),
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_rds_cluster", "storage_encrypted")

	module[keyToCheck] != true

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s should be set to true", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is set to false", [name, keyToCheck]),
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}

is_serverless(cluster) {
	cluster.engine_mode == "serverless"
} else {
	keyToCheck := common_lib.get_module_equivalent_key("aws", cluster.source, "aws_rds_cluster", "engine_mode")
	cluster[keyToCheck] == "serverless"
}
