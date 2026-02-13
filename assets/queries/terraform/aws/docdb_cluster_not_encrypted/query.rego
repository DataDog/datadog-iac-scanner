package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_docdb_cluster[name]
	not common_lib.valid_key(resource, "storage_encrypted")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_docdb_cluster",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_docdb_cluster[{{%s}}]", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_docdb_cluster", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_docdb_cluster.storage_encrypted should be set to true",
		"keyActualValue": "aws_docdb_cluster.storage_encrypted is missing",
		"remediation": "storage_encrypted = true",
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_docdb_cluster[name]
	resource.storage_encrypted == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_docdb_cluster",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_docdb_cluster[{{%s}}].storage_encrypted", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_docdb_cluster", name,"storage_encrypted"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_docdb_cluster.storage_encrypted should be set to true",
		"keyActualValue": "aws_docdb_cluster.storage_encrypted is set to false",
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
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_docdb_cluster", "storage_encrypted")
	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"searchLine": common_lib.build_search_line(["module", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s should be set to true", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is missing", [name, keyToCheck]),
		"remediation": sprintf("%s = true", [keyToCheck]),
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_docdb_cluster", "storage_encrypted")
	module[keyToCheck] == false

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
