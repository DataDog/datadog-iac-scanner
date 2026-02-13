package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_dax_cluster[name]
	resource.server_side_encryption.enabled == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dax_cluster",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dax_cluster[{{%s}}].server_side_encryption.enabled", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_dax_cluster", name,"server_side_encryption","enabled"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_dax_cluster.server_side_encryption.enabled should be set to true",
		"keyActualValue": "aws_dax_cluster.server_side_encryption.enabled is set to false",
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_dax_cluster[name]
	not common_lib.valid_key(resource, "server_side_encryption")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dax_cluster",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dax_cluster[{{%s}}]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_dax_cluster.server_side_encryption.enabled should be set to true",
		"keyActualValue": "aws_dax_cluster.server_side_encryption is missing",
		"remediation": "server_side_encryption {\n\tenabled = true\n\t}",
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_dax_cluster[name]
	common_lib.valid_key(resource, "server_side_encryption")
	not common_lib.valid_key(resource.server_side_encryption, "enabled")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dax_cluster",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dax_cluster[{{%s}}].server_side_encryption", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_dax_cluster.server_side_encryption.enabled should be set to true",
		"keyActualValue": "aws_dax_cluster.server_side_encryption.enabled is missing",
		"remediation": "enabled = true",
		"remediationType": "addition",
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_dax_cluster", "server_side_encryption")
	module[keyToCheck].enabled == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.enabled", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck,"enabled"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s.enabled should be set to true", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s.enabled is set to false", [name, keyToCheck]),
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_dax_cluster", "server_side_encryption")
	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s.enabled should be set to true", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is missing", [name, keyToCheck]),
		"remediation": sprintf("%s {\n\tenabled = true\n\t}", [keyToCheck]),
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_dax_cluster", "server_side_encryption")
	common_lib.valid_key(module, keyToCheck)
	not common_lib.valid_key(module[keyToCheck], "enabled")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s.enabled should be set to true", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s.enabled is missing", [name, keyToCheck]),
		"remediation": "enabled = true",
		"remediationType": "addition",
	}
}
