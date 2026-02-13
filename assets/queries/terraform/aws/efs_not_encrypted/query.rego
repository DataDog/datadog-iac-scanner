package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	efs := input.document[i].resource.aws_efs_file_system[name]
	efs.encrypted == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_efs_file_system",
		"resourceName": tf_lib.get_resource_name(efs, name),
		"searchKey": sprintf("aws_efs_file_system[%s].encrypted", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_efs_file_system", name ,"encrypted"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("aws_efs_file_system[%s].encrypted' should be true", [name]),
		"keyActualValue": sprintf("aws_efs_file_system[%s].encrypted' is false", [name]),
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}

CxPolicy[result] {
	efs := input.document[i].resource.aws_efs_file_system[name]
	not common_lib.valid_key(efs, "encrypted")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_efs_file_system",
		"resourceName": tf_lib.get_resource_name(efs, name),
		"searchKey": sprintf("aws_efs_file_system[%s]", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_efs_file_system", name ,"encrypted"], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("aws_efs_file_system[%s].encrypted' should be defined and not null", [name]),
		"keyActualValue": sprintf("aws_efs_file_system[%s].encrypted' is undefined or null", [name]),
		"remediation": "encrypted = true",
		"remediationType": "addition",
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_efs_file_system", "encrypted")
	module[keyToCheck] == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s should be true", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is false", [name, keyToCheck]),
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_efs_file_system", "encrypted")
	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"searchLine": common_lib.build_search_line(["module", name , keyToCheck], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s should be defined and not null", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is undefined or null", [name, keyToCheck]),
		"remediation": sprintf("%s = true", [keyToCheck]),
		"remediationType": "addition",
	}
}
