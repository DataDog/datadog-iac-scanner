package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_athena_workgroup[name]
	not common_lib.valid_key(resource, "configuration")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_athena_workgroup",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_athena_workgroup[{{%s}}]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("aws_athena_workgroup[{{%s}}].configuration.result_configuration.encryption_configuration should be defined", [name]),
		"keyActualValue": sprintf("aws_athena_workgroup[{{%s}}].configuration is missing", [name]),
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_athena_workgroup[name]
	not common_lib.valid_key(resource.configuration, "result_configuration")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_athena_workgroup",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_athena_workgroup[{{%s}}].configuration", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("aws_athena_workgroup[{{%s}}].configuration.result_configuration.encryption_configuration should be defined", [name]),
		"keyActualValue": sprintf("aws_athena_workgroup[{{%s}}].configuration.result_configuration is missing", [name]),
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_athena_workgroup[name]
	not common_lib.valid_key(resource.configuration.result_configuration, "encryption_configuration")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_athena_workgroup",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_athena_workgroup[{{%s}}].configuration.result_configuration", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("aws_athena_workgroup[{{%s}}].configuration.result_configuration.encryption_configuration should be defined", [name]),
		"keyActualValue": sprintf("aws_athena_workgroup[{{%s}}].configuration.result_configuration.encryption_configuration is missing", [name]),
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_athena_workgroup", "configuration")
	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s.result_configuration.encryption should be defined", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is missing", [name, keyToCheck]),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_athena_workgroup", "configuration")
	not common_lib.valid_key(module[keyToCheck], "result_configuration")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s.result_configuration.encryption_configuration should be defined", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s.result_configuration.encryption_configuration is missing", [name, keyToCheck]),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_athena_workgroup", "configuration")
	not common_lib.valid_key(module[keyToCheck].result_configuration, "encryption_configuration")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.result_configuration", [name, keyToCheck]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s.result_configuration.encryption_configuration should be defined", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s.result_configuration.encryption_configuration is missing", [name, keyToCheck]),
	}
}
