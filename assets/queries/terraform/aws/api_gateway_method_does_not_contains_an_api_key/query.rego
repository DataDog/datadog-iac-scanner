package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	document := input.document[i]
	api = document.resource.aws_api_gateway_method[name]

	not common_lib.valid_key(api, "api_key_required")

	result := {
		"documentId": document.id,
		"resourceType": "aws_api_gateway_method",
		"resourceName": tf_lib.get_resource_name(api, name),
		"searchKey": sprintf("resource.aws_api_gateway_method[%s]", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_method", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("resource.aws_api_gateway_method[%s].api_key_required should be defined", [name]),
		"keyActualValue": sprintf("resource.aws_api_gateway_method[%s].api_key_required is undefined", [name]),
		"remediation": "api_key_required = true",
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	document := input.document[i]
	api = document.resource.aws_api_gateway_method[name]

	api.api_key_required != true

	result := {
		"documentId": document.id,
		"resourceType": "aws_api_gateway_method",
		"resourceName": tf_lib.get_resource_name(api, name),
		"searchKey": sprintf("resource.aws_api_gateway_method[%s].api_key_required", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_method", name, "api_key_required"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("resource.aws_api_gateway_method[%s].api_key_required should be 'true'", [name]),
		"keyActualValue": sprintf("resource.aws_api_gateway_method[%s].api_key_required is 'false'", [name]),
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
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_api_gateway_method", "api_key_required")
	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"searchLine": common_lib.build_search_line(["module", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s should be defined", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is undefined", [name, keyToCheck]),
		"remediation": sprintf("%s = true", [keyToCheck]),
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_api_gateway_method", "api_key_required")
	module[keyToCheck] != true

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s should be 'true'", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is 'false'", [name, keyToCheck]),
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}
