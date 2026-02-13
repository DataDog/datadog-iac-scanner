package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
	document := input.document[i]
	resource = document.resource.aws_api_gateway_method[name]

	resource.authorization == "NONE"
	resource.http_method != "OPTIONS"

	result := {
		"documentId": document.id,
		"resourceType": "aws_api_gateway_method",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_api_gateway_method[%s].http_method", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_api_gateway_method.authorization should only be 'NONE' if http_method is 'OPTIONS'",
		"keyActualValue": sprintf("aws_api_gateway_method[%s].authorization type is 'NONE' and http_method is not ''OPTIONS'", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_method", name, "http_method"], []),
		"remediation": json.marshal({
			"before": sprintf("%s", [resource.http_method]),
			"after": "OPTIONS"
		}),
		"remediationType": "replacement",
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_api_gateway_method", "authorization")

	module[keyToCheck] == "NONE"
	httpMethodKey := common_lib.get_module_equivalent_key("aws", module.source, "aws_api_gateway_method", "http_method")

	module[httpMethodKey] != "OPTIONS"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, httpMethodKey]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s should only be 'NONE' if %s is 'OPTIONS'", [keyToCheck, httpMethodKey]),
		"keyActualValue": sprintf("module[%s].%s is 'NONE' and %s is not ''OPTIONS'", [name, keyToCheck, httpMethodKey]),
		"searchLine": common_lib.build_search_line(["module", name, httpMethodKey], []),
		"remediation": json.marshal({
			"before": sprintf("%s", [module[httpMethodKey]]),
			"after": "OPTIONS"
		}),
		"remediationType": "replacement",
	}
}
