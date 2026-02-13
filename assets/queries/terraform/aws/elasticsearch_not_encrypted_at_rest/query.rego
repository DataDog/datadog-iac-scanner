package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
	domain := input.document[i].resource.aws_elasticsearch_domain[name]

	not domain.encrypt_at_rest

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_elasticsearch_domain",
		"resourceName": tf_lib.get_resource_name(domain, name),
		"searchKey": sprintf("aws_elasticsearch_domain[%s]", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_elasticsearch_domain", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'encrypt_at_rest' should be set and enabled",
		"keyActualValue": "'encrypt_at_rest' is undefined",
		"remediation": "encrypt_at_rest {\n\tenabled = true \n\t}",
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	domain := input.document[i].resource.aws_elasticsearch_domain[name]
	encrypt_at_rest := domain.encrypt_at_rest

	encrypt_at_rest.enabled == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_elasticsearch_domain",
		"resourceName": tf_lib.get_resource_name(domain, name),
		"searchKey": sprintf("aws_elasticsearch_domain[%s].encrypt_at_rest.enabled", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_elasticsearch_domain", name, "encrypt_at_rest", "enabled"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'encrypt_at_rest.enabled' should be true",
		"keyActualValue": "'encrypt_at_rest.enabled' is false",
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
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_elasticsearch_domain", "encrypt_at_rest")

	not module[keyToCheck]

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"searchLine": common_lib.build_search_line(["module", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s should be set and enabled", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is undefined", [name, keyToCheck]),
		"remediation": sprintf("%s {\n\tenabled = true \n\t}", [keyToCheck]),
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_elasticsearch_domain", "encrypt_at_rest")
	encrypt_at_rest := module[keyToCheck]

	encrypt_at_rest.enabled == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.enabled", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck, "enabled"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s.enabled should be true", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s.enabled is false", [name, keyToCheck]),
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}
