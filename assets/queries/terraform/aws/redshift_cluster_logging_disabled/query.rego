package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_redshift_cluster[name]
	resource.logging.enable == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_redshift_cluster",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_redshift_cluster[%s].logging.enable", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_redshift_cluster", name, "logging", "enable"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'aws_redshift_cluster.logging.enable' should be true",
		"keyActualValue": "'aws_redshift_cluster.logging.enable' is false",
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_redshift_cluster[name]
	not common_lib.valid_key(resource, "logging")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_redshift_cluster",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_redshift_cluster[%s]", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_redshift_cluster", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'aws_redshift_cluster.logging.enable' should be true",
		"keyActualValue": "'aws_redshift_cluster.logging' is undefined",
		"remediation": "logging {\n\tenable = true \n\t}",
		"remediationType": "addition",
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_redshift_cluster", "logging")
	module[keyToCheck].enable == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.enable", [name, keyToCheck]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s.enable should be true", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s.enable is false", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck, "enable"], []),
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_redshift_cluster", "logging")
	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s.enable should be true", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is undefined", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name], []),
		"remediation": sprintf("%s {\n\tenable = true \n\t}", keyToCheck),
		"remediationType": "addition",
	}
}
