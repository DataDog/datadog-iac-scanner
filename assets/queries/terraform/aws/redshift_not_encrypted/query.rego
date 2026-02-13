package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	cluster := input.document[i].resource.aws_redshift_cluster[name]
	not common_lib.valid_key(cluster, "encrypted")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_redshift_cluster",
		"resourceName": tf_lib.get_resource_name(cluster, name),
		"searchKey": sprintf("aws_redshift_cluster[%s]", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_redshift_cluster", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_redshift_cluster.encrypted should be defined and not null",
		"keyActualValue": "aws_redshift_cluster.encrypted is undefined or null",
		"remediation": "encrypted = true",
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	cluster := input.document[i].resource.aws_redshift_cluster[name]
	cluster.encrypted == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_redshift_cluster",
		"resourceName": tf_lib.get_resource_name(cluster, name),
		"searchKey": sprintf("aws_redshift_cluster[%s].encrypted", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_redshift_cluster", name, "encrypted"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_redshift_cluster.encrypted should be set to false",
		"keyActualValue": "aws_redshift_cluster.encrypted is true",
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
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_redshift_cluster", "encrypted")
	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"searchLine": common_lib.build_search_line(["module", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s should be defined and not null", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is undefined or null", [name, keyToCheck]),
		"remediation": sprintf("%s = true", [keyToCheck]),
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_redshift_cluster", "encrypted")
	module[keyToCheck] == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%].%s should be set to false", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is true", [name, keyToCheck]),
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}
