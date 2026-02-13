package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	public := input.document[i].resource.aws_redshift_cluster[name]
	not common_lib.valid_key(public, "publicly_accessible")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_redshift_cluster",
		"resourceName": tf_lib.get_resource_name(public, name),
		"searchKey": sprintf("aws_redshift_cluster[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_redshift_cluster.publicly_accessible should be defined and not null",
		"keyActualValue": "aws_redshift_cluster.publicly_accessible is undefined or null",
		"remediation": "publicly_accessible = false",
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	public := input.document[i].resource.aws_redshift_cluster[name]
	public.publicly_accessible == true

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_redshift_cluster",
		"resourceName": tf_lib.get_resource_name(public, name),
		"searchKey": sprintf("aws_redshift_cluster[%s].publicly_accessible", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_redshift_cluster.publicly_accessible should be set to false",
		"keyActualValue": "aws_redshift_cluster.publicly_accessible is true",
		"remediation": json.marshal({
			"before": "true",
			"after": "false"
		}),
		"remediationType": "replacement",
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_redshift_cluster", "publicly_accessible")
	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s should be defined and not null", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is undefined or null", [name, keyToCheck]),
		"remediation": sprintf("%s = false", [keyToCheck]),
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_redshift_cluster", "publicly_accessible")
	module[keyToCheck] == true

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s should be set to false", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is true", [name, keyToCheck]),
		"remediation": json.marshal({
			"before": "true",
			"after": "false"
		}),
		"remediationType": "replacement",
	}
}
