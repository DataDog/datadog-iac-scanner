package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_ebs_encryption_by_default[name]
	resource.enabled == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_ebs_encryption_by_default",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_ebs_encryption_by_default[%s].enabled", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_ebs_encryption_by_default", name, "enabled"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'aws_ebs_encryption_by_default.enableed' should be true",
		"keyActualValue": "'aws_ebs_encryption_by_default.enabled' is false",
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
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_ebs_encryption_by_default", "enabled")
	module[keyToCheck] == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].enabled", [name]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'module[%s].%s' should be true", [name, keyToCheck]),
		"keyActualValue": sprintf("'module[%s].%s' is false", [name, keyToCheck]),
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}
