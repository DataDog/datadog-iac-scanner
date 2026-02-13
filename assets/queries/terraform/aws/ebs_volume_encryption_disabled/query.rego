package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	doc := input.document[i]
	resource := doc.resource.aws_ebs_volume[name]
	not common_lib.valid_key(resource, "encrypted")

	result := {
		"documentId": doc.id,
		"resourceType": "aws_ebs_volume",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_ebs_volume[%s]", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_ebs_volume", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "One of 'aws_ebs_volume.encrypted' should be defined",
		"keyActualValue": "One of 'aws_ebs_volume.encrypted' is undefined",
		"remediation": "encrypted = true",
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	doc := input.document[i]
	resource := doc.resource.aws_ebs_volume[name]
	resource.encrypted == false

	result := {
		"documentId": doc.id,
		"resourceType": "aws_ebs_volume",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_ebs_volume[%s].encrypted", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_ebs_volume", name, "encrypted"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "One of 'aws_ebs_volume.encrypted' should be 'true'",
		"keyActualValue": "One of 'aws_ebs_volume.encrypted' is 'false'",
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
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_ebs_volume", "encrypted")
	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"searchLine": common_lib.build_search_line(["module", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("One of 'module[%s].%s' should be defined", [name, keyToCheck]),
		"keyActualValue": sprintf("One of 'module[%s].%s' is undefined", [name, keyToCheck]),
		"remediation": sprintf("%s = true", [keyToCheck]),
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_ebs_volume", "encrypted")
	module[keyToCheck] == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("One of 'module[%s].%s' should be 'true'", [name, keyToCheck]),
		"keyActualValue": sprintf("One of 'module[%s].%s' is 'false'", [name, keyToCheck]),
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}
