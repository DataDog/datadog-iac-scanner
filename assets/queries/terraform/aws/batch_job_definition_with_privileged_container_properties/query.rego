package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
	document := input.document[i]
	properties_json = document.resource.aws_batch_job_definition[name].container_properties
	properties := json.unmarshal(properties_json)
	properties.privileged == true

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_batch_job_definition",
		"resourceName": tf_lib.get_resource_name(document.resource.aws_batch_job_definition[name], name),
		"searchKey": sprintf("aws_batch_job_definition[%s].container_properties.privileged", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_batch_job_definition", name, "container_properties", "privileged"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("aws_batch_job_definition[%s].container_properties.privileged should be 'false' or not set", [name]),
		"keyActualValue": sprintf("aws_batch_job_definition[%s].container_properties.privileged is 'true'", [name]),
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
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_batch_job_definition", "container_properties")
	properties_json = module[keyToCheck]
	properties := json.unmarshal(properties_json)
	properties.privileged == true

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.privileged", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck, "privileged"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s.privileged should be 'false' or not set", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s.privileged is 'true'", [name, keyToCheck]),
		"remediation": json.marshal({
			"before": "true",
			"after": "false"
		}),
		"remediationType": "replacement",
	}
}
