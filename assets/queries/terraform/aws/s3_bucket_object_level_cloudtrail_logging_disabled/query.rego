package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_cloudtrail[name]

	resource.event_selector.data_resource.type == "AWS::S3::Object"
	not common_lib.valid_key(resource.event_selector, "read_write_type")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_cloudtrail",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_cloudtrail[%s].event_selector", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'read_write_type' should be defined and not null",
		"keyActualValue": "'read_write_type' is undefined or null",
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_cloudtrail[name]

	resource.event_selector.data_resource.type == "AWS::S3::Object"
	resource.event_selector.read_write_type != "All"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_cloudtrail",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_cloudtrail[%s].event_selector.read_write_type", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'read_write_type' should be set to 'All'",
		"keyActualValue": "'read_write_type' is not set to 'All'",
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_cloudtrail", "event_selector")

	module[keyToCheck].data_resource.type == "AWS::S3::Object"
	not common_lib.valid_key(module[keyToCheck], "read_write_type")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s.read_write_type should be defined and not null", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s.read_write_type is undefined or null", [name, keyToCheck]),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_cloudtrail", "event_selector")

	module[keyToCheck].data_resource.type == "AWS::S3::Object"
	module[keyToCheck].read_write_type != "All"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.read_write_type", [name, keyToCheck]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s.read_write_type should be set to 'All'", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s.read_write_type is not set to 'All'", [name, keyToCheck]),
	}
}
